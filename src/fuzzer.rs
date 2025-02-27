use std::{
    env,
    io::stdout,
    path::PathBuf,
    process,
    ptr::addr_of_mut,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use clap::Parser;
use libafl::{
    corpus::{Corpus, InMemoryOnDiskCorpus, Testcase},
    events::{EventRestarter, SimpleEventManager},
    executors::ExitKind,
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::StdFuzzer,
    inputs::{BytesInput, HasTargetBytes},
    mutators::{havoc_mutations, scheduled::StdScheduledMutator},
    observers::{CanTrack, HitcountsMapObserver, StdMapObserver, VariableMapObserver},
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, StdState},
    Error, Fuzzer,
};
use libafl_bolts::{
    core_affinity::Cores,
    current_nanos,
    ownedref::OwnedMutSlice,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::tuple_list,
    AsSlice, AsSliceMut,
};
use libafl_qemu::{
    elf::EasyElf, modules::StdEdgeCoverageModule, ArchExtras, CallingConvention, Emulator,
    GuestAddr, GuestReg, MmapPerms, Qemu, QemuForkExecutor, Regs,
};
use libafl_targets::{
    edges_map_mut_ptr, EDGES_MAP_ALLOCATED_SIZE, EDGES_MAP_DEFAULT_SIZE, EDGES_MAP_PTR,
    MAX_EDGES_FOUND,
};
use std::fs::File;
use std::io::Write;

use crate::json_monitor::JsonMonitor;

pub const MAX_INPUT_SIZE: usize = 1048576; // 1MB

#[derive(Parser, Debug)]
pub struct FuzzerOptions {
    #[arg(
        long,
        help = "Base directory for fuzzer runtime data",
        default_value = "fuzz_data"
    )]
    data_dir: PathBuf,

    #[arg(long, help = "Output directory")]
    output: Option<PathBuf>,

    #[arg(long, help = "Input directory")]
    input: Option<PathBuf>,

    #[arg(long, help = "Solution directory")]
    solution: Option<PathBuf>,

    #[arg(long, help = "Bitmap path")]
    bitmap: Option<PathBuf>,

    #[arg(long, help = "Events output directory")]
    events: Option<PathBuf>,

    #[arg(long, help = "Timeout in seconds", default_value_t = 1_u64)]
    timeout: u64,

    #[arg(long = "port", help = "Broker port", default_value_t = 1337_u16)]
    port: u16,

    #[arg(long, help = "Cpu cores to use", default_value = "all", value_parser = Cores::from_cmdline)]
    cores: Cores,

    #[arg(
        short = 'L',
        long = "library-path",
        help = "Path to load libraries from",
        default_value = "/"
    )]
    library_path: String,

    #[arg(
        short = 'H',
        long,
        help = "Harness function to use",
        default_value = "LLVMFuzzerTestOneInput"
    )]
    harness: String,

    #[clap(short, long, help = "Enable output from the fuzzer clients")]
    verbose: bool,

    #[arg(last = true, help = "Arguments passed to the target")]
    args: Vec<String>,
}

fn fix_args(args: &mut FuzzerOptions) {
    if args.output.is_none() {
        args.output = Some(args.data_dir.join("output"));
    }

    if args.input.is_none() {
        args.input = Some(args.data_dir.join("input"));
    }

    if args.solution.is_none() {
        args.solution = Some(args.data_dir.join("solution"));
    }

    if args.bitmap.is_none() {
        args.bitmap = Some(args.data_dir.join("bitmap"));
    }

    if args.events.is_none() {
        args.events = Some(args.data_dir.join("events"));
    }
}

fn create_directory_structure(options: &FuzzerOptions) {
    let dirs = vec![
        &options.output,
        &options.input,
        &options.solution,
        &options.events,
    ];

    for dir in dirs {
        let dir = dir.clone().unwrap();
        if !dir.exists() {
            std::fs::create_dir_all(dir).expect("Failed to create directory");
        }
    }
}

pub fn fuzz(
    mut options: FuzzerOptions,
    limit_loops: Option<u32>,
    log_stdout: bool,
) -> Result<(), Error> {
    fix_args(&mut options);
    create_directory_structure(&options);

    let corpus_dir = options.input.unwrap();

    let files = corpus_dir
        .read_dir()
        .map(|read_dir| {
            read_dir
                .map(|entry| entry.map(|e| e.path()))
                .collect::<Result<Vec<_>, _>>()
        })
        .unwrap_or_else(|_| Ok(Vec::new()))
        .expect("Failed to read dir entry");

    let program = env::args().next().unwrap();
    log::debug!("Program: {program:}");

    options.args.insert(0, program);
    log::debug!("ARGS: {:#?}", options.args);

    if options.library_path != "" {
        env::set_var("QEMU_LD_PREFIX", &options.library_path);
    }

    env::remove_var("LD_LIBRARY_PATH");
    let qemu = Qemu::init(&options.args).unwrap();
    log::debug!("Base address: {:#x}", qemu.load_addr());

    let mut elf_buffer = Vec::new();
    let elf = EasyElf::from_file(qemu.binary_path(), &mut elf_buffer).unwrap();

    // If the harness function is an integer, we assume it's an address
    // Otherwise, try to resolve it as a symbol
    // TODO: Might need something special for thumb mode
    let test_one_input_ptr = if let Ok(addr) = GuestAddr::from_str_radix(&options.harness, 16) {
        if elf.is_pic() {
            addr + qemu.load_addr()
        } else {
            addr
        }
    } else {
        elf.resolve_symbol(&options.harness, qemu.load_addr())
            .expect(format!("Symbol {} not found", &options.harness).as_str())
    };

    log::debug!("Pre-executing up to harness at {test_one_input_ptr:#x}");
    qemu.entry_break(test_one_input_ptr);
    log::debug!("Pre-execution complete");

    let pc: GuestReg = qemu.read_reg(Regs::Pc).unwrap();
    log::debug!("Break at {pc:#x}");

    let ret_addr: GuestAddr = qemu.read_return_address().unwrap();
    log::debug!("Return address = {ret_addr:#x}");
    qemu.set_breakpoint(ret_addr);

    let input_addr = qemu
        .map_private(0, MAX_INPUT_SIZE, MmapPerms::ReadWrite)
        .unwrap();
    log::debug!("Placing input at {input_addr:#x}");

    let stack_ptr: GuestAddr = qemu.read_reg(Regs::Sp).unwrap();

    let mut shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

    let mut edges_shmem = shmem_provider.new_shmem(EDGES_MAP_DEFAULT_SIZE).unwrap();
    let edges_shmem_clone = edges_shmem.clone();
    let edges = edges_shmem.as_slice_mut();
    unsafe { EDGES_MAP_PTR = edges.as_mut_ptr() };

    let mut edges_observer = unsafe {
        HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
            "edges",
            OwnedMutSlice::from_raw_parts_mut(edges_map_mut_ptr(), EDGES_MAP_ALLOCATED_SIZE),
            addr_of_mut!(MAX_EDGES_FOUND),
        ))
        .track_indices()
    };

    let json_monitor = JsonMonitor::new(|event| {
        let epoch_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let filename = options
            .events
            .clone()
            .unwrap()
            .join(epoch_time.as_nanos().to_string());

        let mut file = File::create(filename).unwrap();
        serde_json::to_writer(&file, event).unwrap();
        file.flush().unwrap();

        if log_stdout {
            serde_json::to_writer(stdout(), event).unwrap();
            stdout().write_all(b"\n").unwrap();
            stdout().flush().unwrap();
        }

        // Just shove the hitcount map out here
        let mut bitmap_file =
            File::create(options.bitmap.clone().unwrap()).expect("Failed to create bitmap file");
        bitmap_file
            .write_all(&edges_shmem_clone.as_slice())
            .expect("Failed to write bitmap data to file");
        bitmap_file.flush().expect("Failed to flush bitmap file");
    });

    let mut mgr = SimpleEventManager::new(json_monitor);

    let mut feedback = MaxMapFeedback::new(&edges_observer);

    let mut objective = CrashFeedback::new();

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        InMemoryOnDiskCorpus::new(options.output.unwrap()).unwrap(),
        InMemoryOnDiskCorpus::new(options.solution.unwrap()).unwrap(),
        &mut feedback,
        &mut objective,
    )
    .unwrap();

    let scheduler = QueueScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut harness = |_: &mut Emulator<_, _, _, _, _>, input: &BytesInput| {
        let target = input.target_bytes();
        let mut buf = target.as_slice();
        let mut len = buf.len();
        if len > MAX_INPUT_SIZE {
            buf = &buf[0..MAX_INPUT_SIZE];
            len = MAX_INPUT_SIZE;
        }
        let len = len as GuestReg;

        unsafe {
            qemu.write_mem(input_addr, buf);
            qemu.write_reg(Regs::Pc, test_one_input_ptr).unwrap();
            qemu.write_reg(Regs::Sp, stack_ptr).unwrap();
            qemu.write_return_address(ret_addr).unwrap();
            qemu.write_function_argument(CallingConvention::Cdecl, 0, input_addr)
                .unwrap();
            qemu.write_function_argument(CallingConvention::Cdecl, 1, len)
                .unwrap();
            let _ = qemu.run();
        }

        ExitKind::Ok
    };

    let emulator_modules = tuple_list!(StdEdgeCoverageModule::builder()
        .map_observer(edges_observer.as_mut())
        .build()
        .unwrap(),);

    let emulator = Emulator::empty()
        .qemu(qemu)
        .modules(emulator_modules)
        .build()?;

    let mut executor = QemuForkExecutor::new(
        emulator,
        &mut harness,
        tuple_list!(edges_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        shmem_provider,
        Duration::from_secs(10),
    )?;

    println!("Importing {} seeds...", files.len());

    if state.must_load_initial_inputs() {
        state
            .load_initial_inputs_by_filenames_forced(&mut fuzzer, &mut executor, &mut mgr, &files)
            .unwrap_or_else(|_| {
                println!("Failed to load initial corpus");
                process::exit(0);
            });
        println!("Imported {} seeds from disk.", state.corpus().count());
        if state.corpus().count() == 0 {
            state
                .corpus_mut()
                .add(Testcase::new(BytesInput::new(Vec::new())))
                .unwrap();
        }
    }

    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    if let Some(n) = limit_loops {
        for _ in 0..n {
            fuzzer
                .fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr)
                .expect("Error in the fuzzing loop!");
        }
    } else {
        fuzzer
            .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
            .expect("Error in the fuzzing loop!");
    }
    println!("Fuzzing done, exiting...");

    mgr.send_exiting()?;
    Ok(())
}

pub mod tests {
    use super::*;
    use tempfile::tempdir;

    pub fn test_core(bin: &'static str) {
        let temp_dir = tempdir().expect("Failed to create temporary directory");
        let file_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("test_binaries")
            .join(bin);

        let options = FuzzerOptions {
            data_dir: temp_dir.path().to_path_buf(),
            output: None,
            input: None,
            solution: None,
            bitmap: None,
            events: None,
            timeout: 1,
            port: 1337,
            cores: Cores::from_cmdline("1").unwrap(),
            library_path: "".to_string(),
            harness: "LLVMFuzzerTestOneInput".to_string(),
            verbose: false,
            args: vec![file_path.to_string_lossy().to_string()],
        };

        fuzz(options, Some(100), false).unwrap();
    }
}
