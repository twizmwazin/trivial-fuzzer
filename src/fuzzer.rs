use std::{
    env,
    io::{self, stdout},
    path::PathBuf,
    process,
    time::{SystemTime, UNIX_EPOCH},
};

use clap::Parser;
use libafl::{
    corpus::{Corpus, InMemoryOnDiskCorpus},
    events::{EventRestarter, SimpleRestartingEventManager},
    executors::ExitKind,
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::StdFuzzer,
    inputs::{BytesInput, HasTargetBytes},
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    observers::StdMapObserver,
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, StdState},
    Error, Fuzzer,
};
use libafl_bolts::{
    core_affinity::Cores,
    current_nanos,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::tuple_list,
    AsMutSlice, AsSlice,
};
use libafl_qemu::{
    edges::{QemuEdgeCoverageChildHelper, EDGES_MAP_PTR, EDGES_MAP_SIZE},
    elf::EasyElf,
    emu::Emulator,
    ArchExtras, CallingConvention, GuestAddr, GuestReg, MmapPerms, QemuForkExecutor, QemuHooks,
    Regs,
};
use std::fs::File;
use std::io::Write;

use crate::json_monitor::JsonMonitor;

#[derive(Parser, Debug)]
pub struct FuzzerOptions {
    #[arg(long, help = "Output directory")]
    output: String,

    #[arg(long, help = "Input directory")]
    input: String,

    #[arg(long, help = "Solution directory")]
    solution: String,

    #[arg(long, help = "Bitmap path")]
    bitmap: String,

    #[arg(long, help = "Events output directory")]
    events: String,

    #[arg(long, help = "Timeout in seconds", default_value_t = 1_u64)]
    timeout: u64,

    #[arg(long = "port", help = "Broker port", default_value_t = 1337_u16)]
    port: u16,

    #[arg(long, help = "Cpu cores to use", default_value = "all", value_parser = Cores::from_cmdline)]
    cores: Cores,

    #[clap(short, long, help = "Enable output from the fuzzer clients")]
    verbose: bool,

    #[arg(last = true, help = "Arguments passed to the target")]
    args: Vec<String>,
}

pub const MAX_INPUT_SIZE: usize = 1048576; // 1MB

pub fn fuzz() -> Result<(), Error> {
    let mut options = FuzzerOptions::parse();

    let corpus_dir = PathBuf::from(options.input);

    let files = corpus_dir
        .read_dir()
        .expect("Failed to read corpus dir")
        .map(|x| Ok(x?.path()))
        .collect::<Result<Vec<PathBuf>, io::Error>>()
        .expect("Failed to read dir entry");

    let program = env::args().next().unwrap();
    log::debug!("Program: {program:}");

    options.args.insert(0, program);
    log::debug!("ARGS: {:#?}", options.args);

    env::remove_var("LD_LIBRARY_PATH");
    let env: Vec<(String, String)> = env::vars().collect();
    let emu = Emulator::new(&options.args, &env).unwrap();
    println!("Base address: {:#x}", emu.load_addr());

    let mut elf_buffer = Vec::new();
    let elf = EasyElf::from_file(emu.binary_path(), &mut elf_buffer).unwrap();

    let test_one_input_ptr = elf
        .resolve_symbol("LLVMFuzzerTestOneInput", emu.load_addr())
        .expect("Symbol LLVMFuzzerTestOneInput not found");
    log::debug!("LLVMFuzzerTestOneInput @ {test_one_input_ptr:#x}");

    emu.entry_break(test_one_input_ptr);

    let pc: GuestReg = emu.read_reg(Regs::Pc).unwrap();
    log::debug!("Break at {pc:#x}");

    let ret_addr: GuestAddr = emu.read_return_address().unwrap();
    log::debug!("Return address = {ret_addr:#x}");
    emu.set_breakpoint(ret_addr);

    let input_addr = emu
        .map_private(0, MAX_INPUT_SIZE, MmapPerms::ReadWrite)
        .unwrap();
    log::debug!("Placing input at {input_addr:#x}");

    let stack_ptr: GuestAddr = emu.read_reg(Regs::Sp).unwrap();

    let mut shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

    let mut edges_shmem = shmem_provider.new_shmem(EDGES_MAP_SIZE).unwrap();
    let edges_shmem_clone = edges_shmem.clone();
    let edges = edges_shmem.as_mut_slice();
    unsafe { EDGES_MAP_PTR = edges.as_mut_ptr() };

    let edges_observer = unsafe { StdMapObserver::new("edges", edges) };

    let json_monitor = JsonMonitor::new(|event| {
        let epoch_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let filename = format!("{}/{}", options.events, epoch_time.as_nanos());

        let mut file = File::create(filename).unwrap();
        serde_json::to_writer(&file, event).unwrap();
        file.flush().unwrap();

        serde_json::to_writer(stdout(), event).unwrap();
        stdout().flush().unwrap();

        // Just shove the hitcount map out here
        let mut bitmap_file =
            File::create(PathBuf::from(&options.bitmap)).expect("Failed to create bitmap file");
        bitmap_file
            .write_all(&edges_shmem_clone.as_slice())
            .expect("Failed to write bitmap data to file");
        bitmap_file.flush().expect("Failed to flush bitmap file");
    });

    let (state, mut mgr) =
        match SimpleRestartingEventManager::launch(json_monitor, &mut shmem_provider) {
            Ok(res) => res,
            Err(err) => match err {
                Error::ShuttingDown => {
                    return Ok(());
                }
                _ => {
                    panic!("Failed to setup the restarter: {err}");
                }
            },
        };

    let mut feedback = MaxMapFeedback::tracking(&edges_observer, true, false);

    let mut objective = CrashFeedback::new();

    let mut state = state.unwrap_or_else(|| {
        StdState::new(
            StdRand::with_seed(current_nanos()),
            InMemoryOnDiskCorpus::new(PathBuf::from(options.output)).unwrap(),
            InMemoryOnDiskCorpus::new(PathBuf::from(options.solution)).unwrap(),
            &mut feedback,
            &mut objective,
        )
        .unwrap()
    });

    let scheduler = QueueScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let mut buf = target.as_slice();
        let mut len = buf.len();
        if len > MAX_INPUT_SIZE {
            buf = &buf[0..MAX_INPUT_SIZE];
            len = MAX_INPUT_SIZE;
        }
        let len = len as GuestReg;

        unsafe {
            emu.write_mem(input_addr, buf);
            emu.write_reg(Regs::Pc, test_one_input_ptr).unwrap();
            emu.write_reg(Regs::Sp, stack_ptr).unwrap();
            emu.write_return_address(ret_addr).unwrap();
            emu.write_function_argument(CallingConvention::Cdecl, 0, input_addr)
                .unwrap();
            emu.write_function_argument(CallingConvention::Cdecl, 1, len)
                .unwrap();
            let _ = emu.run();
        }

        ExitKind::Ok
    };

    let mut hooks = QemuHooks::new(
        emu.clone(),
        tuple_list!(QemuEdgeCoverageChildHelper::default(),),
    );

    let mut executor = QemuForkExecutor::new(
        &mut hooks,
        &mut harness,
        tuple_list!(edges_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        shmem_provider,
    )?;

    println!("Importing {} seeds...", files.len());

    if state.must_load_initial_inputs() {
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &files)
            .unwrap_or_else(|_| {
                println!("Failed to load initial corpus");
                process::exit(0);
            });
        println!("Imported {} seeds from disk.", state.corpus().count());
    }

    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop!");
    println!("Fuzzing done, exiting...");

    mgr.send_exiting()?;
    Ok(())
}
