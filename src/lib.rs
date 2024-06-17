mod fuzzer;
mod json_monitor;

use anyhow::Result;
use clap::Parser;
use libc::c_char;

pub fn entry() -> Result<()> {
    unsafe {
        let stdout = libc::fdopen(libc::STDOUT_FILENO, "w".as_ptr() as *const c_char);
        libc::setvbuf(stdout, std::ptr::null_mut(), libc::_IONBF, 0);
    }
    env_logger::init();

    fuzzer::fuzz(fuzzer::FuzzerOptions::try_parse()?, None).unwrap();

    Ok(())
}
