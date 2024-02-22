mod fuzzer;
mod json_monitor;

pub fn main() {
    unsafe {
        let stdout = libc::fdopen(libc::STDOUT_FILENO, "w".as_ptr() as *const u8);
        libc::setvbuf(stdout, std::ptr::null_mut(), libc::_IONBF, 0);
    }

    fuzzer::fuzz().unwrap();
}
