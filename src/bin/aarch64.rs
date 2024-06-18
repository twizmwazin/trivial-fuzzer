use trivial_fuzzer::entry;

pub fn main() {
    entry().unwrap();
}

#[test]
fn test_aarch64() {
    trivial_fuzzer::fuzzer::tests::test_core("test.aarch64-linux-musl")
}
