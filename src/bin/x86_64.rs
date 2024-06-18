use trivial_fuzzer::entry;

pub fn main() {
    entry().unwrap();
}

#[test]
fn test_x86_64() {
    trivial_fuzzer::fuzzer::tests::test_core("test.x86_64-linux-musl")
}
