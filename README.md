trivial-fuzzer
===

This is a fuzzer based on `libafl` and `libafl_qemu` that I use to test and demo Binharness.
The idea is to have a simple fuzzer application that is very easy to use programmatically.

The operation is simple: the fuzzer will run the target binary as provided up until it hits `LLVMFuzzerTestOneInput`, and then will fork the process from there for each test case.

Any feedback or suggestions are welcome!


## Building
```sh
cargo make aarch64  # To build for the aarch64 guest
cargo make aarch64-release  # To build for the aarch64 guest in release mode
cargo make all  # To build for all supported architectures
```

## Usage
Hopefully straightforward enough:
```sh
trivial-fuzzer-aarch64 \
    --inputs <input dir> \
    --output <output dir> \
    --solution <solution dir> \
    --events <events dir> \
    --bitmap <bitmap file> \
    -- <binary> <args>
```
