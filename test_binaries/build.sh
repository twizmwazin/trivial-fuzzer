#!/bin/bash

SRC="test.c"
TARGETS="
aarch64-linux-musl
x86_64-linux-musl
"
CFLAGS="-static"

for target in $TARGETS; do
    zig cc -target $target $CFLAGS $SRC -o test.$target
done
