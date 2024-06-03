#!/bin/bash

SRC="test.c"
TARGETS="
aarch64-linux-musl
arm-linux-musleabi
x86_64-linux-musl
"
CFLAGS="-static -Oz -flto"

for target in $TARGETS; do
    zig cc -target $target $CFLAGS $SRC -o test.$target
done
