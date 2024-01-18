#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

void _segfault() {
    int *p = 0;
    *p = 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // // Print size and first byte of the input
    // printf("size = %zu, data[0] = %d\n", size, data[0]);
    if (size >= 4 && data[0] == 'F' && data[1] == 'U' && data[2] == 'Z' && data[3] == 'Z') {
        _segfault();
    }
    return 0;
}

void main(int argc, char **argv) {
    // if (argc != 3) {
    //     return;
    // }
    // int len = atoi(argv[1]);
    // char *data = argv[2];
    uint8_t buf[10] = {0};
    LLVMFuzzerTestOneInput(buf, 10);
}
