#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

void _segfault() {
    int *p = 0;
    *p = 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size >= 4 && data[0] == 'F' && data[1] == 'U' && data[2] == 'Z' && data[3] == 'Z') {
        _segfault();
    }
    return 0;
}

int main(int argc, char **argv) {
    uint8_t buf[10] = {0};
    LLVMFuzzerTestOneInput(buf, 10);
    printf("Hello, World!\n");
}
