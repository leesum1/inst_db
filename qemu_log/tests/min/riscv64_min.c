#include <stdio.h>

int main(void)
{
    volatile int value = 1;

    for (int index = 1; index <= 5; index++) {
        value *= index;
    }

    if (value != 120) {
        return 1;
    }

    puts("ok-riscv64");
    return 0;
}
