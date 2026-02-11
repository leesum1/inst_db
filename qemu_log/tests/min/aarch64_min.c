#include <stdio.h>

int main(void)
{
    volatile int sum = 0;

    for (int index = 0; index < 8; index++) {
        sum += index;
    }

    if (sum != 28) {
        return 1;
    }

    puts("ok-aarch64");
    return 0;
}
