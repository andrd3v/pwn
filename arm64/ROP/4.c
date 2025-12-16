#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

void check(int *x) __attribute__((no_stack_protector));
int main(void) __attribute__((no_stack_protector));
void pop_x0_x30_ret(void) __attribute__((naked, used));

static int lol __attribute__((used)) = 42;

void check(int *x) {
    if (*x == 42) {
        puts("OK");
    } else {
        puts("NO");
    }
}

void pop_x0_x30_ret(void) {
    __asm__(
        "ldp x0, x30, [sp], #16\n\t"
        "ret\n\t"
    );
}

int main(void) {
    char buf[16];
    read(0, buf, 512);
    return 0;
}

