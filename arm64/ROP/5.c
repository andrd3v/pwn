#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>


void check(char *x)__attribute__((no_stack_protector));
int main(void) __attribute__((no_stack_protector));
void pop_x0_x30_ret(void) __attribute__((naked, used));

static char lol[] __attribute__((used)) = "/bin/ls";

void check(char *x) {
    system(x);
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

