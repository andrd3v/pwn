#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) __attribute__((no_stack_protector));
void pop_x0_x30_ret(void) __attribute__((naked, used));
char s_ls[] = "/bin/ls";

void pop_x0_x30_ret(void) {
    __asm__(
        "ldp x0, x30, [sp], #16\n\t"
        "ret\n\t"
    );
}

int main(void) {
    printf("%p\n", (void *)system);
    printf("%p\n", (void *)puts);
    char buf[32];
    puts("lol");
    read(0, buf, 512);
    return 0;
}


