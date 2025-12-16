#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) __attribute__((no_stack_protector));
static char s_ls[] __attribute__((used)) = "/bin/ls";

void pop_x0_x30_ret(void) {
    __asm__(
        "ldp x0, x30, [sp], #16\n\t"
        "ret\n\t"
    );
}

void func1()  __attribute__((no_stack_protector));
void func1()
{
    puts("1\n");
}

void func2()  __attribute__((no_stack_protector));
void func2()
{
    puts("2\n");
}

int main(void) {
    char buf[16];
    puts("lol");
    read(0, buf, 2048);
    return 0;
}
