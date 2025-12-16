#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) __attribute__((no_stack_protector));
static char s_ls[] __attribute__((used)) = "/bin/ls";

__attribute__((naked, used))
void jop_pop_x0_x30_br(void) {
    __asm__(
        "ldp x0, x30, [sp], #16\n\t"
        "br  x30\n\t"
    );
}

void func1(char *s) __attribute__((no_stack_protector));
void func1(char *s)
{
    puts(s);
}


int main(void) {
    char buf[16];
    puts("JOP task (arm64 macOS)");
    puts("Overflow the buffer and use the jop_pop_x0_x30_br gadget");
    read(STDIN_FILENO, buf, 2048);
    return 0;
}
