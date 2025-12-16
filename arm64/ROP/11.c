#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) __attribute__((no_stack_protector));
void g_ldp_x0_x30(void) __attribute__((naked, used));
char s_ls[] = "/bin/ls";

void g_ldp_x0_x30(void) {
    __asm__(
        "ldr x0, [sp]\n\t"
        "ldr x1, [sp, #0x8]\n\t"
        "add x2, sp, x1\n\t"
        "ldr x30, [x2]\n\t"
        "ret\n\t"
    );
}

int main(void) {
    printf("%p\n", (void *)system);
    char buf[32];
    puts("lol");
    read(0, buf, 512);
    return 0;
}


