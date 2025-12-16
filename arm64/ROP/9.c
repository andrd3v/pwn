#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

int vuln(void) __attribute__((no_stack_protector));
int main(void) __attribute__((no_stack_protector));
void pop_x0_x1_x2_x30_ret(void) __attribute__((naked, used));

static char bin_sh[] __attribute__((used)) = "/bin/sh";
static char cmd_cat_flag[] __attribute__((used)) = "cat flag.txt";
static char *argv_exec[] __attribute__((used)) = { bin_sh, "-c", cmd_cat_flag, NULL };

void pop_x0_x1_x2_x30_ret(void) {
    __asm__(
        "ldp x0, x1, [sp], #16\n\t"
        "ldp x2, x30, [sp], #16\n\t"
        "ret\n\t"
    );
}

int vuln(void) {
    char buf[16];
    puts("Tell me a story:");
    read(0, buf, 512);
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("bin_sh: %p\n", (void *)bin_sh);
    printf("argv:   %p\n", (void *)argv_exec);
    printf("gadget: %p\n", (void *)pop_x0_x1_x2_x30_ret);
    printf("execve: %p\n", (void *)execve);

    vuln();
    return 0;
}

