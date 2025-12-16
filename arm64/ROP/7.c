#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void reset(void) __attribute__((no_stack_protector));
void add(const char *s) __attribute__((no_stack_protector));
void run_cmd(void) __attribute__((no_stack_protector));
int main(void) __attribute__((no_stack_protector));
void pop_x0_x30_ret(void) __attribute__((naked, used));

char cmd[128] = "echo nope";
char s_ls[] = "/bin/ls";
char s_la[] = " -la";

void reset(void) __attribute__((noinline));
void reset(void) {
    memset(cmd, 0, sizeof(cmd));
}

void add(const char *s) {
    strcat(cmd, s);
}

void run_cmd(void) {
    system(cmd);
}

void pop_x0_x30_ret(void) {
    __asm__(
        "ldp x0, x30, [sp], #16\n\t"
        "ret\n\t"
    );
}

int main(void) {
    char buf[32];
    read(0, buf, 512);
    return 0;
}

