#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

void win(void) {
    puts("you win, here is your flag");
    fflush(stdout);
    exit(0);
}

char fake_stack[0x100];

__attribute__((naked))
void pivot(void) {
    __asm__ volatile(
        "ldr x0, [sp]\n"
        "add sp, sp, #8\n"
        "mov sp, x0\n"
        "ret\n"
    );
}

void vuln(void) {
    char buf[32];

    printf("win:        %p\n", (void *)win);
    printf("pivot:      %p\n", (void *)pivot);
    printf("fake_stack: %p\n", (void *)fake_stack);
    printf("&buf:       %p\n", (void *)buf);
    fflush(stdout);

    printf("Input: ");
    fflush(stdout);
    read(0, buf, 0x200);
}

int main(void) {
    vuln();
    return 0;
}

