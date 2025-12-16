#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

__attribute__((noreturn))
void gadget1(void) {
    printf("[*] Executing gadget 1 on pivoted stack\n");
    exit(0);
}

__attribute__((naked, noreturn))
void pivot_and_run(void *new_sp, void (*start)(void)) {
    __asm__ volatile(
        "mov sp, x0\n"
        "br x1\n"
    );
}

int main() {
    void *buf = malloc(0x1000);
    uintptr_t top = (uintptr_t)buf + 0x1000;
    void *new_sp = (void *)(top & ~(uintptr_t)0xF);

    printf("[*] New stack region: %p\n", new_sp);
    printf("[*] Starting pivot...\n");

    pivot_and_run(new_sp, gadget1);
}
