#include <stdio.h>
#include <string.h>
#include <stdint.h>

extern uintptr_t __stack_chk_guard;

void win() {
    puts("🎉 YOU WIN!");
}

void vuln() {
    char buf[64];
    char buf2[64];
    
    printf("canary (guard): 0x%016lx\n", (unsigned long)__stack_chk_guard);

    printf("Input: \n");
    gets(buf);
    printf(buf);
    
    printf("Input2: \n");
    gets(buf2);
    printf(buf2);
}

int main() {
    vuln();
    return 0;
}
