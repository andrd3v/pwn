#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

void win() {
    puts("ACCESS GRANTED");
    system("/bin/cat flag.txt");
}

void deny() {
    puts("ACCESS DENIED");
}

int get_int()
{
    char b[32];
    int r = read(0, b, sizeof(b)-1);
    if (r <= 0) exit(1);
    b[r] = 0;
    return atoi(b);
}

int main() {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    uint64_t key = 0;
    void (*fn)() = deny;

    printf("win:  %p\n", win);
    printf("deny: %p\n", deny);

    puts("Enter count:");
    uint32_t n = (uint32_t)get_int();

    uint32_t mul = n * 0xDEADBEEF;
    uint16_t tiny = (uint16_t)mul;

    printf("n:    %u\n", n);
    printf("mul:  %u\n", mul);
    printf("tiny: %u\n", tiny);

    if (tiny == 0x4242) {
        fn = win;
    }

    puts("Running...");
    fn();

    return 0;
}

