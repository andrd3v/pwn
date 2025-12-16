#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

typedef struct {
    char buf[32];
    void (*fn)(void);
} Ctx;

void win(void) {
    puts("you win, here is your flag:");
    system("/bin/cat flag.txt");
}

void safe(void) {
    puts("nothing interesting happened");
}

static long read_long(void) {
    char tmp[64];
    ssize_t n = read(0, tmp, sizeof(tmp) - 1);
    if (n <= 0) exit(1);
    tmp[n] = '\0';
    return strtol(tmp, NULL, 10);
}

int main(void) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    printf("win:  %p\n", win);

    Ctx ctx;
    ctx.fn = safe;

    puts("How many blocks?");
    long input = read_long();
    uint32_t count = (uint32_t)input;
    uint16_t small = (uint16_t)(count * 16u);
    size_t real = (size_t)count * 16u;

    printf("small (uint16): %u\n", small);
    printf("real (size_t):  %zu\n", real);

    if (small > sizeof(ctx.buf)) {
        puts("too big");
        return 1;
    }

    puts("Send data:");
    ssize_t n = read(0, ctx.buf, real);
    
    puts("Calling ctx.fn()...");
    ctx.fn();

    return 0;
}
