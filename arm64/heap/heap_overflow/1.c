#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

typedef struct {
    char buf[32];
    void (*fn)(void);
} chunk;

void win(void) {
    system("/bin/ls");
}

void safe(void) {
    puts("safe");
}

int main(void) {
    setbuf(stdout, NULL);

    chunk *c = malloc(sizeof(chunk));
    c->fn = safe;

    printf("chunk: %p\n", c);
    printf("win:   %p\n", win);
    printf("safe:  %p\n", safe);
    printf("read:\n");

    read(0, c->buf, 128);

    c->fn();
    return 0;
}
