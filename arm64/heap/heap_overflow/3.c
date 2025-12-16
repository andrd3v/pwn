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
    puts("SAFE");
}

int main(void) {
    setbuf(stdout, NULL);

    chunk *c = malloc(2 * sizeof(chunk));
    if (!c) {
        perror("malloc");
        return 1;
    }

    c[0].fn = safe;
    c[1].fn = safe;

    printf("&c[0]:      %p\n", (void *)&c[0]);
    printf("&c[1]:      %p\n", (void *)&c[1]);
    printf("&c[0].buf:  %p\n", (void *)c[0].buf);
    printf("&c[0].fn:   %p\n", (void *)&c[0].fn);
    printf("&c[1].buf:  %p\n", (void *)c[1].buf);
    printf("&c[1].fn:   %p\n", (void *)&c[1].fn);

    printf("win:        %p\n", (void *)win);
    printf("safe:       %p\n", (void *)safe);

    printf("read into c[0].buf:\n");
    read(0, c[0].buf, 128);

    printf("calling c[1].fn()\n");
    c[1].fn();

    return 0;
}

