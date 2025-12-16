#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void win(void) {
    printf("WIN\n");
    system("/bin/ls");
}

void safe(void) {
    printf("SAFE\n");
}

typedef struct {
    char data[32];
    void (*fn)(void);
} chunk;

typedef struct {
    void (*fn)(void);
    char msg[32];
} handler;

int main(void) {
    chunk *a = malloc(sizeof(chunk));
    handler *h = malloc(sizeof(handler));

    if (!a || !h) {
        perror("malloc");
        return 1;
    }

    h->fn = safe;
    strcpy(h->msg, "hello");

    printf("a: %p\n", (void *)a);
    printf("h: %p\n", (void *)h);
    printf("&h->fn: %p\n", (void *)&h->fn);
    printf("&h->msg: %p\n", (void *)&h->msg);
    printf("&a->data: %p\n", (void *)&a->data);

    printf("win: %p\n", (void *)win);
    printf("safe: %p\n", (void *)safe);

    printf("read into a->data:\n");
    ssize_t n = read(0, a->data, 128);
    printf("read %zd bytes\n", n);

    printf("calling h->fn()\n");
    h->fn();

    return 0;
}

