#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_CHUNKS 8
#define CHUNK_SIZE 0x80

static void menu(void) {
    puts("==== simple double free pwn ====");
    puts("1) alloc");
    puts("2) free");
    puts("3) exit");
    printf("> ");
}

static int read_int(void) {
    char buf[0x20];
    if (!fgets(buf, sizeof(buf), stdin)) {
        exit(1);
    }
    return atoi(buf);
}

static void read_n(char *buf, size_t size) {
    ssize_t r = read(STDIN_FILENO, buf, size);
    if (r <= 0) {
        puts("read error");
        exit(1);
    }
    if (buf[r - 1] == '\n') {
        buf[r - 1] = '\0';
    }
}

int main(void) {
    void *chunks[MAX_CHUNKS] = {0};

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    while (1) {
        menu();
        int choice = read_int();

        if (choice == 1) {
            printf("index (0-%d): ", MAX_CHUNKS - 1);
            int idx = read_int();
            if (idx < 0 || idx >= MAX_CHUNKS) {
                puts("bad index");
                continue;
            }
            if (chunks[idx]) {
                puts("already allocated");
                continue;
            }

            chunks[idx] = malloc(CHUNK_SIZE);
            if (!chunks[idx]) {
                puts("malloc failed");
                exit(1);
            }

            printf("data: ");
            read_n((char *)chunks[idx], CHUNK_SIZE);
            puts("done");

        } else if (choice == 2) {
            printf("index (0-%d): ", MAX_CHUNKS - 1);
            int idx = read_int();
            if (idx < 0 || idx >= MAX_CHUNKS) {
                puts("bad index");
                continue;
            }

            free(chunks[idx]);
            puts("freed");

        } else if (choice == 3) {
            puts("bye");
            break;
        } else {
            puts("unknown choice");
        }
    }

    return 0;
}
