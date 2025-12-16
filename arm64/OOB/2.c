#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    uint32_t len;
    uint32_t cap;
    uint64_t arr[8];
    void (*fn)(void);
} Table;

static Table g_tbl;

static void setup_io(void) {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);
}

static long read_long(void) {
    char buf[64];
    if (!fgets(buf, sizeof(buf), stdin)) {
        exit(1);
    }
    return strtol(buf, NULL, 10);
}

static void handler_default(void) {
    printf("[handler] len=%u cap=%u\n", g_tbl.len, g_tbl.cap);
    for (uint32_t i = 0; i < g_tbl.len && i < g_tbl.cap; i++) {
        printf("  [%u] = 0x%016llx\n", i, (unsigned long long)g_tbl.arr[i]);
    }
}

static void win(void) __attribute__((no_stack_protector));

static void win(void) {
    puts("you reached win() – enjoy your shell");
    system("/bin/sh");
}

static void cmd_push(void) {
    if (g_tbl.len >= g_tbl.cap) {
        puts("table full");
        return;
    }

    printf("value (uint64): ");
    unsigned long long v = (unsigned long long)read_long();
    g_tbl.arr[g_tbl.len++] = (uint64_t)v;
    puts("pushed");
}

static void cmd_set(void) {
    printf("index (0-%u): ", g_tbl.len);
    long idx = read_long();
    if (idx < 0 || (uint32_t)idx > g_tbl.len) {
        puts("invalid index");
        return;
    }

    printf("new value (uint64): ");
    unsigned long long v = (unsigned long long)read_long();
    g_tbl.arr[idx] = (uint64_t)v;
    puts("updated");
}

static void cmd_list(void) {
    printf("len=%u cap=%u\n", g_tbl.len, g_tbl.cap);
    for (uint32_t i = 0; i < g_tbl.len && i < g_tbl.cap; i++) {
        printf("  [%u] = 0x%016llx\n", i, (unsigned long long)g_tbl.arr[i]);
    }
}

static void cmd_call(void) {
    if (!g_tbl.fn) {
        puts("no handler");
        return;
    }
    g_tbl.fn();
}

static void cmd_debug(void) {
    puts("=== debug info ===");
    printf("len: %u\n", g_tbl.len);
    printf("cap: %u\n", g_tbl.cap);
    printf("&arr: %p\n", (void *)g_tbl.arr);
    printf("&fn:  %p\n", (void *)&g_tbl.fn);
    printf("handler_default: %p\n", (void *)handler_default);
    printf("win:             %p\n", (void *)win);
}

static void menu(void) {
    puts("=== ARM64 macOS OOB task (medium) ===");
    puts("1) push value");
    puts("2) set value");
    puts("3) list");
    puts("4) call handler");
    puts("5) debug info");
    puts("6) exit");
    printf("> ");
}

int main(void) __attribute__((no_stack_protector));

int main(void) {
    setup_io();

    memset(&g_tbl, 0, sizeof(g_tbl));
    g_tbl.cap = 8;
    g_tbl.len = 0;
    g_tbl.fn  = handler_default;

    printf("handler_default: %p\n", (void *)handler_default);
    printf("win:             %p\n", (void *)win);
    printf("&g_tbl.fn:       %p\n", (void *)&g_tbl.fn);

    for (;;) {
        menu();
        long choice = read_long();

        switch (choice) {
        case 1:
            cmd_push();
            break;
        case 2:
            cmd_set();
            break;
        case 3:
            cmd_list();
            break;
        case 4:
            cmd_call();
            break;
        case 5:
            cmd_debug();
            break;
        case 6:
            puts("bye");
            return 0;
        default:
            puts("unknown option");
            break;
        }
    }
}

