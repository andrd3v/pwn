//oob vuln
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    uint32_t start;
    uint32_t length;
} Segment;

typedef void (*handler_fn_t)(void);

typedef struct {
    uint32_t count;
    uint32_t capacity;
    Segment segments[16];
    handler_fn_t handler;
} SegmentTable;

static SegmentTable g_tbl;

static void setup_io(void);
static long read_long(void);

static void safe_handler(void);
static void win(void) __attribute__((no_stack_protector));

static void cmd_add(void);
static void cmd_set(void);
static void cmd_list(void);
static void cmd_call_handler(void);
static void cmd_debug(void);
static void menu(void);

int main(void) __attribute__((no_stack_protector));

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

static void safe_handler(void) {
    puts("[handler] dumping segments:");
    for (uint32_t i = 0; i < g_tbl.count && i < g_tbl.capacity; i++) {
        Segment *s = &g_tbl.segments[i];
        printf("  [%02u] start=%u length=%u\n", i, s->start, s->length);
    }
}

static void win(void) {
    puts("you reached win() – enjoy your shell");
    system("/bin/sh");
}

static void cmd_add(void) {
    if (g_tbl.count >= g_tbl.capacity) {
        puts("table full");
        return;
    }

    uint32_t idx = g_tbl.count;
    Segment *s = &g_tbl.segments[idx];

    printf("new segment index: %u\n", idx);
    printf("start: ");
    long start = read_long();
    printf("length: ");
    long len = read_long();

    s->start  = (start < 0) ? 0 : (uint32_t)start;
    s->length = (len   < 0) ? 0 : (uint32_t)len;

    g_tbl.count++;
    puts("segment added");
}

static void cmd_set(void) {
    printf("index (0-%u): ", g_tbl.count);
    long idx = read_long();
    if (idx < 0 || (uint32_t)idx > g_tbl.count) {
        puts("invalid index");
        return;
    }

    Segment *s = &g_tbl.segments[idx];

    printf("new start: ");
    long start = read_long();
    printf("new length: ");
    long len = read_long();

    s->start  = (start < 0) ? 0 : (uint32_t)start;
    s->length = (len   < 0) ? 0 : (uint32_t)len;

    puts("segment updated");
}

static void cmd_list(void) {
    puts("segments:");
    for (uint32_t i = 0; i < g_tbl.count && i < g_tbl.capacity; i++) {
        Segment *s = &g_tbl.segments[i];
        printf("  [%02u] start=%u length=%u\n", i, s->start, s->length);
    }
}

static void cmd_call_handler(void) {
    if (!g_tbl.handler) {
        puts("no handler set");
        return;
    }
    g_tbl.handler();
}

static void cmd_debug(void) {
    puts("=== debug info ===");
    printf("count:      %u\n", g_tbl.count);
    printf("capacity:   %u\n", g_tbl.capacity);
    printf("&segments:  %p\n", (void *)g_tbl.segments);
    printf("&handler:   %p\n", (void *)&g_tbl.handler);
    printf("safe_handler: %p\n", (void *)safe_handler);
    printf("win:          %p\n", (void *)win);
}

static void menu(void) {
    puts("=== ARM64 macOS OOB task (off-by-one) ===");
    puts("1) add segment");
    puts("2) set segment");
    puts("3) list segments");
    puts("4) call handler");
    puts("5) debug info");
    puts("6) exit");
    printf("> ");
}

int main(void) {
    setup_io();

    memset(&g_tbl, 0, sizeof(g_tbl));
    g_tbl.capacity = 16;
    g_tbl.count = 0;
    g_tbl.handler = safe_handler;

    printf("safe_handler: %p\n", (void *)safe_handler);
    printf("win:          %p\n", (void *)win);
    printf("&g_tbl.handler: %p\n", (void *)&g_tbl.handler);

    for (;;) {
        menu();
        long choice = read_long();

        switch (choice) {
        case 1:
            cmd_add();
            break;
        case 2:
            cmd_set();
            break;
        case 3:
            cmd_list();
            break;
        case 4:
            cmd_call_handler();
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

