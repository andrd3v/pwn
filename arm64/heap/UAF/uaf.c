// medium UAF / type confusion–style task
// Theme: classic heap use-after-free -> function pointer overwrite

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

typedef struct Obj Obj;

typedef void (*obj_fn_t)(Obj *self);

struct Obj {
    char data[32];
    obj_fn_t fn;
};

static Obj *g_obj = NULL;
static void *g_buf = NULL;

static void setup_io(void);
static long read_long(void);
static void read_exact(void *buf, size_t size);

static void safe_action(Obj *self);
static void win(Obj *self) __attribute__((no_stack_protector));

static void cmd_create(void);
static void cmd_delete(void);
static void cmd_alloc_buf(void);
static void cmd_use(void);
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

static void read_exact(void *buf, size_t size) {
    unsigned char *p = buf;
    size_t total = 0;
    while (total < size) {
        ssize_t n = read(0, p + total, size - total);
        if (n <= 0) {
            puts("read error");
            exit(1);
        }
        total += (size_t)n;
    }
}

static void safe_action(Obj *self) {
    if (!self) {
        puts("[safe] no object");
        return;
    }
    printf("[safe] data: \"");
    fwrite(self->data, 1, 32, stdout);
    printf("\"\n");
}

static void win(Obj *self) {
    (void)self;
    puts("you reached win() – enjoy your shell");
    system("/bin/sh");
}

static void cmd_create(void) {
    if (g_obj) {
        puts("object already exists");
        return;
    }

    g_obj = malloc(sizeof(Obj));
    if (!g_obj) {
        perror("malloc");
        exit(1);
    }

    memset(g_obj->data, 0, sizeof(g_obj->data));
    g_obj->fn = safe_action;

    printf("enter initial data (up to 32 bytes, will be zero-padded):\n");
    ssize_t n = read(0, g_obj->data, sizeof(g_obj->data));
    if (n < 0) {
        perror("read");
        exit(1);
    }

    printf("created object at %p\n", (void *)g_obj);
}

static void cmd_delete(void) {
    if (!g_obj) {
        puts("no object");
        return;
    }

    printf("freeing object at %p\n", (void *)g_obj);
    free(g_obj);

    /*
     * BUG: pointer is not cleared.
     * g_obj now points to freed memory. Later allocations of the same size
     * may reuse this chunk, allowing overwrite of g_obj->fn and data.
     */
    puts("object freed (pointer kept for reuse)");
}

static void cmd_alloc_buf(void) {
    if (g_buf) {
        puts("freeing previous buffer");
        free(g_buf);
        g_buf = NULL;
    }

    size_t sz = sizeof(Obj);
    g_buf = malloc(sz);
    if (!g_buf) {
        perror("malloc");
        exit(1);
    }

    printf("allocated buffer of size %zu at %p\n", sz, g_buf);
    printf("write %zu bytes into buffer:\n", sz);
    read_exact(g_buf, sz);

    puts("buffer filled");
}

static void cmd_use(void) {
    if (!g_obj) {
        puts("no object");
        return;
    }

    printf("using object at %p, fn=%p\n", (void *)g_obj, (void *)g_obj->fn);
    g_obj->fn(g_obj);
}

static void cmd_debug(void) {
    puts("=== debug info ===");
    printf("g_obj: %p\n", (void *)g_obj);
    if (g_obj) {
        printf("  g_obj->fn: %p\n", (void *)g_obj->fn);
        printf("  &g_obj->data: %p\n", (void *)g_obj->data);
    }
    printf("g_buf: %p\n", (void *)g_buf);
    printf("sizeof(Obj): %zu\n", sizeof(Obj));
    printf("safe_action: %p\n", (void *)safe_action);
    printf("win:         %p\n", (void *)win);
}

static void menu(void) {
    puts("=== ARM64 macOS UAF task (medium) ===");
    puts("1) create object");
    puts("2) delete object");
    puts("3) allocate and fill buffer");
    puts("4) use object");
    puts("5) debug info");
    puts("6) exit");
    printf("> ");
}

int main(void) {
    setup_io();

    printf("safe_action: %p\n", (void *)safe_action);
    printf("win:         %p\n", (void *)win);

    for (;;) {
        menu();
        long choice = read_long();

        switch (choice) {
        case 1:
            cmd_create();
            break;
        case 2:
            cmd_delete();
            break;
        case 3:
            cmd_alloc_buf();
            break;
        case 4:
            cmd_use();
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

