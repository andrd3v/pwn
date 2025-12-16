// type confusion bug
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef enum {
    OBJ_NONE = 0,
    OBJ_A    = 1,
    OBJ_B    = 2,
} ObjKind;

typedef struct {
    void (*fn)(void);
    char data[32];
} ObjA;

typedef struct {
    char data[32];
    void (*fn)(void);
} ObjB;

#define MAX_OBJS 16

static void *g_objs[MAX_OBJS];
static ObjKind g_kinds[MAX_OBJS];

static void setup_io(void);
static void read_line(char *buf, size_t max);
static long read_long(void);

static void safe_a(void);
static void safe_b(void);
static void win(void) __attribute__((no_stack_protector));

static void cmd_new_a(void);
static void cmd_new_b(void);
static void cmd_invoke(void);
static void cmd_delete(void);
static void cmd_debug(void);
static void menu(void);

int main(void) __attribute__((no_stack_protector));

static void setup_io(void) {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);
}

static void read_line(char *buf, size_t max) {
    if (!fgets(buf, max, stdin)) {
        puts("input error");
        exit(1);
    }
    size_t n = strlen(buf);
    if (n && buf[n - 1] == '\n') {
        buf[n - 1] = '\0';
    }
}

static long read_long(void) {
    char tmp[64];
    if (!fgets(tmp, sizeof(tmp), stdin)) {
        exit(1);
    }
    return strtol(tmp, NULL, 10);
}

static void safe_a(void) {
    puts("[ObjA] safe_a() called");
}

static void safe_b(void) {
    puts("[ObjB] safe_b() called");
}

static void win(void) {
    puts("you reached win() – enjoy your shell");
    system("/bin/sh");
}

static int read_index(const char *prompt) {
    printf("%s", prompt);
    long idx = read_long();
    if (idx < 0 || idx >= MAX_OBJS) {
        puts("invalid index");
        return -1;
    }
    return (int)idx;
}

static void cmd_new_a(void) {
    int idx = read_index("slot (0-15) for ObjA: ");
    if (idx < 0) return;
    if (g_objs[idx]) {
        puts("slot already used");
        return;
    }

    ObjA *obj = calloc(1, sizeof(ObjA));
    if (!obj) {
        perror("calloc");
        exit(1);
    }

    obj->fn = safe_a;
    printf("ObjA data (max 31 chars): ");
    read_line(obj->data, sizeof(obj->data));

    g_objs[idx]  = obj;
    g_kinds[idx] = OBJ_A;

    printf("created ObjA at slot %d (ptr=%p)\n", idx, (void *)obj);
}

static void cmd_new_b(void) {
    int idx = read_index("slot (0-15) for ObjB: ");
    if (idx < 0) return;
    if (g_objs[idx]) {
        puts("slot already used");
        return;
    }

    ObjB *obj = calloc(1, sizeof(ObjB));
    if (!obj) {
        perror("calloc");
        exit(1);
    }

    obj->fn = safe_b;
    printf("ObjB data (32 bytes as string): ");
    read_line(obj->data, sizeof(obj->data));

    g_objs[idx]  = obj;
    /*
     * BUG: должны были записать OBJ_B, но по ошибке помечаем как OBJ_A.
     * При invoke() этот объект будет трактоваться как ObjA, и первые
     * 8 байт data будут восприняты как указатель fn.
     */
    g_kinds[idx] = OBJ_A; /* BUG: type confusion */

    printf("created ObjB at slot %d (ptr=%p)\n", idx, (void *)obj);
}

static void cmd_invoke(void) {
    int idx = read_index("slot to invoke: ");
    if (idx < 0) return;

    if (!g_objs[idx] || g_kinds[idx] == OBJ_NONE) {
        puts("empty slot");
        return;
    }

    if (g_kinds[idx] == OBJ_A) {
        ObjA *a = (ObjA *)g_objs[idx];
        printf("[invoke] treating slot %d as ObjA, fn=%p\n", idx, (void *)a->fn);
        a->fn();
    } else if (g_kinds[idx] == OBJ_B) {
        ObjB *b = (ObjB *)g_objs[idx];
        printf("[invoke] treating slot %d as ObjB, fn=%p\n", idx, (void *)b->fn);
        b->fn();
    } else {
        puts("unknown kind");
    }
}

static void cmd_delete(void) {
    int idx = read_index("slot to delete: ");
    if (idx < 0) return;

    if (!g_objs[idx]) {
        puts("empty slot");
        return;
    }

    printf("freeing slot %d (ptr=%p, kind=%d)\n",
           idx, g_objs[idx], (int)g_kinds[idx]);

    free(g_objs[idx]);
    g_objs[idx]  = NULL;
    g_kinds[idx] = OBJ_NONE;
}

static void cmd_debug(void) {
    puts("=== debug info ===");
    printf("safe_a: %p\n", (void *)safe_a);
    printf("safe_b: %p\n", (void *)safe_b);
    printf("win:    %p\n", (void *)win);
    printf("g_objs: %p\n", (void *)g_objs);
    for (int i = 0; i < MAX_OBJS; i++) {
        void *ptr = g_objs[i];
        ObjKind k = g_kinds[i];
        if (!ptr && k == OBJ_NONE) continue;
        printf("[%02d] kind=%d ptr=%p\n", i, (int)k, ptr);
    }
}

static void menu(void) {
    puts("=== ARM64 macOS type confusion task ===");
    puts("1) new ObjA");
    puts("2) new ObjB");
    puts("3) invoke slot");
    puts("4) delete slot");
    puts("5) debug info");
    puts("6) exit");
    printf("> ");
}

int main(void) {
    setup_io();

    memset(g_objs, 0, sizeof(g_objs));
    memset(g_kinds, 0, sizeof(g_kinds));

    printf("safe_a: %p\n", (void *)safe_a);
    printf("safe_b: %p\n", (void *)safe_b);
    printf("win:    %p\n", (void *)win);

    for (;;) {
        menu();
        long choice = read_long();

        switch (choice) {
        case 1:
            cmd_new_a();
            break;
        case 2:
            cmd_new_b();
            break;
        case 3:
            cmd_invoke();
            break;
        case 4:
            cmd_delete();
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

