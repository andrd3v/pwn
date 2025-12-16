#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

typedef struct Note Note;

struct Note {
    Note *next;
    unsigned short cap;      /* logical buffer capacity (<= 65535) */
    unsigned short used;     /* how many bytes are actually used  */
    void (*printer)(Note *); /* function pointer we want to hijack */
    char *data;              /* points inside this allocation      */
};

static Note *g_head = NULL;

static void setup_io(void);
static long read_long(void);
static void read_bytes(void *buf, size_t size);
static Note *find_note(int index);

static void print_note(Note *n);
static void print_debug(Note *n);
static void debug_leak(void);

static void create_note(void);
static void edit_note(void);
static void show_note(void);
static void delete_note(void);
static void menu(void);

static void win(Note *n) __attribute__((no_stack_protector));
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

static void read_bytes(void *buf, size_t size) {
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

static Note *find_note(int index) {
    Note *cur = g_head;
    int i = 0;
    while (cur && i < index) {
        cur = cur->next;
        i++;
    }
    return cur;
}

static void print_note(Note *n) {
    printf("[note] cap=%hu used=%hu\n", n->cap, n->used);
    if (n->used) {
        fwrite(n->data, 1, n->used, stdout);
        putchar('\n');
    }
}

static void print_debug(Note *n) {
    printf("Note %p: next=%p cap=%hu used=%hu printer=%p data=%p\n",
           (void *)n,
           (void *)n->next,
           n->cap,
           n->used,
           (void *)n->printer,
           (void *)n->data);
}

static void debug_leak(void) {
    Note *cur = g_head;
    int idx = 0;
    puts("[debug] listing notes:");
    while (cur) {
        printf("[%d] ", idx);
        print_debug(cur);
        cur = cur->next;
        idx++;
    }
}

static void create_note(void) {
    printf("note capacity (1-65520): ");
    long cap = read_long();
    if (cap <= 0 || cap > 65520) {
        puts("invalid size");
        return;
    }

    size_t alloc = sizeof(Note) + (size_t)cap;
    Note *n = calloc(1, alloc);
    if (!n) {
        perror("calloc");
        exit(1);
    }

    n->cap = (unsigned short)cap;
    n->used = 0;
    n->printer = print_note;
    n->data = (char *)(n + 1);

    printf("initial content length: ");
    long len = read_long();
    if (len < 0) {
        len = 0;
    }
    if ((unsigned long)len > n->cap) {
        len = n->cap;
    }

    if (len > 0) {
        printf("send %ld bytes:\n", len);
        read_bytes(n->data, (size_t)len);
        n->used = (unsigned short)len;
    }

    if (!g_head) {
        g_head = n;
    } else {
        Note *cur = g_head;
        while (cur->next) {
            cur = cur->next;
        }
        cur->next = n;
    }

    printf("created note at %p (cap=%hu used=%hu)\n",
           (void *)n, n->cap, n->used);
}

static void edit_note(void) {
    printf("index: ");
    long idx = read_long();
    if (idx < 0 || idx > 32) {
        puts("invalid index");
        return;
    }

    Note *n = find_note((int)idx);
    if (!n) {
        puts("no such note");
        return;
    }

    printf("append length: ");
    long add = read_long();
    if (add <= 0) {
        puts("nothing to do");
        return;
    }

    unsigned int want = (unsigned int)add;
    unsigned short total16 = (unsigned short)(n->used + want);

    printf("current used=%hu cap=%hu\n", n->used, n->cap);
    printf("requested append=%u total16=%hu\n", want, total16);

    if (total16 > n->cap) {
        puts("too much");
        return;
    }

    printf("send %u bytes:\n", want);
    read_bytes(n->data + n->used, want);
    n->used = (unsigned short)(n->used + want);
}

static void show_note(void) {
    printf("index: ");
    long idx = read_long();
    if (idx < 0 || idx > 32) {
        puts("invalid index");
        return;
    }

    Note *n = find_note((int)idx);
    if (!n) {
        puts("no such note");
        return;
    }

    n->printer(n);
}

static void delete_note(void) {
    printf("index: ");
    long idx = read_long();
    if (idx < 0 || idx > 32) {
        puts("invalid index");
        return;
    }

    Note *cur = g_head;
    Note *prev = NULL;
    int i = 0;

    while (cur && i < idx) {
        prev = cur;
        cur = cur->next;
        i++;
    }

    if (!cur) {
        puts("no such note");
        return;
    }

    if (prev) {
        prev->next = cur->next;
    } else {
        g_head = cur->next;
    }

    free(cur);
    puts("deleted");
}

static void menu(void) {
    puts("=== arm64 macOS note manager ===");
    puts("1) create note");
    puts("2) append to note");
    puts("3) show note");
    puts("4) delete note");
    puts("5) debug info");
    puts("6) exit");
    printf("> ");
}

static void win(Note *n) {
    (void)n;
    puts("you reached win() – enjoy your shell");
    system("/bin/sh");
}

int main(void) {
    setup_io();

    printf("win:        %p\n", (void *)win);
    printf("print_note: %p\n", (void *)print_note);
    printf("debug:      %p\n", (void *)print_debug);

    for (;;) {
        menu();
        long choice = read_long();

        switch (choice) {
        case 1:
            create_note();
            break;
        case 2:
            edit_note();
            break;
        case 3:
            show_note();
            break;
        case 4:
            delete_note();
            break;
        case 5:
            debug_leak();
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

