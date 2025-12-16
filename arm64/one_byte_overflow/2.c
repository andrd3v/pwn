#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    char title[16];
    unsigned char len;
    char desc[64]; 
    void (*cb)(void);
} Note;

static Note *note = NULL;

static long read_long(void) {
    char buf[32];
    ssize_t n = read(0, buf, sizeof(buf) - 1);
    if (n <= 0) exit(1);
    buf[n] = '\0';
    return strtol(buf, NULL, 10);
}

__attribute__((used))
static void win(void) {
    puts("you win, here is your flag:");
    system("/bin/cat flag.txt");
}

static void safe(void) {
    puts("nothing happens");
}

static void create_note(void) {
    if (note) {
        puts("note already exists");
        return;
    }
    note = malloc(sizeof(Note));
    if (!note) exit(1);
    memset(note, 0, sizeof(Note));
    note->cb = safe;
    note->len = 32;

    printf("Title: ");
    ssize_t n = read(0, note->title, 17);
    if (n <= 0) exit(1);
    if (n < 16) {
        note->title[n] = '\0';
    } else {
        note->title[15] = '\0';
    }
    puts("note created");
}

static void edit_note(void) {
    if (!note) {
        puts("no note");
        return;
    }
    printf("New text (max %u bytes): ", note->len);
    ssize_t n = read(0, note->desc, note->len);
    if (n <= 0) {
        puts("edit error");
        return;
    }
    puts("note updated");
}

static void show_note(void) {
    if (!note) {
        puts("no note");
        return;
    }
    printf("Title: %s\n", note->title);
    printf("Len: %u\n", note->len);
    write(1, "Desc: ", 6);
    write(1, note->desc, 64);
    write(1, "\n", 1);
}

static void run_note(void) {
    if (!note) {
        puts("no note");
        return;
    }
    puts("running callback...");
    note->cb();
}

int main(void) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    for (;;) {
        puts("=== One-byte overflow task #2 ===");
        puts("1) create note");
        puts("2) edit note");
        puts("3) show note");
        puts("4) run note");
        puts("5) exit");
        printf("> ");

        long c = read_long();
        if (c == 1) {
            create_note();
        } else if (c == 2) {
            edit_note();
        } else if (c == 3) {
            show_note();
        } else if (c == 4) {
            run_note();
        } else if (c == 5) {
            break;
        } else {
            puts("unknown choice");
        }
    }

    if (note) free(note);
    return 0;
}

