#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

typedef struct Note {
    char *data;
    void (*print)(struct Note *);
} Note;

Note *notes[8];
char *raws[8];

void default_print(Note *n) {
    if (n && n->data)
        printf("Note: %s\n", n->data);
    else
        puts("Empty note");
}

void win(void) {
    puts("you win, here is your flag");
    fflush(stdout);
    exit(0);
}

void add_note(void) {
    int idx;
    size_t size;
    printf("Index (0-7): ");
    scanf("%d", &idx);
    if (idx < 0 || idx > 7) {
        puts("bad index");
        return;
    }
    if (notes[idx]) {
        puts("already used");
        return;
    }
    printf("Size of data: ");
    scanf("%zu", &size);
    if (size == 0 || size > 0x100) {
        puts("bad size");
        return;
    }
    Note *n = malloc(sizeof(Note));
    if (!n) exit(1);
    n->data = malloc(size);
    if (!n->data) exit(1);
    n->print = default_print;
    notes[idx] = n;
    printf("Content: ");
    read(0, n->data, size);
}

void delete_note(void) {
    int idx;
    printf("Index (0-7): ");
    scanf("%d", &idx);
    if (idx < 0 || idx > 7) {
        puts("bad index");
        return;
    }
    if (!notes[idx]) {
        puts("no note");
        return;
    }
    free(notes[idx]->data);
    free(notes[idx]);
    puts("note freed, pointer kept (uaf)");
}

void show_note(void) {
    int idx;
    printf("Index (0-7): ");
    scanf("%d", &idx);
    if (idx < 0 || idx > 7) {
        puts("bad index");
        return;
    }
    if (!notes[idx]) {
        puts("no note");
        return;
    }
    notes[idx]->print(notes[idx]);
}

void add_raw(void) {
    int idx;
    printf("Raw index (0-7): ");
    scanf("%d", &idx);
    if (idx < 0 || idx > 7) {
        puts("bad index");
        return;
    }
    if (raws[idx]) {
        puts("already used");
        return;
    }
    raws[idx] = malloc(sizeof(Note));
    if (!raws[idx]) exit(1);
    printf("Raw data (%zu bytes): ", sizeof(Note));
    read(0, raws[idx], sizeof(Note));
}

void menu(void) {
    puts("1) add note");
    puts("2) delete note");
    puts("3) show note");
    puts("4) add raw");
    puts("5) exit");
    printf("> ");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("win:   %p\n", (void *)win);
    printf("Note:  %zu bytes\n", sizeof(Note));
    for (;;) {
        menu();
        int choice;
        if (scanf("%d", &choice) != 1)
            break;
        switch (choice) {
        case 1:
            add_note();
            break;
        case 2:
            delete_note();
            break;
        case 3:
            show_note();
            break;
        case 4:
            add_raw();
            break;
        case 5:
            puts("bye");
            return 0;
        default:
            puts("unknown");
            break;
        }
    }
    return 0;
}

