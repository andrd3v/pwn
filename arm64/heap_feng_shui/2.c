#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

typedef struct Note {
    char *data;
    size_t len;
} Note;

typedef struct Handler {
    void (*fn)(void);
    char msg[0x70];
} Handler;

#define MAX_NOTES 8
#define MAX_HANDLERS 4
#define MAX_SPRAY 16

Note *notes[MAX_NOTES];
Handler *handlers[MAX_HANDLERS];
void *spray_bufs[MAX_SPRAY];

void win(void) {
    puts("you win, harder heap feng shui success");
    fflush(stdout);
    exit(0);
}

void default_handler(void) {
    puts("default handler");
}

void menu(void) {
    puts("1) new note");
    puts("2) edit note");
    puts("3) delete note");
    puts("4) new handler");
    puts("5) delete handler");
    puts("6) call handler");
    puts("7) spray free");
    puts("8) exit");
    printf("> ");
}

int find_free_spray_slot(void) {
    for (int i = 0; i < MAX_SPRAY; i++) {
        if (!spray_bufs[i]) return i;
    }
    return -1;
}

void new_note(void) {
    int idx;
    size_t sz;
    printf("note index (0-%d): ", MAX_NOTES - 1);
    if (scanf("%d", &idx) != 1) return;
    if (idx < 0 || idx >= MAX_NOTES) {
        puts("bad index");
        return;
    }
    if (notes[idx]) {
        puts("already exists");
        return;
    }
    printf("size: ");
    if (scanf("%zu", &sz) != 1) return;
    if (sz == 0 || sz > 0x100) {
        puts("bad size");
        return;
    }

    Note *n = malloc(sizeof(Note));
    if (!n) exit(1);
    n->data = malloc(sz);
    if (!n->data) exit(1);
    n->len = sz;
    notes[idx] = n;

    int s = find_free_spray_slot();
    void *pad = NULL;
    if (s >= 0) {
        pad = malloc(sizeof(Handler));
        spray_bufs[s] = pad;
    }

    printf("[DBG] new_note idx=%d Note=%p data=%p len=%zu pad_slot=%d pad=%p\n",
           idx, (void *)n, (void *)n->data, n->len, s, pad);

    printf("content: ");
    read(0, n->data, sz);
}

void edit_note(void) {
    int idx;
    size_t sz;
    printf("note index (0-%d): ", MAX_NOTES - 1);
    if (scanf("%d", &idx) != 1) return;
    if (idx < 0 || idx >= MAX_NOTES) {
        puts("bad index");
        return;
    }
    if (!notes[idx]) {
        puts("no note");
        return;
    }
    Note *n = notes[idx];
    printf("new size: ");
    if (scanf("%zu", &sz) != 1) return;

    printf("[DBG] edit_note idx=%d Note=%p data=%p len=%zu write=%zu\n",
           idx, (void *)n, (void *)n->data, n->len, sz);

    printf("data: ");
    read(0, n->data, sz);
}

void delete_note(void) {
    int idx;
    printf("note index (0-%d): ", MAX_NOTES - 1);
    if (scanf("%d", &idx) != 1) return;
    if (idx < 0 || idx >= MAX_NOTES) {
        puts("bad index");
        return;
    }
    if (!notes[idx]) {
        puts("no note");
        return;
    }

    printf("[DBG] delete_note idx=%d Note=%p data=%p len=%zu\n",
           idx, (void *)notes[idx], (void *)notes[idx]->data, notes[idx]->len);

    free(notes[idx]->data);
    free(notes[idx]);
    notes[idx] = NULL;
    puts("note deleted");
}

void new_handler(void) {
    int idx;
    printf("handler index (0-%d): ", MAX_HANDLERS - 1);
    if (scanf("%d", &idx) != 1) return;
    if (idx < 0 || idx >= MAX_HANDLERS) {
        puts("bad index");
        return;
    }
    if (handlers[idx]) {
        puts("already exists");
        return;
    }
    Handler *h = malloc(sizeof(Handler));
    if (!h) exit(1);
    h->fn = default_handler;
    handlers[idx] = h;

    printf("[DBG] new_handler idx=%d Handler=%p fn=%p msg=%p size=%zu\n",
           idx, (void *)h, (void *)h->fn, (void *)h->msg, sizeof(Handler));

    printf("message: ");
    read(0, h->msg, sizeof(h->msg));
}

void delete_handler(void) {
    int idx;
    printf("handler index (0-%d): ", MAX_HANDLERS - 1);
    if (scanf("%d", &idx) != 1) return;
    if (idx < 0 || idx >= MAX_HANDLERS) {
        puts("bad index");
        return;
    }
    if (!handlers[idx]) {
        puts("no handler");
        return;
    }

    printf("[DBG] delete_handler idx=%d Handler=%p fn=%p msg=%p\n",
           idx, (void *)handlers[idx], (void *)handlers[idx]->fn, (void *)handlers[idx]->msg);

    free(handlers[idx]);
    handlers[idx] = NULL;
    puts("handler deleted");
}

void call_handler(void) {
    int idx;
    printf("handler index (0-%d): ", MAX_HANDLERS - 1);
    if (scanf("%d", &idx) != 1) return;
    if (idx < 0 || idx >= MAX_HANDLERS) {
        puts("bad index");
        return;
    }
    if (!handlers[idx]) {
        puts("no handler");
        return;
    }

    printf("[DBG] call_handler idx=%d Handler=%p fn=%p msg=%p\n",
           idx, (void *)handlers[idx], (void *)handlers[idx]->fn, (void *)handlers[idx]->msg);

    handlers[idx]->fn();
}

void spray_free(void) {
    int idx;
    printf("spray index (0-%d): ", MAX_SPRAY - 1);
    if (scanf("%d", &idx) != 1) return;
    if (idx < 0 || idx >= MAX_SPRAY) {
        puts("bad index");
        return;
    }
    if (!spray_bufs[idx]) {
        puts("no spray");
        return;
    }

    printf("[DBG] spray_free idx=%d ptr=%p\n", idx, spray_bufs[idx]);
    free(spray_bufs[idx]);
    spray_bufs[idx] = NULL;
    puts("spray freed");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("win: %p\n", (void *)win);
    printf("Note size: %zu\n", sizeof(Note));
    printf("Handler size: %zu\n", sizeof(Handler));
    for (int i = 0; i < MAX_NOTES; i++) notes[i] = NULL;
    for (int i = 0; i < MAX_HANDLERS; i++) handlers[i] = NULL;
    for (int i = 0; i < MAX_SPRAY; i++) spray_bufs[i] = NULL;
    while (1) {
        menu();
        int choice;
        if (scanf("%d", &choice) != 1)
            break;
        switch (choice) {
        case 1:
            new_note();
            break;
        case 2:
            edit_note();
            break;
        case 3:
            delete_note();
            break;
        case 4:
            new_handler();
            break;
        case 5:
            delete_handler();
            break;
        case 6:
            call_handler();
            break;
        case 7:
            spray_free();
            break;
        case 8:
            puts("bye");
            return 0;
        default:
            puts("unknown");
            break;
        }
    }
    return 0;
}
