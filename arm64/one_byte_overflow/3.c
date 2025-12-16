# one byte overflow + uaf

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    char name[32];
    void (*cb)(void);
} User;

typedef struct {
    char text[40];
} Note;

#define MAX_USERS 4
#define MAX_NOTES 4

static User *users[MAX_USERS];
static Note *notes[MAX_NOTES];

void win(void) __attribute__((used));
void safe(void);

static long read_long(void) {
    char buf[32];
    ssize_t n = read(0, buf, sizeof(buf) - 1);
    if (n <= 0) exit(1);
    buf[n] = '\0';
    return strtol(buf, NULL, 10);
}

void win(void) {
    puts("you win, here is your flag:");
    system("/bin/cat flag3.txt");
}

void safe(void) {
    puts("nothing happens");
}

static void create_user(void) {
    printf("User index (0-%d): ", MAX_USERS - 1);
    long idx = read_long();
    if (idx < 0 || idx >= MAX_USERS) {
        puts("invalid index");
        return;
    }
    if (users[idx]) {
        puts("slot already in use");
        return;
    }
    User *u = malloc(sizeof(User));
    if (!u) exit(1);
    memset(u, 0, sizeof(User));
    u->cb = safe;
    printf("Name: ");
    ssize_t n = read(0, u->name, sizeof(u->name) - 1);
    if (n <= 0) exit(1);
    if (u->name[n - 1] == '\n') {
        u->name[n - 1] = '\0';
    } else {
        u->name[sizeof(u->name) - 1] = '\0';
    }
    users[idx] = u;
    printf("Created user %ld\n", idx);
}

static void delete_user(void) {
    printf("User index (0-%d): ", MAX_USERS - 1);
    long idx = read_long();
    if (idx < 0 || idx >= MAX_USERS) {
        puts("invalid index");
        return;
    }
    if (!users[idx]) {
        puts("no user here");
        return;
    }
    free(users[idx]);
    puts("User deleted");
}

static void use_user(void) {
    printf("User index (0-%d): ", MAX_USERS - 1);
    long idx = read_long();
    if (idx < 0 || idx >= MAX_USERS) {
        puts("invalid index");
        return;
    }
    if (!users[idx]) {
        puts("no user here");
        return;
    }
    puts("running callback...");
    users[idx]->cb();
}

static void create_note(void) {
    printf("Note index (0-%d): ", MAX_NOTES - 1);
    long idx = read_long();
    if (idx < 0 || idx >= MAX_NOTES) {
        puts("invalid index");
        return;
    }
    if (notes[idx]) {
        puts("note slot already in use");
        return;
    }
    Note *n = malloc(sizeof(Note));
    if (!n) exit(1);
    memset(n, 0, sizeof(Note));
    printf("Note text: ");
    ssize_t r = read(0, n->text, sizeof(n->text));
    if (r <= 0) exit(1);
    notes[idx] = n;
    printf("Created note %ld\n", idx);
}

static void edit_note(void) {
    printf("Note index (0-%d): ", MAX_NOTES - 1);
    long idx = read_long();
    if (idx < 0 || idx >= MAX_NOTES) {
        puts("invalid index");
        return;
    }
    if (!notes[idx]) {
        puts("no note here");
        return;
    }
    printf("New text: ");
    ssize_t r = read(0, notes[idx]->text, sizeof(notes[idx]->text));
    if (r <= 0) exit(1);
    puts("note updated");
}

static void show_info(void) {
    printf("win:  %p\n", win);
    printf("safe: %p\n", safe);
    printf("User size: %zu\n", sizeof(User));
    printf("Note size: %zu\n", sizeof(Note));
}

int main(void) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    for (int i = 0; i < MAX_USERS; i++) users[i] = NULL;
    for (int i = 0; i < MAX_NOTES; i++) notes[i] = NULL;

    show_info();

    for (;;) {
        puts("=== UAF task 3 ===");
        puts("1) Create user");
        puts("2) Delete user");
        puts("3) Use user");
        puts("4) Create note");
        puts("5) Edit note");
        puts("6) Exit");
        printf("> ");

        long c = read_long();
        if (c == 1) {
            create_user();
        } else if (c == 2) {
            delete_user();
        } else if (c == 3) {
            use_user();
        } else if (c == 4) {
            create_note();
        } else if (c == 5) {
            edit_note();
        } else if (c == 6) {
            break;
        } else {
            puts("unknown option");
        }
    }

    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i]) free(users[i]);
    }
    for (int i = 0; i < MAX_NOTES; i++) {
        if (notes[i]) free(notes[i]);
    }
    return 0;
}

