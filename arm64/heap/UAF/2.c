#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define MAX_USERS 4
#define MAX_NOTES 4

typedef struct {
    char name[32];
    void (*action)(void);
} User;

typedef struct {
    char *data;
    size_t size;
} Note;

static User *users[MAX_USERS];
static Note notes[MAX_NOTES];

static void win(void) {
    system("/bin/sh");
}

static void safe_action(void) {
    puts("Nothing interesting happens...");
}

static void setup(void) {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);
}

static long read_long(void) {
    char buf[32];
    if (!fgets(buf, sizeof(buf), stdin)) {
        exit(1);
    }
    return strtol(buf, NULL, 10);
}

static void read_bytes(char *buf, size_t size) {
    ssize_t n = read(0, buf, size);
    if (n <= 0) {
        puts("read error");
        exit(1);
    }
}

static void menu(void) {
    puts("=== UAF task 2 ===");
    puts("1) Create user");
    puts("2) Delete user");
    puts("3) Use user");
    puts("4) Create note");
    puts("5) Edit note");
    puts("6) Exit");
    printf("> ");
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
    printf("DEBUG ALLOCATED ADDR: %p\n", u);
    if (!u) {
        puts("malloc failed");
        exit(1);
    }

    u->action = safe_action;
    memset(u->name, 0, sizeof(u->name));

    printf("Name: ");
    ssize_t n = read(0, u->name, sizeof(u->name) - 1);
    if (n <= 0) {
        puts("read error");
        free(u);
        exit(1);
    }
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
    // users[idx] = NULL; // тут фиксим UAF
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

    printf("Using user %ld (%s)\n", idx, users[idx]->name);
    users[idx]->action();
}

static void create_note(void) {
    printf("Note index (0-%d): ", MAX_NOTES - 1);
    long idx = read_long();
    if (idx < 0 || idx >= MAX_NOTES) {
        puts("invalid index");
        return;
    }
    if (notes[idx].data) {
        puts("note already exists");
        return;
    }

    notes[idx].size = sizeof(User);
    notes[idx].data = malloc(notes[idx].size);
    printf("DEBUG ALLOCATED ADDR: %p\n", notes[idx].data);

    if (!notes[idx].data) {
        puts("malloc failed");
        exit(1);
    }

    printf("Write %zu bytes to note:\n", notes[idx].size);
    read_bytes(notes[idx].data, notes[idx].size);
    puts("Note created");
}

static void edit_note(void) {
    printf("Note index (0-%d): ", MAX_NOTES - 1);
    long idx = read_long();
    if (idx < 0 || idx >= MAX_NOTES) {
        puts("invalid index");
        return;
    }
    if (!notes[idx].data || !notes[idx].size) {
        puts("no note here");
        return;
    }

    printf("Rewrite %zu bytes:\n", notes[idx].size);
    read_bytes(notes[idx].data, notes[idx].size);
    puts("Note edited");
}

int main(void) {
    setup();

    printf("win:  %p\n", (void *)win);
    printf("safe: %p\n", (void *)safe_action);
    printf("User size: %zu\n", sizeof(User));

    while (1) {
        menu();
        long choice = read_long();

        switch (choice) {
        case 1:
            create_user();
            break;
        case 2:
            delete_user();
            break;
        case 3:
            use_user();
            break;
        case 4:
            create_note();
            break;
        case 5:
            edit_note();
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

