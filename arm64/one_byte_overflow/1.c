#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    char name[16];
    unsigned char is_admin;
} User;

static User *user = NULL;

static long read_long(void) {
    char buf[32];
    ssize_t n = read(0, buf, sizeof(buf) - 1);
    if (n <= 0) exit(1);
    buf[n] = '\0';
    return strtol(buf, NULL, 10);
}

static void register_user(void) {
    if (user) {
        puts("user already exists");
        return;
    }
    user = malloc(sizeof(User));
    if (!user) exit(1);
    memset(user, 0, sizeof(User));

    printf("Name: ");
    ssize_t n = read(0, user->name, 17);
    if (n <= 0) exit(1);
    if (n < 16) {
        user->name[n] = '\0';
    } else {
        user->name[15] = '\0';
    }
    puts("user created");
}

static void show_user(void) {
    if (!user) {
        puts("no user");
        return;
    }
    printf("Name: %s\n", user->name);
    printf("is_admin: %u\n", user->is_admin);
}

static void get_flag(void) {
    if (!user) {
        puts("no user");
        return;
    }
    if (user->is_admin) {
        puts("you are admin, here is your flag:");
        system("/bin/cat flag.txt");
    } else {
        puts("access denied");
    }
}

int main(void) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    for (;;) {
        puts("=== One-byte overflow task ===");
        puts("1) register user");
        puts("2) show user");
        puts("3) get flag");
        puts("4) exit");
        printf("> ");

        long c = read_long();
        if (c == 1) {
            register_user();
        } else if (c == 2) {
            show_user();
        } else if (c == 3) {
            get_flag();
        } else if (c == 4) {
            break;
        } else {
            puts("unknown choice");
        }
    }

    if (user) free(user);
    return 0;
}

