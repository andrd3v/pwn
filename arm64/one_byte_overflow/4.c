/*
 задание: one_byte_overflow -> UAF -> ROP
 то есть функцию  win можно вызвать только из vuln
 
 также советую не смотреть сурсы тут, а чекать код только в иде
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void vuln(void) __attribute__((no_stack_protector));


typedef struct {
    char name[16];
    unsigned char len;
    char bio[32];
} Profile;

typedef struct {
    char pad[40];
    void (*cb)(void);
    unsigned char freed;
} Session;

static Profile *profile = NULL;
static Session *session = NULL;

void safe(void);
void win(void) __attribute__((used));
void vuln(void) __attribute__((used));

static long read_long(void) {
    char buf[32];
    ssize_t n = read(0, buf, sizeof(buf) - 1);
    if (n <= 0) exit(1);
    buf[n] = '\0';
    return strtol(buf, NULL, 10);
}

void safe(void) {
    puts("safe session");
}

void win(void) {
    puts("you win, here is your flag:");
    system("/bin/cat flag.txt");
}

void vuln(void) {
    char buf[64];
    puts("vuln: ROP payload:");
    read(0, buf, 256);
}

static void show_info(void) {
    printf("safe:  %p\n", safe);
    printf("win:   %p\n", win);
    printf("vuln:  %p\n", vuln);
}

static void create_profile(void) {
    if (profile) {
        puts("profile already exists");
        return;
    }
    profile = malloc(sizeof(Profile));
    if (!profile) exit(1);
    memset(profile, 0, sizeof(Profile));
    profile->len = 32;
    printf("Name: ");
    ssize_t n = read(0, profile->name, 17);
    if (n <= 0) exit(1);
    if (n < 16) {
        profile->name[n] = '\0';
    } else {
        profile->name[15] = '\0';
    }
    puts("profile created");
}

static void edit_bio(void) {
    if (!profile) {
        puts("no profile");
        return;
    }
    printf("Bio (max %u bytes): ", profile->len);
    ssize_t n = read(0, profile->bio, profile->len);
    if (n <= 0) {
        puts("edit error");
        return;
    }
    puts("bio updated");
}

static void show_profile(void) {
    if (!profile) {
        puts("no profile");
        return;
    }
    printf("Name: %s\n", profile->name);
    printf("Len: %u\n", profile->len);
    write(1, "Bio: ", 5);
    write(1, profile->bio, 32);
    write(1, "\n", 1);
}

static void create_session(void) {
    if (session) {
        puts("session already exists");
        return;
    }
    session = malloc(sizeof(Session));
    if (!session) exit(1);
    memset(session, 0, sizeof(Session));
    session->cb = safe;
    session->freed = 0;
    puts("session created");
}

static void delete_session(void) {
    if (!session) {
        puts("no session");
        return;
    }
    free(session);
    session->freed = 1;
    puts("session deleted");
}

static void run_session(void) {
    if (!session) {
        puts("no session");
        return;
    }
    if (session->freed) {
        puts("session already deleted");
        return;
    }
    puts("running session callback...");
    session->cb();
}

int main(void) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    show_info();

    for (;;) {
        puts("=== One-byte + UAF + ROP ===");
        printf("Profile: %p\n", (void*)profile);
        printf("Session: %p\n", (void*)session);
        puts("1) Create profile");
        puts("2) Edit bio");
        puts("3) Show profile");
        puts("4) Create session");
        puts("5) Delete session");
        puts("6) Run session");
        puts("7) Exit");
        printf("> ");

        long c = read_long();
        if (c == 1) {
            create_profile();
        } else if (c == 2) {
            edit_bio();
        } else if (c == 3) {
            show_profile();
        } else if (c == 4) {
            create_session();
        } else if (c == 5) {
            delete_session();
        } else if (c == 6) {
            run_session();
        } else if (c == 7) {
            break;
        } else {
            puts("unknown option");
        }
    }

    if (profile) free(profile);
    if (session && !session->freed) free(session);
    return 0;
}

