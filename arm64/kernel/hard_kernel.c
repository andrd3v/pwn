#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

typedef struct kcred {
    uint64_t uid;
    uint64_t gid;
    uint64_t pad1;
    uint64_t pad2;
} kcred;

typedef struct userclient {
    uint64_t id;
    char    *kaddr;   /* interpreted as kernel address */
    size_t   ksize;   /* logical size of kernel region */
    char    *backing; /* real buffer for honest clients */
} userclient;

#define MAX_CLIENTS 8
#define MAX_RAW     32

static userclient *g_clients[MAX_CLIENTS];
static void       *g_raw[MAX_RAW];
static uint64_t    g_next_id = 1;

static kcred g_cred = {
    .uid  = 1000,
    .gid  = 1000,
    .pad1 = 0,
    .pad2 = 0,
};

static const kcred g_root_cred = {
    .uid  = 0,
    .gid  = 0,
    .pad1 = 0,
    .pad2 = 0,
};

static void win(void) {
    puts("[+] kernel says: you are root, enjoy your shell");
    system("/bin/sh");
    _exit(0);
}

static void setup_stdio(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

static long read_long(void) {
    char buf[64];
    if (!fgets(buf, sizeof(buf), stdin)) {
        exit(1);
    }
    return strtol(buf, NULL, 10);
}

static size_t read_size(void) {
    long v = read_long();
    if (v < 0) {
        return 0;
    }
    return (size_t)v;
}

static void read_bytes(void *buf, size_t sz) {
    size_t off = 0;
    while (off < sz) {
        ssize_t n = read(0, (char *)buf + off, sz - off);
        if (n <= 0) {
            puts("[-] read error");
            exit(1);
        }
        off += (size_t)n;
    }
}

static void debug_info(void) {
    printf("[info] hard_kernel: sizeof(userclient) = %zu\n", sizeof(userclient));
    printf("[info] g_cred @ %p (uid=%llu gid=%llu)\n",
           (void *)&g_cred,
           (unsigned long long)g_cred.uid,
           (unsigned long long)g_cred.gid);
    printf("[info] g_root_cred @ %p\n", (void *)&g_root_cred);
    printf("[info] win() @ %p\n", (void *)win);
}

static void client_open(void) {
    int slot = -1;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!g_clients[i]) {
            slot = i;
            break;
        }
    }
    if (slot == -1) {
        puts("[-] no free client slots");
        return;
    }

    printf("buffer size (max 0x400): ");
    size_t sz = read_size();
    if (sz == 0 || sz > 0x400) {
        puts("[-] bad size");
        return;
    }

    userclient *uc = (userclient *)malloc(sizeof(userclient));
    if (!uc) {
        puts("[-] malloc userclient failed");
        exit(1);
    }
    memset(uc, 0, sizeof(*uc));

    char *buf = (char *)malloc(sz);
    if (!buf) {
        puts("[-] malloc backing failed");
        free(uc);
        exit(1);
    }

    uc->id = g_next_id++;
    uc->backing = buf;
    uc->kaddr = buf;
    uc->ksize = sz;

    g_clients[slot] = uc;

    printf("[+] opened client slot=%d uc=%p backing=%p size=%zu id=%llu\n",
           slot, (void *)uc, (void *)buf, sz, (unsigned long long)uc->id);
}

static void client_write(void) {
    printf("client slot (0-%d): ", MAX_CLIENTS - 1);
    long idx = read_long();
    if (idx < 0 || idx >= MAX_CLIENTS) {
        puts("[-] bad index");
        return;
    }
    if (!g_clients[idx]) {
        puts("[-] no client in slot");
        return;
    }
    userclient *uc = g_clients[idx];
    if (!uc->backing || uc->ksize == 0) {
        puts("[-] client has no backing buffer");
        return;
    }

    printf("bytes to write (<= %zu): ", uc->ksize);
    size_t n = read_size();
    if (n > uc->ksize) {
        puts("[-] too big");
        return;
    }
    printf("[*] writing %zu bytes into client backing\n", n);
    read_bytes(uc->backing, n);
}

static void client_close(void) {
    printf("client slot (0-%d): ", MAX_CLIENTS - 1);
    long idx = read_long();
    if (idx < 0 || idx >= MAX_CLIENTS) {
        puts("[-] bad index");
        return;
    }
    if (!g_clients[idx]) {
        puts("[-] no client in slot");
        return;
    }
    userclient *uc = g_clients[idx];
    printf("[*] closing client slot=%ld uc=%p backing=%p\n",
           idx, (void *)uc, (void *)uc->backing);

    if (uc->backing) {
        free(uc->backing);
        uc->backing = NULL;
    }

    /*
     * Логическое освобождение: ядро считает client "мертвым",
     * но структура остаётся аллоцированной, а указатель в g_clients[]
     * не чистится. Это моделирует dangling pointer на объект в слэбе.
     */
    uc->kaddr = (char *)0;
    uc->ksize = 0;
    uc->id ^= 0xdeadbeefdeadbeefULL;

    puts("[!] client logically freed but slot pointer not cleared (dangling)");
}

static void client_debug_dump(void) {
    printf("client slot (0-%d): ", MAX_CLIENTS - 1);
    long idx = read_long();
    if (idx < 0 || idx >= MAX_CLIENTS) {
        puts("[-] bad index");
        return;
    }
    if (!g_clients[idx]) {
        puts("[-] no client in slot");
        return;
    }
    userclient *uc = g_clients[idx];
    printf("[debug] uc=%p id=%llu kaddr=%p ksize=%zu backing=%p\n",
           (void *)uc,
           (unsigned long long)uc->id,
           (void *)uc->kaddr,
           uc->ksize,
           (void *)uc->backing);
}

/*
 * Vulnerable primitive: treat uc->kaddr as kernel address and
 * write user data there. Intended for safe clients, but with
 * dangling userclient + fake contents you can turn this into
 * arbitrary write.
 *
 * BUG: only checks off <= ksize, not off + sz <= ksize.
 */
static void kernel_write_via_client(void) {
    printf("client slot (0-%d): ", MAX_CLIENTS - 1);
    long idx = read_long();
    if (idx < 0 || idx >= MAX_CLIENTS) {
        puts("[-] bad index");
        return;
    }
    if (!g_clients[idx]) {
        puts("[-] no client in slot");
        return;
    }
    userclient *uc = g_clients[idx];
    if (!uc->kaddr || uc->ksize == 0) {
        puts("[-] client has no kernel mapping");
        return;
    }

    printf("offset into kernel region: ");
    size_t off = read_size();
    printf("size to write (max 0x400): ");
    size_t sz = read_size();

    if (off > uc->ksize) {
        puts("[-] bad offset");
        return;
    }
    if (sz == 0 || sz > 0x400) {
        puts("[-] bad size");
        return;
    }

    char tmp[0x400];
    printf("[*] provide %zu bytes to write into kernel memory\n", sz);
    read_bytes(tmp, sz);

    char *dst = uc->kaddr + off;
    printf("[*] kernel write: dst=%p (kaddr=%p + 0x%zx) sz=%zu\n",
           (void *)dst, (void *)uc->kaddr, off, sz);

    memcpy(dst, tmp, sz);
}

static int is_client_struct(void *p) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_clients[i] == (userclient *)p) {
            return 1;
        }
    }
    return 0;
}

/*
 * Найти "логически освобождённый" client:
 * backing == NULL и ksize == 0 после client_close().
 */
static int find_logically_freed_client(void) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_clients[i] &&
            g_clients[i]->backing == NULL &&
            g_clients[i]->ksize == 0) {
            return i;
        }
    }
    return -1;
}

/* raw heap feng-shui: либо переиспользуем userclient, либо берём свежий heap chunk */
static void raw_alloc(void) {
    int slot = -1;
    for (int i = 0; i < MAX_RAW; i++) {
        if (!g_raw[i]) {
            slot = i;
            break;
        }
    }
    if (slot == -1) {
        puts("[-] no free raw slots");
        return;
    }

    void *p = NULL;
    int dead_idx = find_logically_freed_client();
    if (dead_idx >= 0) {
        /* Напрямую перехватываем структуру userclient */
        p = (void *)g_clients[dead_idx];
        printf("[+] raw chunk slot=%d ptr=%p size=%zu (reusing logical freed userclient from client slot %d)\n",
               slot, p, sizeof(userclient), dead_idx);
    } else {
        p = malloc(sizeof(userclient));
        if (!p) {
            puts("[-] malloc raw failed");
            exit(1);
        }
        printf("[+] raw chunk slot=%d ptr=%p size=%zu\n",
               slot, p, sizeof(userclient));
    }

    printf("[*] write %zu bytes into raw chunk:\n", sizeof(userclient));
    read_bytes(p, sizeof(userclient));

    g_raw[slot] = p;
}

static void raw_free(void) {
    printf("raw slot (0-%d): ", MAX_RAW - 1);
    long idx = read_long();
    if (idx < 0 || idx >= MAX_RAW) {
        puts("[-] bad index");
        return;
    }
    if (!g_raw[idx]) {
        puts("[-] no raw chunk in slot");
        return;
    }
    void *p = g_raw[idx];
    if (is_client_struct(p)) {
        puts("[*] raw chunk points into userclient; not freeing underlying memory");
    } else {
        free(p);
        puts("[*] raw heap chunk freed");
    }
    g_raw[idx] = NULL;
}

static void check_root_and_win(void) {
    printf("[*] current cred: uid=%llu gid=%llu\n",
           (unsigned long long)g_cred.uid,
           (unsigned long long)g_cred.gid);
    if (g_cred.uid == 0) {
        puts("[+] privilege check: uid == 0, entering win()");
        win();
    } else {
        puts("[-] not root yet, try harder");
    }
}

static void menu(void) {
    puts("=== hard_kernel: XNU-style userclient/cred pwn ===");
    puts("1) open userclient");
    puts("2) write client backing buffer");
    puts("3) close userclient (UAF bug)");
    puts("4) debug dump client");
    puts("5) kernel write via client (buggy bounds)");
    puts("6) raw alloc (heap feng shui, sizeof(userclient))");
    puts("7) raw free");
    puts("8) check root & win()");
    puts("9) quit");
    printf("> ");
}

int main(void) {
    setup_stdio();
    debug_info();

    for (;;) {
        menu();
        long choice = read_long();
        switch (choice) {
        case 1:
            client_open();
            break;
        case 2:
            client_write();
            break;
        case 3:
            client_close();
            break;
        case 4:
            client_debug_dump();
            break;
        case 5:
            kernel_write_via_client();
            break;
        case 6:
            raw_alloc();
            break;
        case 7:
            raw_free();
            break;
        case 8:
            check_root_and_win();
            break;
        case 9:
            puts("bye");
            return 0;
        default:
            puts("unknown choice");
            break;
        }
    }
}
