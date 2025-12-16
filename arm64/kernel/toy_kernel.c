#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/random.h>

typedef struct kobject {
    uint64_t    id;
    uint32_t    refcount;
    uint32_t    flags;
    size_t      size;
    uintptr_t   encoded_handler; /* handler ^ cookie */
    char       *data;
} kobject;

#define MAX_KOBJECTS 32
#define MAX_RAWS     64

static kobject *g_kobjects[MAX_KOBJECTS];
static void    *g_raw_chunks[MAX_RAWS];
static uint64_t g_next_id = 1;
static uintptr_t g_cookie;

static void win(void) {
    puts("[*] you reached win() in kernel context!");
    system("/bin/sh");
    _exit(0);
}

typedef void (*khandler_t)(kobject *obj, char *user_buf, size_t len);

static void safe_handler(kobject *obj, char *user_buf, size_t len) {
    (void)user_buf;
    (void)len;
    printf("[*] safe_handler: kobject id=%llu size=%zu data=%p\n",
           (unsigned long long)obj->id, obj->size, (void *)obj->data);
    if (obj->data && obj->size) {
        printf("[*] first bytes: ");
        size_t to_print = obj->size;
        if (to_print > 16) {
            to_print = 16;
        }
        for (size_t i = 0; i < to_print; i++) {
            printf("%02x ", (unsigned char)obj->data[i]);
        }
        puts("");
    }
}

static void init_cookie(void) {
    uint64_t v = 0;
    if (getentropy(&v, sizeof(v)) != 0) {
        v = (uint64_t)rand() ^ (uint64_t)(uintptr_t)&v ^ (uint64_t)(uintptr_t)&win;
    }
    if (v == 0) {
        v = 0xdeadbeefcafebabeULL;
    }
    g_cookie = (uintptr_t)v;
}

static uintptr_t encode_handler(khandler_t h) {
    return (uintptr_t)h ^ g_cookie;
}

static khandler_t decode_handler(uintptr_t enc) {
    return (khandler_t)(enc ^ g_cookie);
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

static void kobject_create(void) {
    int slot = -1;
    for (int i = 0; i < MAX_KOBJECTS; i++) {
        if (!g_kobjects[i]) {
            slot = i;
            break;
        }
    }
    if (slot == -1) {
        puts("[-] no free kobject slots");
        return;
    }

    printf("size of kernel buffer (max 0x400): ");
    size_t sz = read_size();
    if (sz == 0 || sz > 0x400) {
        puts("[-] bad size");
        return;
    }

    kobject *obj = (kobject *)malloc(sizeof(kobject));
    if (!obj) {
        puts("[-] malloc kobject failed");
        exit(1);
    }
    memset(obj, 0, sizeof(*obj));

    obj->data = (char *)malloc(sz);
    if (!obj->data) {
        puts("[-] malloc data failed");
        free(obj);
        exit(1);
    }

    obj->id = g_next_id++;
    obj->refcount = 1;
    obj->flags = 0;
    obj->size = sz;
    obj->encoded_handler = encode_handler(safe_handler);

    g_kobjects[slot] = obj;

    printf("[+] created kobject slot=%d ptr=%p id=%llu size=%zu\n",
           slot, (void *)obj, (unsigned long long)obj->id, obj->size);
}

static void kobject_release(void) {
    printf("slot index (0-%d): ", MAX_KOBJECTS - 1);
    long idx = read_long();
    if (idx < 0 || idx >= MAX_KOBJECTS) {
        puts("[-] bad index");
        return;
    }
    if (!g_kobjects[idx]) {
        puts("[-] no kobject in slot");
        return;
    }
    kobject *obj = g_kobjects[idx];
    if (obj->refcount == 0) {
        puts("[!] refcount already zero (logic bug)");
    } else {
        obj->refcount--;
    }
    printf("[*] release: kobject %p id=%llu refcount=%u\n",
           (void *)obj, (unsigned long long)obj->id, obj->refcount);
    if (obj->refcount == 0) {
        printf("[*] freeing kobject %p\n", (void *)obj);
        free(obj->data);
        free(obj);
    }
}

static void kobject_retain(void) {
    printf("slot index (0-%d): ", MAX_KOBJECTS - 1);
    long idx = read_long();
    if (idx < 0 || idx >= MAX_KOBJECTS) {
        puts("[-] bad index");
        return;
    }
    if (!g_kobjects[idx]) {
        puts("[-] no kobject in slot");
        return;
    }
    kobject *obj = g_kobjects[idx];
    obj->refcount++;
    printf("[*] retain: kobject %p id=%llu refcount=%u\n",
           (void *)obj, (unsigned long long)obj->id, obj->refcount);
}

static void kobject_write_data(void) {
    printf("slot index (0-%d): ", MAX_KOBJECTS - 1);
    long idx = read_long();
    if (idx < 0 || idx >= MAX_KOBJECTS) {
        puts("[-] bad index");
        return;
    }
    if (!g_kobjects[idx]) {
        puts("[-] no kobject in slot");
        return;
    }
    kobject *obj = g_kobjects[idx];
    printf("bytes to write (<= %zu): ", obj->size);
    size_t n = read_size();
    if (n > obj->size) {
        puts("[-] too big");
        return;
    }
    printf("[*] writing %zu bytes to kernel buffer\n", n);
    read_bytes(obj->data, n);
}

/* infoleak: dumps raw kernel object, including encoded_handler */
static void kobject_debug_leak(void) {
    printf("slot index (0-%d): ", MAX_KOBJECTS - 1);
    long idx = read_long();
    if (idx < 0 || idx >= MAX_KOBJECTS) {
        puts("[-] bad index");
        return;
    }
    if (!g_kobjects[idx]) {
        puts("[-] no kobject in slot");
        return;
    }
    kobject *obj = g_kobjects[idx];
    printf("[*] kobject leak slot=%ld ptr=%p\n", idx, (void *)obj);
    unsigned char *p = (unsigned char *)obj;
    for (size_t off = 0; off < sizeof(kobject); off += 8) {
        uint64_t v = 0;
        memcpy(&v, p + off, sizeof(v));
        printf("  +0x%02zx : 0x%016llx\n",
               off, (unsigned long long)v);
    }
}

/* user-controlled allocations of same size as kobject to reclaim freed chunks */
static void raw_alloc(void) {
    int slot = -1;
    for (int i = 0; i < MAX_RAWS; i++) {
        if (!g_raw_chunks[i]) {
            slot = i;
            break;
        }
    }
    if (slot == -1) {
        puts("[-] no free raw slots");
        return;
    }
    void *p = malloc(sizeof(kobject));
    if (!p) {
        puts("[-] malloc raw failed");
        exit(1);
    }
    printf("[+] raw chunk slot=%d ptr=%p (size=%zu)\n",
           slot, p, sizeof(kobject));
    printf("[*] provide %zu bytes for raw chunk:\n", sizeof(kobject));
    read_bytes(p, sizeof(kobject));
    g_raw_chunks[slot] = p;
}

static void raw_free(void) {
    printf("raw slot index (0-%d): ", MAX_RAWS - 1);
    long idx = read_long();
    if (idx < 0 || idx >= MAX_RAWS) {
        puts("[-] bad index");
        return;
    }
    if (!g_raw_chunks[idx]) {
        puts("[-] no raw chunk in slot");
        return;
    }
    free(g_raw_chunks[idx]);
    g_raw_chunks[idx] = NULL;
    puts("[*] raw chunk freed");
}

/* vulnerable entry: uses encoded_handler ^ cookie function pointer */
static void kobject_invoke(void) {
    printf("slot index (0-%d): ", MAX_KOBJECTS - 1);
    long idx = read_long();
    if (idx < 0 || idx >= MAX_KOBJECTS) {
        puts("[-] bad index");
        return;
    }
    if (!g_kobjects[idx]) {
        puts("[-] no kobject in slot");
        return;
    }
    kobject *obj = g_kobjects[idx];

    char buf[256];
    printf("user data length (max %zu): ", sizeof(buf));
    size_t n = read_size();
    if (n > sizeof(buf)) {
        puts("[-] too big");
        return;
    }
    printf("[*] send %zu bytes of user data\n", n);
    if (n > 0) {
        read_bytes(buf, n);
    }

    uintptr_t enc = obj->encoded_handler;
    khandler_t fn = decode_handler(enc);

    printf("[*] invoking handler %p for kobject %p\n",
           (void *)fn, (void *)obj);
    fn(obj, buf, n);
}

static void menu(void) {
    puts("=== toy XNU-style kernel ===");
    puts("1) create kobject");
    puts("2) retain kobject");
    puts("3) release kobject   (UAF bug)");
    puts("4) write kobject data");
    puts("5) debug leak kobject (infoleak)");
    puts("6) raw alloc (heap spray same size as kobject)");
    puts("7) raw free");
    puts("8) invoke kobject handler (function pointer)");
    puts("9) exit");
    printf("> ");
}

int main(void) {
    setup_stdio();
    init_cookie();

    printf("[info] toy_kernel compiled for arm64/arm64e userland\n");
    printf("[info] sizeof(kobject): %zu\n", sizeof(kobject));
    printf("[info] offsetof(encoded_handler): 0x%zx\n",
           offsetof(kobject, encoded_handler));
    printf("[info] safe_handler: %p\n", (void *)safe_handler);
    printf("[info] win:         %p\n", (void *)win);

    for (;;) {
        menu();
        long choice = read_long();
        switch (choice) {
        case 1:
            kobject_create();
            break;
        case 2:
            kobject_retain();
            break;
        case 3:
            kobject_release();
            break;
        case 4:
            kobject_write_data();
            break;
        case 5:
            kobject_debug_leak();
            break;
        case 6:
            raw_alloc();
            break;
        case 7:
            raw_free();
            break;
        case 8:
            kobject_invoke();
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

