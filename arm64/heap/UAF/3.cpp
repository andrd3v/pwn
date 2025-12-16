#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

class Animal {
public:
    virtual void speak() {
        std::puts("Animal speaks...");
    }

};

class Dog : public Animal {
public:
    void speak() override {
        std::puts("Woof! (safe)");
    }
};

static Animal *g_animal = nullptr;
static char *g_buf = nullptr;

static void win() {
    std::system("/bin/sh");
}

using func_t = void (*)();
static func_t fake_vtable[] = { win };

static void setup() {
    setbuf(stdout, nullptr);
    setbuf(stdin, nullptr);
    setbuf(stderr, nullptr);
}

static long read_long() {
    char buf[32];
    if (!fgets(buf, sizeof(buf), stdin)) {
        std::exit(1);
    }
    return std::strtol(buf, nullptr, 10);
}

static void read_bytes(char *buf, size_t size) {
    ssize_t n = ::read(0, buf, size);
    if (n <= 0) {
        std::puts("read error");
        std::exit(1);
    }
}

static void menu() {
    std::puts("=== UAF vtable task ===");
    std::puts("1) Create animal");
    std::puts("2) Delete animal");
    std::puts("3) Use animal");
    std::puts("4) Allocate buffer");
    std::puts("5) Exit");
    std::printf("> ");
}

static void create_animal() {
    if (g_animal) {
        std::puts("animal already exists");
        return;
    }

    g_animal = new Dog();
    std::printf("Created Animal at %p (Dog)\n", (void *)g_animal);
}

static void delete_animal() {
    if (!g_animal) {
        std::puts("no animal");
        return;
    }

    std::printf("Deleting Animal at %p\n", (void *)g_animal);
    delete g_animal;

    std::puts("Animal deleted");
}

static void use_animal() {
    if (!g_animal) {
        std::puts("no animal");
        return;
    }

    std::printf("Using Animal at %p\n", (void *)g_animal);
    g_animal->speak();
}

static void allocate_buffer() {
    if (g_buf) {
        std::puts("buffer already allocated");
        return;
    }

    size_t sz = sizeof(Dog);
    g_buf = new char[sz];
    std::printf("Allocated buffer of size %zu at %p\n", sz, (void *)g_buf);
    std::printf("Write %zu bytes to buffer:\n", sz);
    read_bytes(g_buf, sz);
    std::puts("Buffer written");
}

int main() {
    setup();

    std::printf("win:        %p\n", (void *)win);
    std::printf("fake_vtable: %p\n", (void *)fake_vtable);
    std::printf("sizeof(Animal): %zu\n", sizeof(Animal));
    std::printf("sizeof(Dog):    %zu\n", sizeof(Dog));

    while (true) {
        menu();
        long choice = read_long();

        switch (choice) {
        case 1:
            create_animal();
            break;
        case 2:
            delete_animal();
            break;
        case 3:
            use_animal();
            break;
        case 4:
            allocate_buffer();
            break;
        case 5:
            std::puts("bye");
            return 0;
        default:
            std::puts("unknown option");
            break;
        }
    }
}
