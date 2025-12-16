#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

typedef struct 
{
  int a;
  char name[8];
} data;


typedef struct 
{
  u_int8_t a;
  char name[16];
} big_data;

void memory_dumper(uintptr_t addr, size_t size) {
    unsigned char *ptr = (unsigned char *)addr;

    for (size_t i = 0; i < size; i += 16) {
        printf("%016lx  ", (unsigned long)(addr + i));
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < size)
                printf("%02x ", ptr[i + j]);
            else
                printf("   ");
            if (j == 7) printf(" "); 
        }

        printf(" |");

        for (size_t j = 0; j < 16 && i + j < size; ++j) {
            unsigned char c = ptr[i + j];
            printf("%c", isprint(c) ? c : '.');
        }

        printf("|\n");
    }
}


int main(int argc, char *argv[])
{
  data *d = malloc(sizeof(data));
  d->a = 5;
  strncpy(d->name, "ilyaandr", sizeof(d->name));
  
  printf("data: %p\n", (void*)d);
  printf("int a: %p\n", (void*)&d->a);
  printf("char name: %p\n", (void*)d->name);


  data *d2 = malloc(sizeof(data));
  d2->a = 6;
  strncpy(d2->name, "nikitahm", sizeof(d->name));
  
  printf("data2: %p\n", (void*)d2);
  printf("int a2: %p\n", (void*)&d2->a);
  printf("char name2: %p\n", (void*)d2->name);

  big_data *bd = malloc(sizeof(big_data));
  bd->a = 7;
  strncpy(bd->name, "ilyaandr+nikitahm = kaktus", sizeof(bd->name));
  printf("big data: %p\n", (void*)bd);
  printf("int big data: %p\n", (void*)&bd->a);
  printf("char big data: %p\n", (void*)bd->name);


  memory_dumper((uintptr_t)d-0x300, 0x1000);

  return EXIT_SUCCESS;
}

