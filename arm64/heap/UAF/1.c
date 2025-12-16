#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

typedef struct 
{
  int code;
  void (*fn)(void);
} meta_info;

typedef struct
{
  int pin_code;
  char name[24];
  meta_info *info;
} data;

void win(void)
{
  system("/bin/ls");
}

void safe(void)
{
  puts("SAFE");
}

int main(void)
{
  setbuf(stdout, NULL);

  data *d = malloc(sizeof(data));
  meta_info *info = malloc(sizeof(meta_info));

  if (!d || !info) {
    perror("malloc");
    return 1;
  }

  d->pin_code = 1337;
  strncpy(d->name, "task1", sizeof(d->name) - 1);
  d->name[sizeof(d->name) - 1] = '\0';

  d->info = info;
  d->info->code = 1;
  d->info->fn = safe;

  printf("data:        %p\n", (void *)d);
  printf("d->info:     %p\n", (void *)d->info);
  printf("&d->info->fn %p\n", (void *)&d->info->fn);
  printf("win:         %p\n", (void *)win);
  printf("safe:        %p\n", (void *)safe);

  free(d->info); // use-after-free: d->info остается висеть

  meta_info *uaf = malloc(sizeof(meta_info));
  printf("uaf chunk:   %p\n", (void *)uaf);

  printf("read meta_info:\n");
  read(0, uaf, sizeof(meta_info));

  printf("calling d->info->fn()\n");
  d->info->fn();

  return 0;
}
