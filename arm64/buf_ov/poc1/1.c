#include <stdio.h>
#include <stdlib.h>

void secret(void) __attribute__((no_stack_protector));
void secret(void)
{
  printf("Wow ur are strong!\n");
}

int vuln(void) __attribute__((no_stack_protector));
int vuln(void)
{
  char buf[16];
  scanf("%64s", buf);
  printf("%s\n", buf);
  return 1;
}

int main(int argc, char *argv[]) __attribute__((no_stack_protector));
int main(int argc, char *argv[])
{
  int a;
  printf("secret (as pointer) : %p\n", (void*)(uintptr_t)secret);
  printf("Let's try hack me!\n");
  a = vuln();
  return a;
}




