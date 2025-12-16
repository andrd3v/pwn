#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void func(void) __attribute__((no_stack_protector));
int main(void) __attribute__((no_stack_protector));
void idk_what_is_it(void) __attribute__((naked, used));

static char ls[] __attribute__((used)) = "/bin/ls";

void win()
{
    puts("end?...");
}

void idk_what_is_it(void) {
    __asm__(
        "ldp x0, x30, [sp], #16\n\t"
        "ret\n\t"
    );
}

void func()
{
  char buf[8];
  gets(buf);
}

int main(void)
{
  puts("hi, sweetie! Gime me ur passwd: ");
  func();
  return EXIT_SUCCESS;
}


// pls call system("/bin/ls")
// lol its easy to us man
