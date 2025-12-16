#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void change(void) __attribute__((no_stack_protector));
void secret(void) __attribute__((no_stack_protector));
int main() __attribute__((no_stack_protector));

char command[] = "date";

void change(void) {
    strcpy(command, "ls");
}

void secret(void) {
    system(command);
}

int main() {
    char buff[8];
    scanf("%s", buff);
    return 0;
}

