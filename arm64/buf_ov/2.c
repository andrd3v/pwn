#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char username[16];
    char password[16];
    int is_authenticated;
    void (*auth_handler)();
} user_session;

void secret(void) __attribute__((no_stack_protector));
void default_auth(void) __attribute__((no_stack_protector));

void secret(void) {
    printf("Access granted! Secret flag: CTF{Buff3r_0v3rfl0w_M4st3r}\n");
    exit(0);
}

void default_auth(void) {
    printf("Authentication failed.\n");
}

void login(void) __attribute__((no_stack_protector));
void login(void) {
    user_session session;
    char input_buffer[12];
    
    session.is_authenticated = 0;
    session.auth_handler = default_auth;
    strcpy(session.username, "guest");
    strcpy(session.password, "password123");
    
    printf("Username: %s\n", session.username);
    printf("Enter your credentials: ");
    gets(input_buffer);
    
    printf("Input: %s\n", input_buffer);
    printf("is_authenticated: %d\n", session.is_authenticated);
    
    if (session.is_authenticated) {
        printf("Welcome admin!\n");
        session.auth_handler();
    } else {
        session.auth_handler();
    }
}

int main(int argc, char *argv[]) __attribute__((no_stack_protector));
int main(int argc, char *argv[]) {
    printf("=== Secure Login System ===\n");
    login();
    return 0;
}
