  #include <stdio.h>
  #include <stdlib.h>
  #include <string.h>
  #include <unistd.h>

  void set_ls(void) __attribute__((no_stack_protector));
  void add_la(void) __attribute__((no_stack_protector));
  void run_cmd(void) __attribute__((no_stack_protector));
  int main() __attribute__((no_stack_protector));

  char cmd[64] = "date";

  void set_ls(void) {
      strcpy(cmd, "ls");
  }

  void add_la(void) {
      strcat(cmd, " -la");
  }

  void run_cmd(void) {
      system(cmd);
  }

  int main() {
      char buf[16];
      read(0, buf, 512);
      return 0;
  }
