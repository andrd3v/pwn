CC      = clang
CFLAGS  = -Wall -Wextra -O0 -g -fno-stack-protector -fno-pic -fno-pie
LDFLAGS = -Wl,-no_pie

all: toy_kernel hard_kernel

toy_kernel: toy_kernel.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

hard_kernel: hard_kernel.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f toy_kernel hard_kernel

