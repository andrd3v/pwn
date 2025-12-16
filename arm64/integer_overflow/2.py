mask = 0x4242
big = 0xDEADBEEF

for i in range(10000, 100000000000000):
    new = hex(i * big)
    if new.endswith("4242"):
        print(i)
        break
