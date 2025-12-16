from platform import processor
from pwn import *

context.log_level = "DEBUG"
p = process(["./aslrbp", "./hard_kernel"])



