# RopEmporium_wp
Writeup For https://ropemporium.com  

一些基本的ROP技巧，主要考察Rop Chain的构造和利用
## ret2win
直接Ret to ret2win function ，执行system("cat flag.txt")即可
## split
通过system()函数，构造参数传递给system函数，执行system("/bin/sh")等
## callme
根据题目要求以此调用callme1,callme2,callme3并正确传递参数即可
## write4
首先泄露STDIN的文件指针地址，并将其传参给fgtes从而将"/bin/sh"写入bss段中，调用system执行即可
## badchars
题目中进行了部分敏感字符的过滤
将字符进行xor加密的结果写入bss段中，传参之前在利用题目中给出的ROPgadgets进行XOR解密，避免敏感字符即可
## fluff
题目的用意是利用Biniary中的ROPgadgets将字符串写入到bss中，巧妙利用题目中给出的mov [reg1],reg2类型的Ropgadgets将
“/bin/sh”写入到bss中，之后过程同上
## pivot
考察劫持栈指针Stack pivot技巧
根据题目的要求，泄露libcpivot的地址，并通过mov esp,reg的ROPgodgtes将sp指针劫持到可控区域，最后通过libcpivot的偏移计算
调用ret2win函数实现漏洞利用
