# heapmath/solve.py
from pwn import *

context.arch = 'amd64'
#context.terminal = ['tmux', 'splitw', '-h']
#r = process('./chal')
r = remote('edu-ctf.zoolab.org', 10006)

def recv_lines(lines):
    for _ in range(lines):
        print(r.recvline().decode().strip())

# Q1
recv_lines(1)
m = {}
for i in range(7):
    alpha = r.recvline().decode().strip()
    print(alpha)
    alpha = alpha[-4:-2]
    m[chr(ord('A') + i)] = alpha
free_list = []
for _ in range(8):
    free = r.recvline().decode().strip()
    print(free)
    free_list.append(free[-3:-2])
free_list.pop()
print(r.recvuntil(b': ').decode(), end='')
recv_lines(1)
print(r.recvuntil(b': ?\n> ').decode(), end='')
free_list.reverse()
answer1 = ''
for i in free_list:
    value = int(m[i], 16) - 0x8 + 0x10
    if 0x21 <= value <= 0x30:
        answer1 += i + ' --> '
answer1 += 'NULL'
print(answer1)
r.sendline(answer1.encode())
recv_lines(1)

# Q2
print(r.recvuntil(b': ?\n> ').decode(), end='')
answer2 = ''
for i in free_list:
    value = int(m[i], 16) - 0x8 + 0x10
    if 0x31 <= value <= 0x40:
        answer2 += i + ' --> '
answer2 += 'NULL'
print(answer2)
r.sendline(answer2.encode())

# Q3
print(r.recvuntil(b'assert( ').decode(), end='')
alpha1 = r.recv(1).decode()
print(alpha1, end='')
print(r.recvuntil(b' == 0x').decode(), end='')
alpha1_addr = r.recvline().decode()
print(alpha1_addr, end='')
alpha1_addr = alpha1_addr[:-4]
alpha2 = r.recv(1).decode()
print(alpha2, end=' ')
print(r.recvline().decode().strip())
print(r.recvuntil(b'> ').decode(), end='')
alpha = alpha1
answer3 = int(alpha1_addr, 16)
while True:
    chunk_size = int(m[alpha], 16) - 0x8 + 0x10
    if chunk_size % 0x10 != 0:
        chunk_size = ((chunk_size // 0x10) + 1) * 0x10
    answer3 += chunk_size
    alpha = chr(ord(alpha) + 1)
    if alpha == alpha2:
        break
r.sendline(hex(answer3).encode())
print(hex(answer3))

# Q4
recv_lines(3)
print(r.recvuntil(b'malloc(0x').decode(), end='')
X_malloc_size = r.recv(2).decode()
print(X_malloc_size, end='')
recv_lines(2)
print(r.recv(2).decode(), end='')
Y_address = r.recvline().decode()
print(Y_address, end='')
Y_address = Y_address.split('] =')[0]
print(r.recvline().decode().strip())
print(r.recvuntil(b'> ').decode(), end='')
answer4 = str(int(Y_address) + int(X_malloc_size, 16) // 8 + 2)
#gdb.attach(r)
r.sendline(answer4.encode())
print(answer4)

# Q5
recv_lines(5)
print(r.recvuntil(b'assert( Y == 0x').decode(), end='')
Y_address = r.recvline().decode()
print(Y_address)
Y_address = Y_address[:-4]
recv_lines(1)
print(r.recv(2).decode(), end='')
answer5 = hex(int(Y_address, 16) - int(X_malloc_size, 16) - 0x10).encode()
r.sendline(answer5)
print(answer5.decode())

# Q6
recv_lines(5)
print(r.recvuntil(b'(0x').decode(), end='')
X_malloc_size = r.recv(2).decode()
print(X_malloc_size, end='')
recv_lines(5)
print(r.recvuntil(b'assert( Y == 0x').decode(), end='')
Y_address = r.recvline().decode()
print(Y_address)
Y_address = Y_address[:-4]
recv_lines(1)
print(r.recvuntil(b'> ').decode(), end='')
answer6 = hex(int(Y_address, 16) - int(X_malloc_size, 16) - 0x20).encode()
r.sendline(answer6)
print(answer6.decode())
recv_lines(2)