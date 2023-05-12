from pwn import *
from Crypto.Util.number import long_to_bytes, inverse

r = remote('edu-ctf.zoolab.org', 10102)
n = int(r.recvline().strip().decode())
e = int(r.recvline().strip().decode())
enc = int(r.recvline().strip().decode())

r.sendline(str(enc).encode())
a = [] # [a_0, a_1, a_2, ...]
a_0 = int(r.recvline().strip().decode())
a.append(a_0) # a_0
m = a[0] * (3 ** 0) # a_0 * 3^0

inv_3 = inverse(3, n) # modular inverse of 3 to n
i = 1
t = 0

while True:
    send_msg = (pow(inv_3, e*i, n) * enc) % n
    r.sendline(str(send_msg).encode())
    recv_msg = int(r.recvline().strip().decode())
    t = (a[i-1] * inv_3 + inv_3 * t) % n
    a.append((recv_msg - t) % 3) # a_i
    m += a[i] * (3 ** i) # a_i * 3^i
    flag = long_to_bytes(m)
    if b'flag' in flag or b'FLAG' in flag:
        print(flag)
        break
    i += 1