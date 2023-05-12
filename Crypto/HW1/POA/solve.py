from pwn import *

r = remote('edu-ctf.zoolab.org', 10101)
ct = bytes.fromhex(r.readline()[:-1].decode())
print(ct)
pt = b''
for block in range(1, 16):
    block_pt = b''
    block_ct = ct[block*16: (block+1)*16]
    last_ct = ct[(block-1)*16: block*16]
    for idx in range(15, -1, -1):
        postfix = bytes([i ^ j for i, j in zip(block_pt, last_ct[idx+1:])])
        prefix = last_ct[:idx]
        for i in range(128, 256):
            now = prefix + bytes([i ^ last_ct[idx]]) + postfix + block_ct
            r.sendline(now.hex().encode('ascii'))
            res = r.readline()
            if res == b'Well received :)\n':
                block_pt = bytes([i ^ 0x80]) + block_pt
                break
        else:
            block_pt = bytes([0x80]) + block_pt
    pt += block_pt
    print(pt)

r.close()