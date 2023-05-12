# Exception/solve.py
enc_flag = 'E7 E3 72 78 AC 90 90 7C 90 AC B1 A6 A4 9E A7 A2 AC 90 \
B9 B2 BF BB BD B6 AB 90 BA B4 90 BF C0 C0 C4 CA 95 ED C0 B2 00'
flag = bytearray.fromhex(enc_flag)
for i in range(39):
    flag[i] = ((flag[i] - (i + 0xef)) % 256) ^ ((i + 0xbe) % 256)
print(bytes(flag).decode())