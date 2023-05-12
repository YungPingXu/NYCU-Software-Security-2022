key = 'DE AD BE BF'
key = [i for i in bytearray.fromhex(key)]
# function list: xor 87, not, xor 63
# after TLS callback function 2, function list: not, xor 63, xor 87
# after TLS callback function 1
key[0] = ~key[0]
key[1] ^= 0x63
key[2] ^= 0x87
key[3] = ~key[3]
key = [i % 256 for i in key]
# after TLS callback function 2, function list: xor 63, xor 87, not
enc_flag = '46 99 F7 64 1D 79 44 22 C1 D3 27 CD 31 C1 D9 77 EC 7A 75 \
24 BF DD 24 DD 23 B2 CD 7C 02 58 46 24 AC D8 21 D1 5D BC C5 7C 05 6C \
48 2B BB D5 11 CB 35 B6 D9 57 0F 60 3F 34 FF EC'
flag = [i for i in bytearray.fromhex(enc_flag)]
for i in range(len(flag)):
    if i % 3 == 0:
        flag[i] = (flag[i] - key[i % 4]) ^ 0x63
    elif i % 3 == 1:
        flag[i] = (flag[i] - key[i % 4]) ^ 0x87
    elif i % 3 == 2:
        flag[i] = ~(flag[i] - key[i % 4])
flag = [i % 256 for i in flag]
print(bytes(flag).decode())