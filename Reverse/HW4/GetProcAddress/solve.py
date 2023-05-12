# python3 GetProcAddress/solve.py
v8 = '54 68 69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E \
6E 6F 74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F \
53 20 6D 6F 64 65 2E'.split(' ')

enc_flag = '12 00 00 00 00 00 00 00 24 00 00 00 00 00 00 00 28 00 00 00 00 \
00 00 00 34 00 00 00 00 00 00 00 5B 00 00 00 00 00 00 00 3A 00 00 00 00 00 \
00 00 07 00 00 00 00 00 00 00 1C 00 00 00 00 00 00 00 13 00 00 00 00 00 00 \
00 2D 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 32 00 00 00 00 00 00 00 \
43 00 00 00 00 00 00 00 16 00 00 00 00 00 00 00 12 00 00 00 00 00 00 00 1A \
00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 1D 00 \
00 00 00 00 00 00 5A 00 00 00 00 00 00 00 07 00 00 00 00 00 00 00 01 00 00 \
00 00 00 00 00 7F 00 00 00 00 00 00 00 35 00 00 00 00 00 00 00 10 00 00 00 \
00 00 00 00 1A 00 00 00 00 00 00 00 70 00 00 00 00 00 00 00 1B 00 00 00 00 \
00 00 00 01 00 00 00 00 00 00 00 43 00 00 00 00 00 00 00 05 00 00 00 00 00 \
00 00 2B 00 00 00 00 00 00 00 37 00 00 00 00 00 00 00 52 00 00 00 00 00 00 \
00 08 00 00 00 00 00 00 00 1C 00 00 00 00 00 00 00 17 00 00 00 00 00 00 00 \
44 00 00 00 00 00 00 00 53 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
00 00 00 00 00 00 00 00 00 00 00 00 00'.replace('00 00 00 00 00 00 00 ', '')
enc_flag = enc_flag.split(' ')

flag = [chr(int(enc_flag[i], 16) ^ int(v8[i], 16)) for i in range(len(v8))]
print(''.join(flag))