# python3 AMessageBox/solve.py
def de_rol(num):
    s = bin(num)[2:]
    while len(s) < 8:
        s = '0' + s
    s = s[-2:] + s[:5]
    return int(s, 2)

enc_flag = 'B5 E5 8D BD 5C 46 36 4E 4E 1E 0E 26 A4 1E 0E 4E \
46 06 16 AC B4 3E 4E 16 94 3E 94 8C 94 8C 9C 4E \
A4 8C 2E 46 8C 6C'.split(' ')
flag = [chr(de_rol(int(s, 16) ^ 0x87)) for s in enc_flag]
print(''.join(flag))