enc_flag = '37 3D 30 36 0A 25 03 30 12 42 2E 3C 42 2E 40 37 2E 24 2E 12 30 3F 0C'
enc_flag = enc_flag.split(' ')
enc_flag = [int(s, 16) for s in enc_flag]

flag = ''
for i in enc_flag:
    flag += chr(i ^ 0x71)
print(flag)