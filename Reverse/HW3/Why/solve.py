enc_flag = '50 56 4B 51 85 73 78 73 7E 69 70 73 78 73 69 77 7A 7C 79 7E 6F 6D 7E 2B 87'

flag_list = enc_flag.split(' ')
flag_list = [int(s, 16) - 10 for s in flag_list]
print(bytes(flag_list).decode())