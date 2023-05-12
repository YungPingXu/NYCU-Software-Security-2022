# python3 IAT Hook/solve.py
enc_flag = '113E2E291C1E333B312F383D04422A32011C0F0032300016262A'
Wrong = 'Wrong'
flag = [int(enc_flag[i:i+2], 16) ^ ord(Wrong[i//2 % 5]) for i in range(0, len(enc_flag), 2)]
print(bytes(flag).decode())