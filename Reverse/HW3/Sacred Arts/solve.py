# ex: '8D909984B8BEBAB3' to b'\xb3\xba\xbe\xb8\x84\x99\x90\x8d'
def hexstr_to_little_endian(s):
    lst = bytearray.fromhex(s)
    lst.reverse()
    return bytes(lst)

def twos_complement(n):
    return (n ^ ((1 << 64) - 1)) + 1

enc_flag = [
    '8D909984B8BEBAB3',
    '8D9A929E98D18B92',
    'D0888BD19290D29C',
    '8C9DC08F978FBDD1',
    'D9C7C7CCCDCB92C2',
    'C8CFC7CEC2BE8D91',
    'FFFFFFFFFFFFCF82'
]
enc_list = [hexstr_to_little_endian(s) for s in enc_flag]
flag = ''
for s in enc_list:
    AL_AH = s[0:2]
    s = AL_AH[::-1] + s[2:] # xchg al, ah
    s = twos_complement(int.from_bytes(s, 'little')) # nag rax
    flag += int.to_bytes(s, 8, 'little').decode()
print(flag)