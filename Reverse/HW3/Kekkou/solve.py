struct_data = '75 1C D7 87 83 40 87 98 8A 39 30 93 A6 E6 21 68 44 6F 89 8D 3E B9\
 63 AF 1F 6B F6 86 31 37 3D 46 59 0C 13 23 DC 16 BD 38 C1 EE B1 FB DF 8D 2C 85 76\
 0A 0A 68 CB D9 A5 44 F5 6B 0E 82 F5 B8 B5 46 E3 69 30 8E 34 D0 83 2F D5 FD 66 CA\
 6B 45 41 70 FE A8 65 D7 4B 32 EA A7 BD D0 56 F0 94 4C DF EE 56 69 DE 61 3C 70 B9\
 D6 F3 D6 F7 B3 0F F0 99 6B 1B B7 B1 B5 15 1B 23 B0 62 59 E3 64 82 2F 29 20 01 F4\
 C7 28 29 4D DE AC 3A D8 30 29 04 23 8C D6 0C 1B 4A 5E 79 F4 E5 72 75 FC EF B1 9F\
 D5 5C B4 19 B4 E9 D4 51 51 C1 16 EF 47 78 FF 68 29 0D E7 27 FB 60 39 4E B4 9F F3\
 86 2E 71 75 C9 C6 27 2D 0B CB E9'
struct_list = struct_data.split(' ')
struct_list = [int(s, 16) for s in struct_list]

enc_flag = '41 92 41 47 EF BC 65 8B F2 6F 75 5F 6D 75 DF 9A 5F B3 8F 61 89 31 61\
 F5 3F 5D 61 69 8F 21 9D 96 A7 61 5C EC 03 5F 70 3C C0 DC 79 56 6E 25 6F 5F BD DD\
 72 FF 73 34 69 B5 6D 58 5F 0C 49 40 72 C8 5D'
flag_list = enc_flag.split(' ')
flag_list = [int(s, 16) for s in flag_list]

head_index = 0
for i in range(0, len(struct_list), 3):
    direction = struct_list[i]
    step = struct_list[i+1]
    value = struct_list[i+2]
    if (direction & 1):
        head_index += step # odd
    else:
        head_index -= step # even
    head_index %= len(flag_list)
    flag_list[head_index] ^= value
print(bytes(flag_list).decode())