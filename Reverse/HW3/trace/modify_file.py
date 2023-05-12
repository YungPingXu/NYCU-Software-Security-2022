with open('cs_2022_fall_ouo', 'rb') as f:
    s = f.read()
#print(s)
out = s.replace(b'\xe8\xef\xbe\xad\xde\xcc\xcb\xe8', b'\x90\x90\x90\x90\x90\x90\x90\x90')

with open('cs_2022_fall_ouo_new', 'wb') as f:
    f.write(out)