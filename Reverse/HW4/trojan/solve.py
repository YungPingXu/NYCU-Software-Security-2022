# python3 trojan/solve.py
with open('payload.txt', 'r') as f:
    s = f.read()

payload = b''
for i in range(0, len(s), 2):
    payload += bytes.fromhex(s[i:i+2])

v4 = '0vCh8RrvqkrbxN9Q7Ydx\0'
out = b''
for i in range(len(payload)):
    j = payload[i] ^ ord(v4[i % 0x15])
    out += j.to_bytes(1, 'little')

with open('output', 'wb') as f:
    f.write(out)