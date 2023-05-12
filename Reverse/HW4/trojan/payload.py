# python3 trojan/payload.py
with open('payload.txt', 'r') as f:
    s = f.read()

payload = b''
for i in range(0, len(s), 2):
    payload += bytes.fromhex(s[i:i+2])

with open('out', 'wb') as f:
    f.write(payload)