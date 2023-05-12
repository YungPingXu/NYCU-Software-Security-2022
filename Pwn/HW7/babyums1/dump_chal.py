# babyums1/dump_chal.py
import base64

with open('chal_base64.txt', 'r') as f:
    s = f.read()
with open('chal_remote', 'wb') as f:
    f.write(base64.b64decode(s))