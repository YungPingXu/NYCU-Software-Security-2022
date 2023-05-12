with open("hw0/share/chal", "rb") as f:
    s = f.read()
print(s.find(b"flag")) # this is the offset for the flag

# 1. nc edu-ctf.zoolab.org 10001
# 2. 1
# 3. /home/chal/chal
# 4. 5
# 5. input the offset we find
# 6. 3