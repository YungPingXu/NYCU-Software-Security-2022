import requests

url = 'https://pyscript.ctf.zoolab.org/'
file = open("solve.js", "r")
f = {'file': file.read()}
x = requests.post(url, files=f)

print(x.text)