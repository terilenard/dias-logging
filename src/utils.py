import os

from binascii import hexlify


def exists(dir):
    """
    Verifies if directory exists.
    """
    return os.path.exists(dir)


def dump(data, file):

    with open(file, 'w', encoding="utf-8") as f:
        for line in data:
            f.write(str(line))

def load_binary(file):
    data = ''

    with open(file, 'rb') as f:
        data = f.read()
    
    return hexlify(data).decode()
