import os
import errno

from binascii import hexlify
from stat import S_IFIFO, S_IRUSR, S_IWUSR

from DiasLogging.logging.handlers import FIFO_FILE

def exists(dir):
    """
    Verifies if directory exists.
    """
    return os.path.exists(dir)

def make_pipe(fifo):
    # Set up communication structures

    if exists(fifo):
        return True
    
    try:
        os.mkfifo(fifo, S_IFIFO | S_IRUSR | S_IWUSR)
        return True
    except OSError as ex:
        if (ex.errno != errno.EEXIST):
            print("Unable to create fifo file\n")
            print(str(ex))
            return False

def open_pipe(fifo):
    return os.open(fifo, os.O_RDONLY)

def close_pipe(fifo):
    os.close(fifo)

def read_pipe(fifo):
    print("Opening FIFO...")
    with open(fifo) as _fifo:
        print("FIFO opened")
        while True:
            data = _fifo.read()
            if len(data) == 0:
                print("Writer closed")
                break
            print('Read: "{0}"'.format(data))
            return data

def dump(data, file):

    with open(file, 'w', encoding="utf-8") as f:
        for line in data:
            f.write(str(line))

def load_binary(file):
    data = ''

    with open(file, 'rb') as f:
        data = f.read()
    
    return hexlify(data).decode()