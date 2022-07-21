"""
This work is licensed under the terms of the MIT license.  
For a copy, see <https://opensource.org/licenses/MIT>.

Developed by NISLAB - Network and Information Security Laboratory
at George Emil Palade University of Medicine, Pharmacy, Science and
Technology of Târgu Mureş <https://nislab.umfst.ro/>

Contributors: Teri Lenard
"""

import os
import errno

from binascii import hexlify, unhexlify
from stat import S_IFIFO, S_IRUSR, S_IWUSR


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
    fd = os.open(fifo, os.O_RDONLY)
    return fd, os.fdopen(fd, "r")

def close_pipe(fifo):
    os.close(fifo)


def read_pipe(fifo):
    data = ''
    while True:
        data += fifo.read(1)
        if data.endswith('\n'):
            return data[:-1]


def dump(data, file):
    with open(file, 'w') as f:
        for line in data:
            f.write(str(line))


def write_binary(data, file):

    with open(file, "wb") as f:
        f.write(unhexlify(data))

def load_binary(file):
    data = ''

    with open(file, 'rb') as f:
        data = f.read()

    return hexlify(data).decode()
