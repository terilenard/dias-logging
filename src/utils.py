import os
import errno

from binascii import hexlify
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
    return os.open(fifo, os.O_RDONLY)


def close_pipe(fifo):
    os.close(fifo)


def read_pipe(path, bufferSize=100, timeout=0.100):
    import time
    grace = True
    content = None
    try:
        pipe = os.open(path, os.O_RDONLY | os.O_NONBLOCK)

        while True:
            try:
                buf = os.read(pipe, bufferSize)
                if not buf:
                    break
                else:
                    content = buf.decode("utf-8")
                    return content
            except OSError as e:
                if e.errno == 11 and grace:
                    time.sleep(timeout)
                    grace = False
                else:
                    break

    except OSError as e:
        if e.errno == errno.ENOENT:
            pipe = None
        else:
            raise e
    finally:
        os.close(pipe)

    return content


def dump(data, file):
    with open(file, 'w') as f:
        for line in data:
            f.write(str(line))


def load_binary(file):
    data = ''

    with open(file, 'rb') as f:
        data = f.read()

    return hexlify(data).decode()
