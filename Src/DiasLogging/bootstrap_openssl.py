#!/usr/bin/env python3

import os
import errno

from argparse import ArgumentParser

from OpenSSL.crypto import TYPE_RSA, TYPE_DSA, PKey, FILETYPE_PEM
from OpenSSL.crypto import dump_publickey, dump_privatekey


PRIV_NAME = "dias-logger.priv"
PUB_NAME = "dias-logger.pub"

def bootstrap_openssl(key_type, bits, path):
    
    pkey = PKey()
    if key_type == "RSA":
        pkey.generate_key(TYPE_RSA, bits)
    elif key_type == "DSA":
        pkey.generate_key(TYPE_DSA, bits)
    else:
        raise ValueError("Wrong value for key_type. It can be only: RSA or DSA")
    
    _path = path if path.endswith("/") else path + "/"

    with open(_path + PRIV_NAME, 'wb') as key_out:
        key_out.write(dump_privatekey(FILETYPE_PEM, pkey))

    with open(_path + PUB_NAME, 'wb') as key_out:
        key_out.write(dump_publickey(FILETYPE_PEM, pkey))


if __name__ == "__main__":
    
    parser = ArgumentParser(description="Bootstraping script for the DIAS Secure Logging Module.")
    parser.add_argument("--path", type=str, help="Path where to bootstrap credentials.")
    parser.add_argument("--key_type", type=str, help="Type of the keys generated. It can only be RSA or DSA")
    parser.add_argument("--bits", type=int, help="Key length in bits.")

    args = parser.parse_args()

    if args.path is None or args.key_type is None or args.bits is None:
        print("Invalid arguments")
        return

    if not os.path.exists(os.path.dirname(args.path)):
        try:
            os.makedirs(os.path.dirname(args.path))
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise

    bootstrap_openssl(args.key_type, args.bits, args.path)
