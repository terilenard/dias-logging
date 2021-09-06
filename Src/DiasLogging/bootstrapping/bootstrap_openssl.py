#!/usr/bin/env python3

import os

from argparse import ArgumentParser
from argparse import RawTextHelpFormatter
from shutil import copy

from OpenSSL.crypto import TYPE_RSA, TYPE_DSA, PKey, FILETYPE_PEM
from OpenSSL.crypto import dump_publickey, dump_privatekey

"""
Aggregator:
    - one pair of asymetric keys, for generating signatures for received logs (openssl)
    - sequence of public keys, from generators in order to verify signed logs 
    received over network

Generator:
    - one pair of asymetric key to generate log signatures (openssl)
"""

AGGR_PATH = "aggregator/"
GENS_PATH = "generators/"


def _gen_rsa(bits, path, out_pub, out_priv):
    """
    Creates a RSA of bits length and saves it to path.
    """

    pkey = PKey()
    
    print("Generating RSA key of {} length.".format(bits))

    pkey.generate_key(TYPE_RSA, bits)

    _mkdir(path)

    print("Writing to {} private key.".format(path))
    with open(path + out_priv, 'wb') as key_out:
        key_out.write(dump_privatekey(FILETYPE_PEM, pkey))

    print("Writing to {} public key.".format(path))
    with open(path + out_pub, 'wb') as key_out:
        key_out.write(dump_publickey(FILETYPE_PEM, pkey))

    print("Finish key generation.")

def _mkdir(dir_name):
    """
    Create dir_name if dir_name doesn't exist.
    """
    if not os.path.exists(os.path.dirname(dir_name)):
      
        try:
            print("Creating dir {}.".format(dir_name))
            os.makedirs(os.path.dirname(dir_name))
            
            return True
      
        except OSError as exc:
            return False

def _provision_generator():

    
if __name__ == "__main__":
    
    parser = ArgumentParser(description="Bootstraping script for the DIAS Secure Logging Module.\n\n"
                            "Usage:\n\n"
                            "Create two generators keys. Possible on different or the same machine.\n\n"
                            "$ python3 bootstrap_openssl.py --provision_generator --path tree/gen1/"
                            "--bits 1024 --out_pub gen1.pub --out_priv gen1.priv \n\n"
                            "$python3 bootstrap_openssl.py --provision_generator --path tree/gen2/"
                            " --bits 1024 --out_pub gen2.pub --out_priv gen2.priv \n\n"
                            "Provision the aggregator. Possible requires to copy public keys on a machine.\n\n"
                            "$ python3 bootstrap_openssl.py --provision_aggregator --path tree/aggr/"
                            " --bits 1024 --out_pub aggr.pub --out_priv aggr.priv "
                            "--generator_keys tree/gen1/gen1.pub tree/gen2/gen2.pub",
                            formatter_class=RawTextHelpFormatter
                            )
    parser.add_argument("--provision_aggregator", action='store_true', help="Generates a set of RSA asymetric keys for the aggregator."
                        " Requires a sequence of public keys from generators. Saves them on the <path> provided.")
    parser.add_argument("--provision_generator", action='store_true', help="Generates a set of RSA asymetric keys in <path>.")
    parser.add_argument("--generator_keys", type=str, nargs='+', help="Sequence of paths for generators public keys, containing their location.")
    parser.add_argument("--path", type=str, help="Path where to bootstrap credentials.")
    parser.add_argument("--bits", type=int, help="Key length in bits for RSA.")
    parser.add_argument("--out_pub", type=str, help="Output file for the public part of the RSA keys.")
    parser.add_argument("--out_priv", type=str, help="Output file for the private part of the RSA keys.")

    args = parser.parse_args()

    if args.provision_aggregator is None or args.provision_generator is None:
        print("One of the provision arguments must be provided, but not both.")
        exit(-1)

    if args.provision_aggregator and args.provision_generator:
        print("Only one provision argument should be provided, not both")
        exit(-2)

    if args.provision_aggregator:

        if args.path is None or args.bits is None:
            print("Invalid arguments. Please provide <path> or <bits> for aggregator keys.")
            exit(-3)

        # If we are provisioning a aggregator, a sequence of keys is expected
        
        if args.generator_keys is None:
            # No keys provided
            print("Please provided sequence of public keys from generators.")
            exit()

        if args.out_pub is None or args.out_priv is None:
            print("Provide out files for pub and priv.")
            exit(-3)
        # Generate Aggregator Key
        
        _path = args.path if args.path.endswith("/") else args.path + "/"
        
        _mkdir(_path)
        _mkdir(_path + GENS_PATH)

        _path_aggr = _path + AGGR_PATH
        _path_gens = _path + GENS_PATH

        _gen_rsa(args.bits, _path_aggr, args.out_pub, args.out_priv)

        keys = args.generator_keys

        for key in keys:
            print("Copy {} to {}.".format(key, _path_gens))
            copy(key, _path_gens)

        print("Finish provisioning aggregator.")
        exit(0)

    elif args.provision_generator:
        # If generator provisioning is selected
        # a pair of asymetric keys will be generated in <path>
        
        if args.path is None or args.bits is None:
            print("Invalid arguments. Please provide <path> or <bits> for generator keys.")
            exit(-3)

        if args.out_pub is None or args.out_priv is None:
            print("Provide out files for pub and priv.")
            exit(-3)

        _gen_rsa(args.bits, args.path, args.out_pub, args.out_priv)

        print("Finish provisioning generator.")
    else:
        exit(0)
