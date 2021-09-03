
from argparse import ArgumentParser

from tpm2tools.wrapper import TPM2_Provision


"""
Aggregator:
    - one pair of asymetric keys, for generating signatures for received logs (openssl)
    - sequence of public keys, from generators in order to verify signed logs 
    received over network

Generator:
    - one pair of asymetric key to generate log signatures (openssl)
"""
    
if __name__ == "__main__":
    
    parser = ArgumentParser(description="Bootstraping script for the DIAS Secure Logging Module.")
    parser.add_argument("--provision_aggregator", type=bool, help="If set to True ...")
    parser.add_argument("--provision_generator", type=bool, help="Provisions ...")
    parser.add_argument("--provision_path", type=str, help="Path where to bootstrap credentials.")
    parser.add_argument("--out_file", type=str, help="Type of the keys generated. It can only be RSA or DSA")
    
    args = parser.parse_args()

    if args.provision_aggregator is None or args.provision_generator is None:
        print("One of the provision arguments must be provided, but not both.")
        return

    if args.provision_aggregator and args.provision_generator:
        print("Only one provision argument should be provided, not both")
        return


    if args.provision_aggregator:
        success = TPM2_Provision(args.provision_path, args.out_file)
    elif args.provision_generator:
        pass
    else
        return
