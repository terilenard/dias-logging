"""
This work is licensed under the terms of the MIT license.  
For a copy, see <https://opensource.org/licenses/MIT>.

Developed by NISLAB - Network and Information Security Laboratory
at George Emil Palade University of Medicine, Pharmacy, Science and
Technology of Târgu Mureş <https://nislab.umfst.ro/>

Contributors: Teri Lenard
"""

import sys

sys.path.append("../")

from argparse import ArgumentParser

from wrapper import TPM2_Provision, TPM2_CreateAsymKey


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
    parser.add_argument("--provision_aggregator", action='store_true', help="Generates a set of RSA asymetric keys for the aggregator."
                        " Requires a sequence of public keys from generators. Saves them on the <path> provided.")
    parser.add_argument("--provision_generator", action='store_true', help="Generates a set of RSA asymetric keys in <path>.")
    parser.add_argument("--generator_keys", type=str, nargs='+', help="Sequence of paths for generators public keys, containing their location.")
    parser.add_argument("--path", type=str, help="Path where to bootstrap credentials.")
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
        pass
    elif args.provision_generator:
        
        if args.path is None:
            print("Invalid arguments. Please provide <path> or <bits> for generator keys.")
            exit(-3)

        if args.out_pub is None or args.out_priv is None:
            print("Provide out files for pub and priv.")
            exit(-3)

        
        success =  TPM2_Provision(args.path, "primary.ctx")

        if success:
            print("Created primary.ctx in " + args.path)

            success = TPM2_CreateAsymKey(
                args.path + "/primary.ctx",
                args.path + "/children",
                args.out_pub,
                args.out_priv
                )

            if success:
                print("Created asymetric keys in " + args.path + "/children")
                exit(0)
            else:
                print("Error creating asymetric keys.")
                exit(-1)
        else:
            print("Error creating primary.ctx")
            exit(-1)
