#!/usr/bin/python3

# Version number
__version__ = "0.1"

# System imports
from datetime import datetime
import signal, os

# Our own imports
#from  import TPM2_Provision, TPM2_CreateAsymKey, TPM2_LoadExternalPubKey, TPM2_EvictControl

#from mastertpm import MTPM_Provision, MTPM_LoadExternalKey, MTPM_CreateSymKey
from mastertpm import MasterTPM
from fwtpm import FirewallTPM

g_fw = None

def log_msg(msg):
    s = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    s += " - " + msg
    print(s)


def sig_handler(signum, frame):
    log_msg("Received a signal, exiting...")
    g_fw.stop_firewall()


if __name__ == '__main__':
    log_msg("This is the Python TPM software, version: " + __version__ )

    master = MasterTPM()

    master.provision_master('METPMCTX')

    #extk_idx = master.load_external_key("./public.pem")
    #if (extk_idx > 0):
    #    print("Successfully loded external key, received idx: " + str(extk_idx))

    #extk = master.generate_ext_sym_key(extk_idx, 32)
    #if (extk is not None):
    #    (encf, signf) = extk
    #    print("Successfully generated symmetric key, result stored in: " + encf + ", " + signf)

    #kidx = master.generate_sealed_sym_key(32)
    #if (kidx > 0):
    #    print("Successfully generated symmetric key, result idx: " + str(kidx))

    #res = master.export_sealed_sym_key(extk_idx, kidx)
    #if (res is not None):
    #    (encf, signf) = res
    #    print("Successfully exported symmetric key, result stored in: " + encf + ", " + signf)


    # Setup exit signal
    signal.signal(signal.SIGINT, sig_handler)

    g_fw = FirewallTPM('METPMCTX/primary.ctx')
    g_fw.provision_firewall('METPMCTX')
    g_fw.start_firewall('METPMCTX')
    print("Result: " + g_fw.sign_message('alabalaportocala'))

    while (True):
        if (g_fw.receive_sign_log_message() == False):
            break

    print("PyTPM software gracefully stopped!\n")

    #print("Result of receive and sign: " + fw.receive_and_sign_message())

    #TPM2_Provision('METPMCTX')
    #TPM2_EvictControl('METPMCTX/primary.ctx', 'METPMCTX/hpersist.ctx')

    #TPM2_CreateAsymKey('METPMCTX/ASYMKEYCTX', 'METPMCTX')
    #TPM2_LoadExternalPubKey("./public.pem", "METPMCTX/EXTPUBK", "rsa")

