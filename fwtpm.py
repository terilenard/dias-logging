# This is the implementation of the interface for the communication between the fw and the TPM.
# It also includes the code for the provisioning of the TPM, in case it is needed.
import os
import errno
from stat import *
import logging
from logging.handlers import RotatingFileHandler

from tpm2tools import TPM2_CreateHMACKey, TPM2_LoadKey, TPM2_ComputeHMAC

TPM2T_HMACKEYPUB_FILE = "hmacpub.ctx"
TPM2T_HMACKEYSENS_FILE = "hmacsens.ctx"
TPM2T_HMACKEYLOADED_FILE = "hmacloaded.ctx"
FWFIFO_FILE = "/home/pi/DIAS/FirewallBackend/UnitTesting/fwtpm_pipe"

class FirewallTPM(object):
    '''
    A class that implements the basic features for the communication between the Firewall component, and the TPM.
    '''

    def __init__(self, key_ctx):
        '''
        Constructor. It requires the primary key context file (this means that it considers that the primary key has already been provisioned).
        '''

        self._h_primaryk = key_ctx
        self._f_base = None # The base folder

        # Define handlers for the MAC key used for integrity protection of FW messages
        self._h_mack =  None
        self._h_pubk = None
        self._h_sensk = None

        # Define handler for the communication with the PIPE
        self._h_fwpipe = None


    def _prepare_key_handlers(self, folderName):
        '''
        Prepare the basic key handlers.
        '''
        # Save the base folder
        self._f_base = folderName

        # Prepare the file handlers
        self._h_pubk = self._f_base + "/" + TPM2T_HMACKEYPUB_FILE
        self._h_sensk = self._f_base + "/" + TPM2T_HMACKEYSENS_FILE
        self._h_mack = self._f_base + "/" + TPM2T_HMACKEYLOADED_FILE


    def provision_firewall(self, folderName):
        '''
        The main FW TPM provisioning method.
        '''

        # Set up the basic key handlers
        self._prepare_key_handlers(folderName)

        # Generate the new key (overwrites exiting instances, if they exist).
        if (TPM2_CreateHMACKey(self._h_primaryk, self._h_pubk, self._h_sensk) == False):
            return False

        # Load the generated key
        if (TPM2_LoadKey(self._h_primaryk, self._h_pubk, self._h_sensk, self._h_mack) == False):
            return False

        return True


    def start_firewall(self, folderName):
        '''
        Method that is called after the provisioning of the firewall. The method also loads the appropriate keys.
        '''

        if (self._h_mack == None):
            # Set up the basic key handlers
            self._prepare_key_handlers(folderName)

            # Load the key
            if (TPM2_LoadKey(self._h_primaryk, self._h_pubk, self._h_sensk) == False):
                return False

        # Set up communication structures
        try:
            os.mkfifo(FWFIFO_FILE, S_IFIFO | S_IRUSR | S_IWUSR)
        except Exception as ex:
            if (ex.errno != errno.EEXIST):
                print("Unable to create fifo file\n")
                print(str(ex))
                return False

        # Now open the communication, should not fail
        self._h_fwpipe = os.open(FWFIFO_FILE, os.O_RDWR)

        # Prepare data logging handlers
        formatter = logging.Formatter('%(asctime)s - %(levelname)-8s %(message)s')

        file_handler = None

        try:
            file_handler = RotatingFileHandler("pytpm.log", maxBytes=1000000, backupCount=2)
            file_handler.setFormatter(formatter)
        except Exception as ex:
            print("Unable to set up logger\n")
            print(str(ex))

        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)
        logger.addHandler(file_handler)

        logger.info('*********************')
        logger.info('FW-TPM version: 0.1')
        logger.info('*********************')

        return True


    def stop_firewall(self):
        '''
        The method stops the firewall.
        '''

        if (self._h_fwpipe == None):
            return

        os.close(self._h_fwpipe)


    def sign_message(self, message):
        '''
        The method signs the given message
        '''

        if (self._h_mack == None):
            return False

        return TPM2_ComputeHMAC(self._h_mack, message)


    def receive_and_sign_message(self):
        '''
        This is a blocking method that reads an incoming message, and signs it, returning the signature to the caller.
        '''

        if (self._h_fwpipe == None):
            return None

        msg = ''
        while True:
            try:
                ch = os.read(self._h_fwpipe, 1)
            except Exception:
                print("** Caught an exception, probably need to exit\n")
                return None

            chs = str(ch, 'utf-8')

            if (ord(chs) == 0):
                break

            msg += chs

        logging.info("*** Received message from FW: " + msg)

        return (msg,self.sign_message(msg))


    def receive_sign_log_message(self):
        '''
        This is a blocking method that receives, signs, and logs a given message.
        '''

        # Read the message and sign it
        mpair = self.receive_and_sign_message()
        if (mpair == None):
            return False

        # Unpack the two components
        (msg, msign) = mpair

        # Log to file
        logging.critical("Message: " + msg)
        logging.critical("--->>> signature: " + msign)

        return True
