"""
This work is licensed under the terms of the MIT license.  
For a copy, see <https://opensource.org/licenses/MIT>.

Developed by NISLAB - Network and Information Security Laboratory
at George Emil Palade University of Medicine, Pharmacy, Science and
Technology of Târgu Mureş <https://nislab.umfst.ro/>

Contributors: Teri Lenard
"""

import json
from hashlib import sha1

from log import logger
from utils import *
from wrapper import TPM2_LoadExternalPubKey, TPM2_Verify, TPM2_Hash, \
    TPM2_ExtendPcr, TPM2_ReadPcr, TPM2_CreatePrimary, TPM2_DICTIONARY_LOCKOUT, \
    TPM2_ResetPCR, TPM2_ExtendPcr, TPM2_ReadPcr


class TPMCore:

    def __init__(self, config):

        self._primary_ctx = config["tpm2_primary_ctx"]
        self._prov_path = config["tpm2_provision_path"]
        self._key_pub = config["public_key"]
        self._key_ctx = config["public_key_ctx"]
        self._tmp_file = config["tmp_file"]
        self._digest_file = config["tmp_digest_file"]
        self._pcr = config["pcr"]
        self._sign_file = config["sign_file"]

    def initialise(self):

        success = TPM2_DICTIONARY_LOCKOUT()

        if success:
            logger.info("Removed dictionary lockout.")
        else:
            logger.error("Could not execute dictionary lockout")

        success = TPM2_CreatePrimary(self._prov_path, self._primary_ctx)

        if success:
            logger.debug("Recreated primary.ctx in " + self._prov_path)

            if success:
                logger.debug("Finished recreating primary.ctx.")
            else:
                logger.error("Could not recreate primary.ctx.")
                return False

        success = TPM2_LoadExternalPubKey(self._key_pub, self._key_ctx)

        return success

    def verify(self, obj):

        dump(obj.message, self._tmp_file)

        digest = TPM2_Hash(self._tmp_file, self._digest_file)

        if not digest:
            logger.error("Could not hash message.")
            return False

        write_binary(obj.signature, self._sign_file)

        success = TPM2_Verify(self._key_ctx,
                            self._digest_file, self._sign_file)

        if not success:
            print("Couldn't not verify signature {}".format(str(obj.message)))
            return False

        return success
