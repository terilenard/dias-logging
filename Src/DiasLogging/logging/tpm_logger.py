import asyncio
import json
from queue import Queue
from hashlib import sha1

from DiasLogging.logging.logger import Logger as ParentLogger
from DiasLogging.logging.handlers import *
from DiasLogging.logging.utils import *
from DiasLogging.tpm2tools.wrapper import TPM2_FlushContext, TPM2_LoadKey, TPM2_Sign, TPM2_Hash



class TPMLogger(ParentLogger):


    def __init__(self, filename):
        super().__init__(filename)
        self._key_loaded = False
        self._pipe = None
        self._queue = list()
        self._loop = asyncio.get_event_loop()
        
    def _check_provision(self):
        """
        Verifies that the provision step was done correctly,
        and the keys/handlers exists in expected directories.
        """
        return exists(TPM2_PRIMARY_CTX) and exists(TPM2_PRIV_RSA) and exists(TPM2_PUB_RSA)

    def _hash(self, msg):
        return sha1(msg.encode()).hexdigest()

    async def _listen_on_pipe(self):
        
        msg = read_pipe(FIFO_FILE)
        self._queue.append(msg)
        self.info("Added in queue. New size: {}".format(len(self._queue)))

        if len(self._queue) == 1:
            logs = [self._queue.pop(0) for i in range(1)]
            asyncio.run_coroutine_threadsafe(self._sign(logs), self._loop)
            return
        
        asyncio.run_coroutine_threadsafe(self._listen_on_pipe(), self._loop)

    async def _sign(self, logs):

        self.info("Started singing")
        json_log = dict()

        for log in logs:
            json_log[self._hash(log)] = log
        
        dump(logs, TMP_FILE)
        self.info("Before dump" + str(logs))
        success = TPM2_Hash(TMP_FILE, TMP_DIGEST_FILE)
        self.info("after")
        if not success:
            self.error("Couldn't hash: {}.".format(str(logs)))
            return

        if not self._key_loaded:
            self.error("Keys not loaded.")
            return

        success = TPM2_Sign(TPM2_PRIV_CTX, TMP_DIGEST_FILE, TMP_OUTPUT)

        if not success:
            self.error("Couldn't sign {}".format(str(logs)))
            return

        signature = load_binary(TMP_OUTPUT)
        self.info("Signature: {}".format(signature))
        json_log["signature"] = signature
        self.info(json.dumps(json_log))
        self.info("Finished signing")

        asyncio.run_coroutine_threadsafe(self._listen_on_pipe(), self._loop)

    def start(self):
        
        if not self._check_provision():
            # self.error("Provision error.")
            return False

        self._key_loaded = TPM2_LoadKey(TPM2_PRIMARY_HNDLR, TPM2_PUB_RSA, 
            TPM2_PRIV_RSA, TPM2_PRIV_CTX)

        if not self._key_loaded:
            # self._info_log.error("Couldn't load keys into the TPM.")
            return False

        if not make_pipe(FIFO_FILE):
            # self._info_log.error("Couldn't create fifo.")
            return False

        if self._loop is None:
            self._loop = asyncio.get_event_loop()

        # Register async coroutines

        # self._info_log.info("Registering task....")
        self._loop.create_task(self._listen_on_pipe())
        
        # self._info_log.info("Running the loop...")
        self._loop.run_forever()
        
    def stop(self):
        
        if self._loop.is_running:
            # self._info_log.info("Stopping the loop...")
            self._loop.close()
            # self._info_log.info("Loop stopped.")

        if self._key_loaded:
            # self._info_log.info("Removing handlers from TPM.")
            TPM2_FlushContext()
            # self._info_log.info("Handlers removed from TPM.")

        if self._pipe:
            # self._info_log.info("Closing the pipe.")    
            close_pipe(self._pipe)


if __name__ == "__main__":

    tpm_logger = TPMLogger("tpmlogger.log")
    tpm_logger.start()
