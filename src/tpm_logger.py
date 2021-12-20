import asyncio
import json
from logging import log
import signal
import sys

from hashlib import sha1

sys.path.append("/home/pi/workspace/dias-logging/Src")
sys.path.append("/home/pi/workspace/dias-logging/Src/DiasLogging/communication_protocols/dias_communication")

from DiasLogging.logging.logger import Logger as ParentLogger
from DiasLogging.logging.handlers import *
from DiasLogging.logging.utils import *
from DiasLogging.tpm2tools.wrapper import TPM2_FlushContext, TPM2_LoadKey, TPM2_Sign, TPM2_Hash, TPM2_ExtendPcr

from comm_core.communicator import Communicator
from comm_core.logging_pb2 import LogMessage

"""
Dependencies
    pip3 install pyzmq
    pip3 install protobuf
    pip3 install blist
"""

class TPMLogger(ParentLogger):

    MAX_MSGS = 3
    PCR = 4
    _REQUEST_ADDRESS = "tcp://127.0.0.1:11002"
    _MODULE_NAME = "TPMLogger"
    _REQUESTOR_NAME = "DummyRequestor"
    _REQUESTOR_ADDRESS = "tcp://127.0.0.1:11004"

    def __init__(self, filename):
        super().__init__(filename)
        self._key_loaded = False
        self._communicator = None
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

    async def _sign(self, logs):

        self.info("Started singing")
        json_log = dict()

        for log in logs:
            json_log[self._hash(log)] = log

        dump(logs, TMP_FILE)
        digest = TPM2_Hash(TMP_FILE, TMP_DIGEST_FILE)

        if not digest:
            self.error("Couldn't hash: {}.".format(str(logs)))
            return

        self.info("Extending pcr with:" + TMP_DIGEST_FILE)

        success = TPM2_ExtendPcr(TPMLogger.PCR, TMP_DIGEST_FILE)
        if not success:
            self.error("Couldn't extend PCR {} with {}".format(TPMLogger.PCR, TMP_DIGEST_FILE))
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

    def start(self):

        if not self._check_provision():
            self.error("Provision error.")
            return False

        self._key_loaded = TPM2_LoadKey(TPM2_PRIMARY_HNDLR, TPM2_PUB_RSA, 
            TPM2_PRIV_RSA, TPM2_PRIV_CTX)

        if not self._key_loaded:
            self.error("Couldn't load keys into the TPM.")
            return False

        if not make_pipe(FIFO_FILE):
            self._info_log.error("Couldn't create fifo.")
            return False

        if self._loop is None:
            self._loop = asyncio.get_event_loop()

        self.debug("Starting Communicator on {}".format(TPMLogger._REQUEST_ADDRESS))
        self._communicator = Communicator(
            TPMLogger._REQUEST_ADDRESS,
            self._on_request,
            None, # pub address
            [(TPMLogger._REQUESTOR_NAME, TPMLogger._REQUEST_ADDRESS)],
            [])
        self.debug("Communicator started.")

        self.debug("Starting the loop")
        self._loop.run_forever()

    def stop(self):

        if self._communicator:
            self._communicator.stop()

        if self._loop.is_running:
            self.debug("Stopping the loop...")
            self._loop.close()
            self.debug("Loop stopped.")

        if self._key_loaded:
            self.debug("Removing handlers from TPM. This can break something.")
            TPM2_FlushContext()
            self.debug("Handlers removed from TPM.")

    def _on_request(self, request):
        
        log_request = LogMessage()
        log_request.ParseFromString(request.data)

        if (log_request):
            request.reply("ok".encode())

        self._queue.append(log_request.message)
        self.info("Added in queue. New size: {}".format(len(self._queue)))

        if len(self._queue) == TPMLogger.MAX_MSGS:
            logs = [self._queue.pop(0) for i in range(TPMLogger.MAX_MSGS)]
            asyncio.run_coroutine_threadsafe(self._sign(logs), self._loop)
            return
  

def signal_handler(signum, frame):
    tpm_logger.stop()


if __name__ == "__main__":

    signal.signal(signal.SIGQUIT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    global tpm_logger
    tpm_logger = TPMLogger("tpmlogger.log")
    tpm_logger.start()
