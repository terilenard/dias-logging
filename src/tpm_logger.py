import asyncio
import json
import signal
import sys
import logging

from configparser import ConfigParser
from argparse import ArgumentParser

from hashlib import sha1

sys.path.append("/home/teri/Workspace/dias-logging/src")
sys.path.append("/home/teri/Workspace/dias-hackathon-testbed1/modules/communication_protocol/python/")

from utils import *
from wrapper import TPM2_FlushContext, TPM2_LoadKey, TPM2_Sign, TPM2_Hash, TPM2_ExtendPcr

#from comm_core.communicator import Communicator
#from comm_core.proto.logging_pb2 import LogMessage

"""
Dependencies
    pip3 install pyzmq
    pip3 install protobuf
    pip3 install blist
"""

def setup_logger(name, log_file, level=logging.DEBUG):
    """To setup as many loggers as you want"""
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')

    handler = logging.FileHandler(log_file)
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)

    return logger


class TPMLogger():

    MAX_MSGS = 1
    PCR = 4
    _REQUEST_ADDRESS = "tcp://127.0.0.1:11002"
    _MODULE_NAME = "TPMLogger"
    _REQUESTOR_NAME = "DummyRequestor"
    _REQUESTOR_ADDRESS = "tcp://127.0.0.1:11004"

    def __init__(self, config):

        self._sec_logger = setup_logger("TPMLogger", config["log"]["tpm_log"])
        self._app_logger = setup_logger("ServiceTPMLogger", config["log"]["info_log"])

        self._tpm_conf = dict(config["tpm"])
#        self._zmq_conf = dict(config["zmq"])
        self._key_loaded = False
        # self._communicator = None

        self._pipe = config["log"]["fifo"]
        self._pipe_fd = None
        self._queue = list()
        self._loop = asyncio.get_event_loop()

    def _check_provision(self):
        """
        Verifies that the provision step was done correctly,
        and the keys/handlers exists in expected directories.
        """
        return exists(self._tpm_conf["tpm2_primary_ctx"]) \
                and exists(self._tpm_conf["tpm2_priv_rsa"]) \
                and exists(self._tpm_conf["tpm2_pub_rsa"])

    def _hash(self, msg):
        return sha1(msg.encode()).hexdigest()

    async def _listen_on_pipe(self):

        msg = read_pipe(self._pipe)
        self._queue.append(msg)
        self._app_logger.info("Added in queue. New size: {}".format(len(self._queue)))

        if len(self._queue) == 1:
            logs = [self._queue.pop(0) for i in range(1)]
            asyncio.run_coroutine_threadsafe(self._sign(logs), self._loop)
            return

        asyncio.run_coroutine_threadsafe(self._listen_on_pipe(), self._loop)

    async def _sign(self, logs):

        self._app_logger.info("Started singing")
        json_log = dict()

        for log in logs:
            json_log[self._hash(log)] = log

        dump(logs, self._tpm_conf["tmp_file"])
        digest = TPM2_Hash(self._tpm_conf["tmp_file"],
                           self._tpm_conf["tmp_digest_file"])

        if not digest:
            self._app_logger.error("Couldn't hash: {}.".format(str(logs)))
            return

        self._app_logger.info("Extending pcr with:" + self._tpm_conf["tmp_digest_file"])

        success = TPM2_ExtendPcr(self._tpm_conf["pcr"],
                                 self._tpm_conf["tmp_digest_file"])
        if not success:
            self._app_logger.error("Couldn't extend PCR {} with {}".format(
                        self._tpm_conf["pcr"],
                        self._tpm_conf["tmp_digest_file"]))
            return

        if not self._key_loaded:
            self._app_logger.error("Keys not loaded.")
            return

        success = TPM2_Sign(self._tpm_conf["tpm2_priv_ctx"],
                            self._tpm_conf["tmp_digest_file"],
                            self._tpm_conf["tmp_output"])

        if not success:
            self._app_logger.error("Couldn't sign {}".format(str(logs)))
            return

        signature = load_binary(self._tpm_conf["tmp_output"])
       # self.sec_logger.info(signature)

        json_log["signature"] = signature
        self._sec_logger.info(json.dumps(json_log))
        self._app_logger.info("Finished signing")

        asyncio.run_coroutine_threadsafe(self._listen_on_pipe(), self._loop)

    def start(self):

        if not make_pipe(self._pipe):
            # self._info_log.error("Couldn't create fifo.")
            return False

        if not self._check_provision():
            self._app_logger.error("Provision error.")
            return False

        self._key_loaded = TPM2_LoadKey(self._tpm_conf["tpm2_primary_ctx"],
                                        self._tpm_conf["tpm2_pub_rsa"],
                                        self._tpm_conf["tpm2_priv_rsa"],
                                        self._tpm_conf["tpm2_priv_ctx"])

        if not self._key_loaded:
            self._app_logger.error("Couldn't load keys into the TPM.")
            return False

        if self._loop is None:
            self._loop = asyncio.get_event_loop()

        self._loop.create_task(self._listen_on_pipe())

       # self._app_logger.debug("Starting Communicator on {}".format(self._zmq_conf["request_address"]))

        # self._communicator = Communicator(
        #     self._zmq_conf["request_address"],
        #     self._on_request,
        #     None, # pub address
        #     [(self._zmq_conf["requestor_name"], self._zmq_conf["request_address"])],
        #     [])
        # self._app_logger.debug("Communicator started.")

        self._app_logger.debug("Starting the loop")
        self._loop.run_forever()

    def stop(self):

        # if self._communicator:
        #     self._communicator.stop()

        read_event.clear()
        if self._loop.is_running:
            self._app_logger.debug("Stopping the loop...")

            self._loop.call_soon_threadsafe(self._loop.stop)

            self._app_logger.debug("Loop stopped.")

        if self._key_loaded:
            self._app_logger.debug("Removing handlers from TPM. This can break something.")
            TPM2_FlushContext()
            self._app_logger.debug("Handlers removed from TPM.")


    # def _on_request(self, request):
    #
    #     # log_request = LogMessage()
    #     # log_request.ParseFromString(request.data)
    #
    #     if (log_request):
    #         request.reply("ok".encode())
    #
    #     self._queue.append(log_request.message)
    #     self._app_logger.info("Added in queue. New size: {}".format(len(self._queue)))
    #
    #     if len(self._queue) == TPMLogger.MAX_MSGS:
    #         logs = [self._queue.pop(0) for i in range(TPMLogger.MAX_MSGS)]
    #         asyncio.run_coroutine_threadsafe(self._sign(logs), self._loop)
    #         return
  

def signal_handler(signum, frame):
    tpm_logger.stop()


if __name__ == "__main__":

    signal.signal(signal.SIGQUIT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    parser = ArgumentParser(description="TPM Logger")
    parser.add_argument("-c", type=str, help="Path to config file.")
    args = parser.parse_args()

    config = ConfigParser()
    config.read(args.c)

    global tpm_logger
    tpm_logger = TPMLogger(config)
    tpm_logger.start()
