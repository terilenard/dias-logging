"""
This work is licensed under the terms of the MIT license.  
For a copy, see <https://opensource.org/licenses/MIT>.

Developed by NISLAB - Network and Information Security Laboratory
at George Emil Palade University of Medicine, Pharmacy, Science and
Technology of Târgu Mureş <https://nislab.umfst.ro/>

Contributors: Teri Lenard
"""

import asyncio
import json
import signal
import sys
import logging
import re
import time

from string import printable
from configparser import ConfigParser
from argparse import ArgumentParser
from hashlib import sha1

from client_mqtt import MQTTClient
from utils import *
from wrapper import TPM2_FlushContext, TPM2_LoadKey, TPM2_Sign, TPM2_Hash, \
    TPM2_ExtendPcr, TPM2_Provision, TPM2_DICTIONARY_LOCKOUT


def setup_logger(name, log_file, level=logging.DEBUG):
    """To setup as many loggers as you want"""
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')

    handler = logging.FileHandler(log_file)
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)

    return logger

class StopProcessException(Exception):

    def __init__(self):
        pass


class TPMLogger:

    MAX_MSGS = 1
    PCR = 4

    def __init__(self, config):

        self._sec_logger = setup_logger("TPMLogger", config["log"]["tpm_log"])
        self._app_logger = setup_logger("ServiceTPMLogger", config["log"]["info_log"])

        self._tpm_conf = dict(config["tpm"])
        self._key_loaded = False

        self._pipe_path = config["log"]["fifo"]
        self._pipe = None
        self._queue = list()
        self._last_message = ""
        self._should_read = True

        self._mqtt_client = MQTTClient(config["mqtt"]["user"],
                                      config["mqtt"]["passwd"],
                                      config["mqtt"]["host"],
                                      int(config["mqtt"]["port"]))

        self._loop = asyncio.get_event_loop()

    def _read_pipe(self):
        self._last_message = ""
        while self._should_read:
            self._last_message += self._pipe.read(1)
            if self._last_message.endswith('\n'):
                return self._last_message[:-1]

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

        try:
            msg = self._read_pipe()
        except StopProcessException:
            self.stop()
            return

        if not msg:
            asyncio.run_coroutine_threadsafe(self._listen_on_pipe(), self._loop)
            return

        json_log = dict()

        log = ''.join(char for char in msg if char in printable)
        print(log)
        m = re.search('CAN ID: (.+?) .', log)
        if m:
            found = m.group(1)
            try:
                json_log["CanId"] = int(found)
            except ValueError:
                pass

        m = re.search('(.+?) CAN', log)

        if m:
            found = m.group(1)
            json_log["Message"] = found

        m = re.search("Timestamp: (.+?) .", log)
        if m:
            found = m.group(1)

            try:
                json_log["Timestamp"] = float(found)
            except ValueError:
                pass
        else:
            json_log["Timestamp"] = time.time()

        json_log["Count"] = 1

        if self._mqtt_client.is_connected():
            self._mqtt_client.publish(
            json.dumps(json_log))

        asyncio.run_coroutine_threadsafe(self._listen_on_pipe(), self._loop)

    async def _sign(self, logs):

        self._app_logger.info("Started singing")
        json_log = dict()

        for log in logs:
            #json_log[self._hash(log)] = log
            json_log["Message"] = log

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

        json_log["Signature"] = signature

        self._sec_logger.info(json.dumps(json_log))

        if self._mqtt_client.is_connected():
            self._mqtt_client.publish(json.dumps(json_log))

        self._app_logger.info("Finished signing")

        asyncio.run_coroutine_threadsafe(self._listen_on_pipe(), self._loop)

    def start(self):

        if not make_pipe(self._pipe_path):
            self._app_logger.error("Couldn't create fifo.")
            return False

        self._should_read = True
        fd = os.open(self._pipe_path, os.O_RDONLY)
        self._pipe = os.fdopen(fd, "r")
        #
        # success = TPM2_DICTIONARY_LOCKOUT()
        #
        # if success:
        #     self._app_logger.info("Removed dictionary lockout.")
        # else:
        #     self._app_logger.error("Could not execute dictionary lockout")
        #
        # success = TPM2_Provision(self._tpm_conf["tpm2_prov_path"], "primary.ctx")
        #
        # if success:
        #     self._app_logger.debug("Recreated primary.ctx in " + self._tpm_conf["tpm2_prov_path"])
        #
        #     if success:
        #         self._app_logger.debug("Finished recreating primary.ctx.")
        #     else:
        #         self._app_logger.error("Could not recreate primary.ctx.")
        #
        # self._key_loaded = TPM2_LoadKey(self._tpm_conf["tpm2_primary_ctx"],
        #                                 self._tpm_conf["tpm2_pub_rsa"],
        #                                 self._tpm_conf["tpm2_priv_rsa"],
        #                                 self._tpm_conf["tpm2_priv_ctx"])
        #
        # if not self._key_loaded:
        #     self._app_logger.error("Couldn't load keys into the TPM.")
        #     return False

        self._mqtt_client.connect()

        if self._loop is None:
            self._loop = asyncio.get_event_loop()

        self._loop.create_task(self._listen_on_pipe())

        self._app_logger.debug("Starting the loop")
        self._loop.run_forever()

    def stop(self):

        if self._pipe:
            self._should_read = False
            self._pipe.close()


        if self._mqtt_client.is_connected():
            self._app_logger.debug("Stopping the mqtt client")
            self._mqtt_client.stop()
            self._app_logger.debug("Mqtt client stopped")

        if self._loop.is_running:
            self._app_logger.debug("Stopping the loop...")

            self._loop.call_soon_threadsafe(self._loop.stop)

            self._app_logger.debug("Loop stopped.")

        # if self._key_loaded:
        #     self._app_logger.debug("Removing handlers from TPM. This can break something.")
        #     TPM2_FlushContext()
        #     self._app_logger.debug("Handlers removed from TPM.")



def signal_handler(signum, frame):
    raise StopProcessException()


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
