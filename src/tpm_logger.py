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
import re
import time

from string import printable
from configparser import ConfigParser
from argparse import ArgumentParser
from hashlib import sha1

from log import logger
from client_mqtt import MQTTClient
from utils import *
from wrapper import TPM2_FlushContext, TPM2_LoadKey, TPM2_Sign, TPM2_Hash, \
    TPM2_ExtendPcr, TPM2_ReadPcr, TPM2_CreatePrimary, TPM2_DICTIONARY_LOCKOUT


class StopProcessException(Exception):

    def __init__(self):
        pass


class TPMCore:

    def __init__(self, config):
        self._config = dict(config["tpm"])

        self._primary_ctx = self._config["tpm2_primary_ctx"]
        self._key_priv = self._config["tpm2_priv_rsa"]
        self._key_pub = self._config["tpm2_pub_rsa"]
        self._tmp_file = self._config["tmp_file"]
        self._digest_file = self._config["tmp_digest_file"]
        self._pcr = self._config["pcr"]
        self._sign_file = self._config["tmp_output"]
        self._prov_path = self._config["tpm2_prov_path"]
        self._key_ctx = self._config["tpm2_priv_ctx"]


        self._key_loaded = False

        self._is_provisioned = self._check_provision()

    @property
    def is_provisioned(self):
        return self._is_provisioned

    @property
    def is_key_loaded(self):
        return self._key_loaded

    @property
    def pcr_state(self):
        # Return True if PCR is 0x00 else False

        pcr_value = TPM2_ReadPcr(self._pcr);

        if "0x0000000000000000000000000000000000000000" == pcr_value:
            return True
        return False

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

        self._key_loaded = TPM2_LoadKey(self._prov_path + self._primary_ctx,
                                        self._prov_path + self._key_pub,
                                        self._prov_path + self._key_priv,
                                        self._prov_path + self._key_ctx)

        if not self._key_loaded:
            logger.error("Couldn't load keys into the TPM.")
            return False

        return True

    def _check_provision(self):
        """
        Verifies that the provision step was done correctly,
        and the keys/handlers exists in expected directories.
        """
        return exists(self._primary_ctx)  \
                and exists(self._key_priv) \
                and exists(self._key_pub)

    def _hash(self, msg):
        return sha1(msg.encode()).hexdigest()

    def sign(self, msg):

        if not self._key_loaded:
            logger.error("Keys not loaded.")
            return False

        json_log = dict()

        json_log["Message"] = msg

        dump(msg, self._tmp_file)

        digest = TPM2_Hash(self._tmp_file, self._digest_file)

        if not digest:
            logger.error("Couldn't hash: {}.".format(msg))
            return False

        success = TPM2_ExtendPcr(self._pcr, self._digest_file)

        if not success:
            logger.error("Couldn't extend PCR {} with {}".format(
                        self._pcr, self._digest_file))
            return False

        json_log["PCR"] = TPM2_ReadPcr(self._pcr);

        success = TPM2_Sign(self._prov_path + self._key_ctx,
                            self._digest_file, self._sign_file)

        if not success:
            logger.error("Couldn't sign {}".format(str(msg)))
            return False

        signature = load_binary(self._sign_file)

        json_log["Signature"] = signature

        logger.info("New secure log: " + json.dumps(json_log))

        return json_log


class MessageParser():

    CANID_REGEX = 'CAN ID: (.+?) .'
    LOG_REGEX = '(.+?) CAN'
    TIMESTAMP_REGEX = "Timestamp: (.+?) ."

    def _get_value(regex, msg):
        found = None
        m = re.search(regex, msg)

        if m:
            found = m.group(1)

        return found

    def parse_message(msg):
        """
        Returns the can_id, count, log message, timestamp
        from a single string.
        """
        can_id = 0
        parsed_log = ""
        count = 1
        timestamp = 0.0

        log = ''.join(char for char in msg if char in printable)
 
        try:
            can_id = int(MessageParser._get_value(
                MessageParser.CANID_REGEX, log
            ))
        except (ValueError, TypeError):
                pass

        parsed_log = MessageParser._get_value(
                MessageParser.LOG_REGEX, log
            )

        try:
            timestamp = float(MessageParser._get_value(
                MessageParser.TIMESTAMP_REGEX, log
            ))
        except (ValueError, TypeError):
            timestamp = time.time()

        return (can_id, parsed_log, count, timestamp)


class TPMLogger:

    def __init__(self, config):

        self._tpm_core = TPMCore(config)

        self._pipe_path = config["log"]["fifo"]
        self._pipe = None
        self._queue = list()
        self._should_read = True

        self._mqtt_client = MQTTClient(config["mqtt"]["user"],
                                      config["mqtt"]["passwd"],
                                      config["mqtt"]["host"],
                                      int(config["mqtt"]["port"]),
                                      on_message_callback=self._on_new_message)

        self._loop = asyncio.get_event_loop()

    def _read_pipe(self):
        _last_message = ""
        while self._should_read:
            _last_message += self._pipe.read(1)
            if _last_message.endswith('\n'):
                return _last_message[:-1]

    async def _listen_on_pipe(self):

        try:
            msg = self._read_pipe()
        except StopProcessException:
            self.stop()
            return

        asyncio.run_coroutine_threadsafe(self._listen_on_pipe(), self._loop)

        if not msg:
            return

        self._handle_log(msg)

    def start(self):

        if not make_pipe(self._pipe_path):
            logger.error("Couldn't create fifo.")
            return False

        self._should_read = True
        fd = os.open(self._pipe_path, os.O_RDONLY)
        self._pipe = os.fdopen(fd, "r")

        if not self._tpm_core.initialise():
            logger.error("Could not initialise/load keys")
            return False

        self._mqtt_client.connect()

        if self._loop is None:
            self._loop = asyncio.get_event_loop()

        self._loop.create_task(self._listen_on_pipe())

        logger.debug("Starting the loop")
        self._loop.run_forever()

    def stop(self):

        if self._pipe:
            self._should_read = False
            self._pipe.close()

        if self._mqtt_client.is_connected():
            logger.debug("Stopping the mqtt client")
            self._mqtt_client.stop()
            logger.debug("Mqtt client stopped")

        if self._loop.is_running:
            logger.debug("Stopping the loop...")
            self._loop.call_soon_threadsafe(self._loop.stop)
            logger.debug("Loop stopped.")

    def _on_new_message(self, mqttc, obj, msg):

        if not msg:
            logger.error("Error on receiving new mqtt message")
            return

        self._handle_log(msg.payload.decode())

    def _handle_log(self, msg):

        can_id, parsed_log, count, timestamp = MessageParser.parse_message(msg)

        json_log = self._tpm_core.sign(parsed_log)

        """
        json_log now looks like:
            json_log{
                "Message": parsed_log,
                "Timestamp": timestamp,
                "Count": count
        }
        Next the can id is set
        """
        json_log["CanId"] = can_id
        json_log["Timestamp"] = timestamp
        json_log["Count"] = count


        # Indicate that a new PCR chain started
        # This should be set to False after the first
        # log is published
        json_log["IsNewChain"] = self._tpm_core.pcr_state

        if self._mqtt_client.is_connected():
            self._mqtt_client.publish_log(
                json.dumps(json_log))
        else:
            logger.error("Couldn't publish json to mqtt")


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
