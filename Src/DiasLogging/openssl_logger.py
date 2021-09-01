import os
from typing import overload

from DiasLogging.logger import Logger

from OpenSSL.crypto import FILETYPE_PEM
from OpenSSL.crypto import load_privatekey, sign


class KeyNotLoadedError(Exception):

    def __init__(self, message="Key not loaded."):
        self.message = message
        super().__init__(self.message)


class OpenSSLogger(Logger):

    SEC_FORMAT = Logger.FORMAT + " - (signature)s"
    DIGEST = "SHA1"

    def __init__(self, filename, priv_path, level="DEBUG", format=SEC_FORMAT) -> None:
        """
        Creates and configures a custom logger over the Logger class. Additionally adds
        a cryptographics signature to the message logged.

        Before using OpenSSLogger, a bootrapping process needs to be done. For this, see
        bootstrap.py.

        Requires in addition to Logger, a pair of asymetric keys which are generated with bootstrap.py. 

        :param priv_path: path to private key, must be the same provided to bootstrap.py  
        """
        super().__init__(filename, level, format)

        if not os.path.isfile(priv_path):
            raise FileNotFoundError("Private key file not found.")
        
        with open("priv_path", r) as priv_f:
            self._priv_key = load_privatekey(FILETYPE_PEM, priv_f.read())

    def info(self, msg, priority=None):
        
        if not self._pub_key or not self._priv_key:
            raise KeyNotLoadedError()
        
        signature = sign(self._priv_key, msg, OpenSSLogger.DIGEST)

        value = self._check_priority(priority)
        extra={
            'priority': value,
            'signature': signature
            }
        self._logger.info(msg, extra=extra)

    def warning(self, msg, priority=None):
        value = self._check_priority(priority)
        extra={
            'priority': value,
            }
        self._logger.warning(msg, extra=extra)


    def error(self, msg, priority=None):
        value = self._check_priority(priority)
        extra={
            'priority': value,
            }
        self._logger.warning(msg, extra=extra)


    def critical(self, msg, priority=None):
        value = self._check_priority(priority)
        extra={
            'priority': value,
            }
        self._logger.warning(msg, extra=extra)