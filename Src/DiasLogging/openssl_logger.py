import os
from typing import overload

from logger import Logger
from bootstrap import PRIV_NAME

from OpenSSL.crypto import FILETYPE_PEM
from OpenSSL.crypto import load_privatekey, sign


class KeyNotLoadedError(Exception):

    def __init__(self, message="Key not loaded."):
        self.message = message
        super().__init__(self.message)


class OpenSSLogger(Logger):

    EOM_TEMPLATE = " - {}"
    DIGEST = "SHA1"

    def __init__(self, filename, priv_path, level="DEBUG"):
        """
        Creates and configures a custom logger over the Logger class. Additionally adds
        a cryptographics signature to the message logged.

        Before using OpenSSLogger, a bootrapping process needs to be done. For this, see
        bootstrap.py.

        Requires in addition to Logger, a pair of asymetric keys which are generated with bootstrap.py. 

        :param priv_path: path to private key, must be the same provided to bootstrap.py  
        """
        super().__init__(filename, level)

        if not os.path.isfile(priv_path):
            raise FileNotFoundError("Private key file not found.")
        
        with open(priv_path, 'r') as priv_f:
            self._priv_key = load_privatekey(FILETYPE_PEM, priv_f.read())

    def info(self, msg, priority=None, do_write=True):
        return self._log(log_func=self._logger.info, msg=msg, 
            priority=priority, do_write=do_write)

    def warning(self, msg, priority=None, do_write=True):
        return self._log(log_func=self._logger.warning, msg=msg, 
            priority=priority, do_write=do_write)


    def error(self, msg, priority=None, do_write=True):
        return self._log(log_func=self._logger.error, msg=msg, 
            priority=priority, do_write=do_write)


    def critical(self, msg, priority=None, do_write=True):
        return self._log(log_func=self._logger.critical, msg=msg, 
            priority=priority, do_write=do_write)

    def _log(self, log_func, **kwargs):
        
        msg = kwargs.get("msg", None)
        priority = kwargs.get("priority", None)
        do_write = kwargs.get("do_write", None)

        if msg == None or priority == None or do_write == None:
            raise ValueError("Invalid arguments.")

        if not self._priv_key:
            raise KeyNotLoadedError()

        log = super()._log(log_func=log_func, msg=msg, 
            priority=priority, do_write=False)  
        signature = sign(self._priv_key, log.encode(), OpenSSLogger.DIGEST)

        signed_log = log + OpenSSLogger.EOM_TEMPLATE.format(signature)

        if do_write:
            log_func(signed_log)

        return log, signature


if __name__ == "__main__":
    
    logger = OpenSSLogger("testlog", "/tmp/"+ PRIV_NAME)
    logger.info("test", Logger.LOW_PRIORITY, True)
