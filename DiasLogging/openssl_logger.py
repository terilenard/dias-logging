
from DiasLogging.logger import Logger

from OpenSSL.crypto import load_publickey, dump_publickey

class OpenSSLogger(Logger):

    SEC_FORMAT = Logger.FORMAT + " - (signature)s"

    def __init__(self, filename, pub_path, priv_path, level="DEBUG", format=SEC_FORMAT) -> None:
        """
        Creates and configures a custom logger over the Logger class. Additionally adds
        a cryptographics signature to the message logged.

        Before using OpenSSLogger, a bootrapping process needs to be done. For this, see
        bootstrap.py.

        Requires in addition to Logger, a pair of asymetric keys which are generated with bootstrap.py. 

        :param pub_path: path to public key, must be the same provided to bootstrap.py
        :param priv_path: path to private key, must be the same provided to bootstrap.py  
        """
        super().__init__(filename, level, format)

    