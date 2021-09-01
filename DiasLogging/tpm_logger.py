
from DiasLogging.logger import Logger


class TPMLogger(Logger):

    SEC_FORMAT = Logger.FORMAT + " - (signature)s"

    def __init__(self, filename, key_ctx, level="DEBUG", format=SEC_FORMAT) -> None:
        super().__init__(filename, level, format)
