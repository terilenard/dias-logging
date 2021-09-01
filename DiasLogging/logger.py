
from logging import getLogger
from logging import FileHandler
from logging import Formatter

from enum import Enum


class Logger(object):
    """
    Wrapper for local logging without security features.
    """

    class Priority(Enum):
        HIGH = "HIGH"
        MEDIUM = "MEDIUM"
        LOW = "LOW"

    FORMAT = "%(created)f - %(levelname)s - Priority: %(priority)s - %(message)s"
    
    HIGH_PRIORITY = Priority.HIGH.value
    MEDIUM_PRIORITY = Priority.MEDIUM.value
    LOW_PRIORITY = Priority.LOW.value

    def __init__(self, filename, level="DEBUG", format=FORMAT) -> None:
        """
        Creates and configures a normal python logger. Parent class for other
        logging classes.

        Wraps python logging functions, with a additional priority field. If during
        function call priority is not given, the default value is LOW.

        :param filename: name of the actual log file
        :param level: log level, equivalent to the python log level
        :param format: string denoting the fields in the log format
        """
        
        super().__init__()

        self._filename = filename
        self._level = level

        self._logger = getLogger(__name__)
        self._logger.setLevel(self._level)

        self._handler = FileHandler(self._filename)
        self._handler.setLevel(self._level)
        
        self._format = Formatter(format)
        
        self._handler.setFormatter(self._format)

        self._logger.addHandler(self._handler)

    def info(self, msg, priority=None):
        value = self._check_priority(priority)
        extra={
            'priority': value,
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


    def _check_priority(self, priority):
        return priority if priority in [e.value for e in Logger.Priority] else Logger.LOW_PRIORITY
