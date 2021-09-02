
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

    LOG_TEMPLATE = "{time} - Priority: {priority} - {message}"
    
    HIGH_PRIORITY = Priority.HIGH.value
    MEDIUM_PRIORITY = Priority.MEDIUM.value
    LOW_PRIORITY = Priority.LOW.value

    def __init__(self, filename, level="DEBUG") -> None:
        """
        Creates and configures a normal python logger. Parent class for other
        logging classes.

        Wraps python logging functions, with a additional priority field. If during
        function call priority is not given, the default value is LOW.

        :param filename: name of the actual log file
        :param level: log level, equivalent to the python log level
        """
        
        super().__init__()

        self._filename = filename
        self._level = level

        self._logger = getLogger(__name__)
        self._logger.setLevel(self._level)

        self._handler = FileHandler(self._filename)
        self._handler.setLevel(self._level)
        
        self._format = Formatter()
        
        self._handler.setFormatter(self._format)

        self._logger.addHandler(self._handler)

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

    def _check_priority(self, priority):
        return priority if priority in [e.value for e in Logger.Priority] else Logger.LOW_PRIORITY

    def _build_log(self, **kwargs):
        return Logger.LOG_TEMPLATE.format(**kwargs)

    def _log(self, log_func, **kwargs):
        
        msg = kwargs.get("msg", None)
        priority = kwargs.get("priority", None)
        do_write = kwargs.get("do_write", False)

        if not msg:
            raise ValueError("Invalid arguments.")

        prior = self._check_priority(priority)
        msg = self._build_log(time="0", priority=prior, message=msg)

        if do_write:
            log_func(msg)

        return msg


if __name__ == "__main__":
    logger = Logger("testlog")
    logger.error("test")
