import logging
from enum import Enum


class LogLevel(Enum):
    INFO = logging.INFO
    DEBUG = logging.DEBUG
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL

    def __str__(self):
        return f"{self.__class__.__name__}.{self.name}"
