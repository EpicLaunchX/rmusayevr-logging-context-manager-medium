import logging
from contextlib import contextmanager


@contextmanager
def log(level):
    logger = logging.getLogger()
    original_level = logger.getEffectiveLevel()
    logger.setLevel(level)
    try:
        yield logger
    finally:
        logger.setLevel(original_level)
