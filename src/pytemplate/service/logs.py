import logging
from contextlib import contextmanager

from pytemplate.domain.validators import validate_log_level


@validate_log_level
@contextmanager
def log(level):
    logger = logging.getLogger()
    original_level = logger.getEffectiveLevel()
    logger.setLevel(level)
    try:
        yield logger
    finally:
        logger.setLevel(original_level)
