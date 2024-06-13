from logging.config import dictConfig

from src.pytemplate.configurator.settings.base import LOGGING
from src.pytemplate.service.logs import log


def main():
    dictConfig(LOGGING)

    log_level = input("Enter log level (DEBUG/INFO/WARNING/ERROR/CRITICAL): ")

    with log(log_level) as logging_manager:
        logging_manager.info("Main worked successfully!")
