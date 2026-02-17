import os
import logging


def blue(text: str) -> str:
    return f"\033[94m{text}\033[0m"


def yellow(text: str) -> str:
    return f"\033[93m{text}\033[0m"


def red(text: str) -> str:
    return f"\033[91m{text}\033[0m"


class HackerTyperFormatter(logging.Formatter):
    """Custom formatter for pretty text prefixes"""

    LEVEL_MAPPING = {
        "DEBUG": blue("[~]"),
        "INFO": blue("[*]"),
        "WARNING": yellow("[-]"),
        "ERROR": red("[!]"),
    }

    def format(self, record: logging.LogRecord):
        prefix = self.LEVEL_MAPPING.get(record.levelname, "[?]")
        record.levelname = prefix
        return super().format(record)


level = getattr(logging, os.environ.get("LOG_LEVEL") or "INFO")
formatter = HackerTyperFormatter("%(levelname)s %(message)s")
handler = logging.StreamHandler()
handler.setFormatter(formatter)

logger = logging.getLogger(__name__)
logger.setLevel(level)
logger.addHandler(handler)
