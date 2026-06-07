import logging
from pathlib import Path

from config import APP_LOG


def get_logger(name: str = "cybersecurity-log-analyzer") -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    Path(APP_LOG).parent.mkdir(parents=True, exist_ok=True)

    handler = logging.FileHandler(APP_LOG, encoding="utf-8")
    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.propagate = False

    return logger
