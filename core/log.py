"""Console logging setup."""
from __future__ import annotations

import logging
import sys

_CONFIGURED = False

_COLORS = {
    "DEBUG": "\033[90m", "INFO": "\033[36m", "WARNING": "\033[33m",
    "ERROR": "\033[31m", "CRITICAL": "\033[41m",
}
_RESET = "\033[0m"


class _Formatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        color = _COLORS.get(record.levelname, "")
        record.levelname_c = f"{color}{record.levelname:<7}{_RESET}"
        return super().format(record)


def _configure() -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_Formatter("%(levelname_c)s %(message)s"))
    root = logging.getLogger("admap")
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    _configure()
    return logging.getLogger("admap." + name.split(".")[-1])


def set_verbose(verbose: bool) -> None:
    _configure()
    logging.getLogger("admap").setLevel(logging.DEBUG if verbose else logging.INFO)
