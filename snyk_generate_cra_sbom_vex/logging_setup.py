"""Default and debug/verbose logging configuration, including token redaction (FR-13).

FR-5 and NFR-3 require the API token never be logged, even in --debug
output. configure() takes an optional list of secret strings and
attaches a filter that redacts any exact occurrence of them from every
log record before it reaches a handler.
"""

from __future__ import annotations

import logging
from typing import Iterable, List, Optional

from .progress import ProgressAwareHandler

LOGGER_NAME = "snyk_generate_cra_sbom_vex"
REDACTED = "***REDACTED***"

_DEFAULT_FORMAT = "%(message)s"
_DEBUG_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"


class _RedactFilter(logging.Filter):
    """Replaces any occurrence of the given secret values in a log message.

    Secrets shorter than _MIN_SECRET_LENGTH are ignored: real Snyk tokens
    are long random strings, and matching a very short value (e.g. a
    one-character placeholder in a test) as a substring would redact
    unrelated text throughout every log line.
    """

    _MIN_SECRET_LENGTH = 8

    def __init__(self, secrets: Iterable[str]) -> None:
        super().__init__()
        self._secrets: List[str] = [
            s for s in secrets if s and len(s) >= self._MIN_SECRET_LENGTH
        ]

    def filter(self, record: logging.LogRecord) -> bool:
        if self._secrets:
            message = record.getMessage()
            for secret in self._secrets:
                message = message.replace(secret, REDACTED)
            record.msg = message
            record.args = ()
        return True


def configure(debug: bool, redact: Optional[Iterable[str]] = None) -> logging.Logger:
    """(Re)configures the root logger's single handler and returns the app logger.

    Safe to call more than once per process (e.g. once before the API
    token is known, and again afterward to start redacting it) -- each
    call replaces the previous handler rather than stacking a new one.
    """
    level = logging.DEBUG if debug else logging.INFO
    fmt = _DEBUG_FORMAT if debug else _DEFAULT_FORMAT

    handler = ProgressAwareHandler()
    handler.setFormatter(logging.Formatter(fmt))
    handler.addFilter(_RedactFilter(redact or []))

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)

    return logging.getLogger(LOGGER_NAME)
