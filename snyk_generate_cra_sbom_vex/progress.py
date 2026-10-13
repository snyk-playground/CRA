"""Status/progress reporting for the SBOM fetch and VEX derivation phases.

On an interactive terminal this draws a single-line status bar on stderr
(percent complete, items done and total). When stderr is not a TTY (CI,
redirected output) it falls back to a plain log line every few items so
logs stay readable. Log records emitted while a bar is showing are
written after clearing the bar line (see ProgressAwareHandler), then the
bar is redrawn.
"""

from __future__ import annotations

import logging
import sys
from typing import Optional, TextIO

_BAR_WIDTH = 30
_NON_TTY_STEPS = 10  # at most this many log lines per phase when not a TTY

_active: Optional["Progress"] = None


class Progress:
    def __init__(
        self, label: str, total: int, stream: Optional[TextIO] = None, enabled: bool = True
    ) -> None:
        self.label = label
        self.total = total if enabled else 0
        self.done = 0
        self._stream = stream if stream is not None else sys.stderr
        self._tty = bool(getattr(self._stream, "isatty", lambda: False)())
        self._last_logged_pct = -1
        self._line_len = 0

    def __enter__(self) -> "Progress":
        global _active
        if self.total > 0:
            _active = self
            self._render()
        return self

    def __exit__(self, *exc: object) -> None:
        global _active
        _active = None
        if self._tty and self.total > 0:
            self._stream.write("\n")
            self._stream.flush()

    def advance(self, n: int = 1) -> None:
        self.done = min(self.total, self.done + n)
        self._render()

    def _line(self) -> str:
        pct = 100 * self.done // self.total if self.total else 100
        filled = _BAR_WIDTH * self.done // self.total if self.total else _BAR_WIDTH
        bar = "#" * filled + "-" * (_BAR_WIDTH - filled)
        return f"{self.label}: [{bar}] {pct:3d}% ({self.done}/{self.total})"

    def _render(self) -> None:
        if self.total <= 0:
            return
        if self._tty:
            line = self._line()
            self._stream.write("\r" + line)
            self._line_len = len(line)
            self._stream.flush()
            return
        pct = 100 * self.done // self.total
        step = 100 // _NON_TTY_STEPS
        if self.done == self.total or pct // step > self._last_logged_pct // step:
            self._last_logged_pct = pct
            self._stream.write(self._line() + "\n")
            self._stream.flush()

    def clear_line(self) -> None:
        if self._tty and self._line_len:
            self._stream.write("\r" + " " * self._line_len + "\r")

    def redraw(self) -> None:
        if self._tty:
            self._render()


class ProgressAwareHandler(logging.StreamHandler):
    """StreamHandler that keeps log lines from colliding with the status bar."""

    def emit(self, record: logging.LogRecord) -> None:
        bar = _active
        if bar is not None:
            bar.clear_line()
        super().emit(record)
        if bar is not None:
            bar.redraw()
