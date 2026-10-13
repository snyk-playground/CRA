import io
import logging
import unittest

from snyk_generate_cra_sbom_vex import progress
from snyk_generate_cra_sbom_vex.progress import Progress, ProgressAwareHandler


class _Stream(io.StringIO):
    def __init__(self, tty):
        super().__init__()
        self._tty = tty

    def isatty(self):
        return self._tty


class ProgressTests(unittest.TestCase):
    def test_tty_draws_bar_with_percent_and_counts(self):
        out = _Stream(tty=True)
        with Progress("Generating SBOMs", 4, out) as bar:
            bar.advance()
            bar.advance()
        text = out.getvalue()
        self.assertIn("Generating SBOMs: [" + "#" * 15 + "-" * 15 + "]  50% (2/4)", text)
        self.assertTrue(text.startswith("\r"))
        self.assertTrue(text.endswith("\n"))

    def test_tty_completes_at_100_percent(self):
        out = _Stream(tty=True)
        with Progress("X", 3, out) as bar:
            for _ in range(3):
                bar.advance()
        self.assertIn("100% (3/3)", out.getvalue())

    def test_non_tty_emits_plain_lines_without_carriage_returns(self):
        out = _Stream(tty=False)
        with Progress("X", 4, out) as bar:
            for _ in range(4):
                bar.advance()
        text = out.getvalue()
        self.assertNotIn("\r", text)
        self.assertEqual(text.splitlines()[-1], "X: [" + "#" * 30 + "] 100% (4/4)")

    def test_non_tty_limits_line_count_for_large_totals(self):
        out = _Stream(tty=False)
        with Progress("X", 1000, out) as bar:
            for _ in range(1000):
                bar.advance()
        self.assertLessEqual(len(out.getvalue().splitlines()), 12)

    def test_advance_never_exceeds_total(self):
        out = _Stream(tty=False)
        with Progress("X", 1, out) as bar:
            bar.advance()
            bar.advance()
        self.assertEqual(bar.done, 1)

    def test_disabled_or_empty_prints_nothing(self):
        for kwargs, total in (({"enabled": False}, 5), ({}, 0)):
            out = _Stream(tty=True)
            with Progress("X", total, out, **kwargs) as bar:
                bar.advance()
            self.assertEqual(out.getvalue(), "")

    def test_active_bar_cleared_after_exit(self):
        with Progress("X", 1, _Stream(tty=True)):
            self.assertIsNotNone(progress._active)
        self.assertIsNone(progress._active)


class ProgressAwareHandlerTests(unittest.TestCase):
    def test_log_line_clears_bar_then_redraws_it(self):
        out = _Stream(tty=True)
        handler = ProgressAwareHandler(out)
        handler.setFormatter(logging.Formatter("%(message)s"))
        record = logging.LogRecord("t", logging.ERROR, __file__, 1, "boom", None, None)
        with Progress("X", 2, out) as bar:
            bar.advance()
            before = len(out.getvalue())
            handler.emit(record)
            emitted = out.getvalue()[before:]
        blank = "\r" + " " * bar._line_len + "\r"
        self.assertTrue(emitted.startswith(blank))
        self.assertIn("boom\n", emitted)
        self.assertTrue(emitted.rstrip("\n").endswith("(1/2)"))

    def test_handler_without_active_bar_just_logs(self):
        out = _Stream(tty=True)
        handler = ProgressAwareHandler(out)
        handler.setFormatter(logging.Formatter("%(message)s"))
        handler.emit(logging.LogRecord("t", logging.INFO, __file__, 1, "hi", None, None))
        self.assertEqual(out.getvalue(), "hi\n")


if __name__ == "__main__":
    unittest.main()
