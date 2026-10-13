"""HTTP 429 backoff/retry policy (FR-15).

FR-15 also asks for the retry count/backoff to be configurable via CLI
flags; that surface is left for a later pass since the current job of
this module is just to keep discovery from tripping the API's rate
limit with the hardcoded defaults below.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class RetryPolicy:
    max_retries: int = 5
    base_delay: float = 1.0
    max_delay: float = 30.0

    def delay_seconds(self, attempt: int, retry_after: Optional[str] = None) -> float:
        """Seconds to wait before the next attempt (0-indexed attempt number)."""
        if retry_after:
            try:
                return float(retry_after)
            except ValueError:
                pass
        delay = min(self.max_delay, self.base_delay * (2**attempt))
        # Full jitter, to avoid every concurrent invocation retrying in lockstep.
        return delay * (0.5 + random.random() / 2)
