"""A polite token bucket, sized to the published Agent quotas.

Published limits (``references/agent-play.md`` §Limits)::

    120 reads / minute and 30 writes / minute, shared by every credential of the Agent
    30 notes / minute, 200 notes per challenge

Being *under* the limit matters for two reasons: a 429 on a submission path costs an
attempt window, and the platform audit-logs every request. Staying local-and-slow beats
being told to slow down.
"""

from __future__ import annotations

import threading
import time


class TokenBucket:
    """Classic token bucket: ``capacity`` tokens, refilled at ``rate_per_second``."""

    def __init__(self, capacity: int, rate_per_second: float) -> None:
        if capacity <= 0 or rate_per_second <= 0:
            raise ValueError("capacity and rate must be positive")
        self.capacity = float(capacity)
        self.rate = float(rate_per_second)
        self._tokens = float(capacity)
        self._updated = time.monotonic()
        self._lock = threading.Lock()

    def _refill_locked(self) -> None:
        now = time.monotonic()
        elapsed = now - self._updated
        if elapsed > 0:
            self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
            self._updated = now

    def try_take(self, tokens: float = 1.0) -> bool:
        with self._lock:
            self._refill_locked()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False

    def take(self, tokens: float = 1.0) -> float:
        """Block until *tokens* are available; return how long we waited, in seconds."""
        waited = 0.0
        while not self.try_take(tokens):
            with self._lock:
                self._refill_locked()
                deficit = tokens - self._tokens
                sleep_for = max(deficit / self.rate, 0.01)
            time.sleep(min(sleep_for, 1.0))
            waited += min(sleep_for, 1.0)
        return waited

    def time_until(self, tokens: float = 1.0) -> float:
        """Seconds until *tokens* would be available, without consuming any."""
        with self._lock:
            self._refill_locked()
            deficit = tokens - self._tokens
            return 0.0 if deficit <= 0 else deficit / self.rate


class Quotas:
    """The read/write pair the Agent is allowed, with a little headroom kept back."""

    def __init__(
        self,
        *,
        read_per_minute: int = 120,
        write_per_minute: int = 30,
        headroom: float = 0.85,
    ) -> None:
        if not 0 < headroom <= 1.0:
            raise ValueError("headroom must be in (0, 1]")
        # Burst a little, but aim below the published ceiling.
        self.reads = TokenBucket(
            capacity=max(1, int(read_per_minute * headroom * 0.25)),
            rate_per_second=read_per_minute * headroom / 60.0,
        )
        self.writes = TokenBucket(
            capacity=max(1, int(write_per_minute * headroom * 0.25)),
            rate_per_second=write_per_minute * headroom / 60.0,
        )

    def before_request(self, is_write: bool) -> float:
        return (self.writes if is_write else self.reads).take(1.0)

    def defer(self, is_write: bool, seconds: float) -> None:
        """After a 429, drain the matching bucket so we do not immediately retry."""
        bucket = self.writes if is_write else self.reads
        bucket.try_take(bucket.capacity)
        del seconds  # the drain above is what actually enforces the pause
