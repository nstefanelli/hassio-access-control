"""Lightweight circuit breaker for async HTTP clients."""
from __future__ import annotations

import logging
import time

_LOGGER = logging.getLogger(__name__)


class CircuitBreaker:
    """
    Circuit breaker with CLOSED / OPEN / HALF_OPEN states.

    CLOSED: calls pass through; failure_threshold consecutive network
            failures trips to OPEN.
    OPEN:   calls blocked immediately; after recovery_timeout elapses
            transitions to HALF_OPEN.
    HALF_OPEN: one probe call allowed; success → CLOSED, failure → OPEN.
    """

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

    def __init__(
        self,
        name: str,
        failure_threshold: int = 3,
        recovery_timeout: float = 60.0,
    ) -> None:
        self.name = name
        self._threshold = failure_threshold
        self._recovery_timeout = recovery_timeout
        self._state = self.CLOSED
        self._failures = 0
        self._opened_at: float = 0.0

    @property
    def state(self) -> str:
        return self._state

    def is_open(self) -> bool:
        """Return True if the call should be blocked."""
        if self._state == self.CLOSED:
            return False
        if self._state == self.HALF_OPEN:
            return False  # allow probe
        # OPEN: check if recovery window has elapsed
        if time.monotonic() - self._opened_at >= self._recovery_timeout:
            self._state = self.HALF_OPEN
            _LOGGER.info("Circuit %s: OPEN → HALF_OPEN (probe allowed)", self.name)
            return False
        return True

    def record_success(self) -> None:
        if self._state == self.HALF_OPEN:
            _LOGGER.info("Circuit %s: HALF_OPEN → CLOSED", self.name)
        self._state = self.CLOSED
        self._failures = 0

    def record_failure(self) -> None:
        self._failures += 1
        if self._state == self.CLOSED:
            if self._failures >= self._threshold:
                self._opened_at = time.monotonic()
                _LOGGER.warning(
                    "Circuit %s: → OPEN (consecutive_failures=%d)", self.name, self._failures
                )
                self._state = self.OPEN
        elif self._state == self.HALF_OPEN:
            # Probe failed — reopen
            self._opened_at = time.monotonic()
            _LOGGER.warning("Circuit %s: HALF_OPEN → OPEN (probe failed)", self.name)
            self._state = self.OPEN
        # If already OPEN, do NOT reset _opened_at — let the recovery timer tick
