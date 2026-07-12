"""Lightweight circuit breaker for async HTTP clients."""
from __future__ import annotations

import logging
import time

_LOGGER = logging.getLogger(__name__)


class CircuitBreaker:
    """
    Circuit breaker with CLOSED / OPEN / HALF_OPEN states.

    CLOSED:    calls pass through; failure_threshold consecutive network
               failures trips to OPEN.
    OPEN:      calls blocked immediately; after recovery_timeout elapses
               transitions to HALF_OPEN.
    HALF_OPEN: exactly ONE probe call allowed at a time. While that probe
               is in flight, additional concurrent callers see the
               breaker as open (per `is_open()`) and bail. Audit
               2026-05-24, clients-#9: without this guard, two
               coroutines calling `_call_service` during HALF_OPEN could
               both observe state=HALF_OPEN and both probe.
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
        # True between the moment a HALF_OPEN probe is dispatched and the
        # moment `record_success` / `record_failure` resolves its outcome.
        # Additional callers observing HALF_OPEN while this flag is set
        # are treated as blocked.
        self._probe_in_flight = False

    @property
    def state(self) -> str:
        return self._state

    def is_open(self) -> bool:
        """Return True if the call should be blocked.

        Side effect: if state is OPEN and the recovery window has elapsed,
        transitions to HALF_OPEN and reserves the probe slot for the
        caller (sets `_probe_in_flight`). The caller MUST follow up with
        either `record_success()` or `record_failure()`.
        """
        if self._state == self.CLOSED:
            return False
        if self._state == self.HALF_OPEN:
            # Concurrent caller arriving during an in-flight probe is
            # blocked. The probing caller's record_* call will release.
            return self._probe_in_flight
        # OPEN: check if recovery window has elapsed
        if time.monotonic() - self._opened_at >= self._recovery_timeout:
            self._state = self.HALF_OPEN
            self._probe_in_flight = True
            _LOGGER.info("Circuit %s: OPEN → HALF_OPEN (probe allowed)", self.name)
            return False
        return True

    def record_success(self) -> None:
        if self._state == self.HALF_OPEN:
            _LOGGER.info("Circuit %s: HALF_OPEN → CLOSED", self.name)
        self._state = self.CLOSED
        self._failures = 0
        self._probe_in_flight = False

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
            self._probe_in_flight = False
        # If already OPEN, do NOT reset _opened_at — let the recovery timer tick

    def abort_probe(self) -> None:
        """Release a reserved half-open probe after cancellation/buggy exit.

        Callers invoke this from ``finally``. Successful/failed requests have
        already transitioned out of HALF_OPEN, so this is a no-op for them.
        Reopening here prevents an uncaught parse error or task cancellation
        from leaving the single probe slot reserved forever.
        """
        if self._state == self.HALF_OPEN and self._probe_in_flight:
            self._state = self.OPEN
            self._opened_at = time.monotonic()
            self._probe_in_flight = False
            _LOGGER.warning("Circuit %s: half-open probe aborted; reopening", self.name)
