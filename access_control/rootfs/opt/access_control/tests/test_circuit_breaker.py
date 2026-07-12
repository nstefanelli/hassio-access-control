from __future__ import annotations

import importlib
import importlib.util
import sys
import unittest
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load_package() -> None:
    """Load the access_control package into sys.modules if not already loaded."""
    if "access_control" in sys.modules:
        return
    spec = importlib.util.spec_from_file_location(
        "access_control",
        ROOT / "__init__.py",
        submodule_search_locations=[str(ROOT)],
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["access_control"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)


_load_package()
circuit_breaker = importlib.import_module("access_control.circuit_breaker")
CircuitBreaker = circuit_breaker.CircuitBreaker


class TestCircuitBreakerStateMachine(unittest.TestCase):
    # ------------------------------------------------------------------
    # 1. Initial state
    # ------------------------------------------------------------------

    def test_starts_closed(self) -> None:
        cb = CircuitBreaker("test", failure_threshold=3, recovery_timeout=60.0)
        self.assertFalse(cb.is_open())
        self.assertEqual(cb.state, CircuitBreaker.CLOSED)

    # ------------------------------------------------------------------
    # 2. Failures below threshold keep the breaker CLOSED
    # ------------------------------------------------------------------

    def test_failure_below_threshold_stays_closed(self) -> None:
        cb = CircuitBreaker("test", failure_threshold=3, recovery_timeout=60.0)
        cb.record_failure()
        cb.record_failure()
        self.assertFalse(cb.is_open())
        self.assertEqual(cb.state, CircuitBreaker.CLOSED)

    # ------------------------------------------------------------------
    # 3. Threshold failures trip the breaker to OPEN
    # ------------------------------------------------------------------

    def test_threshold_failures_opens_circuit(self) -> None:
        cb = CircuitBreaker("test", failure_threshold=3, recovery_timeout=60.0)
        cb.record_failure()
        cb.record_failure()
        cb.record_failure()
        self.assertTrue(cb.is_open())
        self.assertEqual(cb.state, CircuitBreaker.OPEN)

    # ------------------------------------------------------------------
    # 4. record_success resets the failure counter
    # ------------------------------------------------------------------

    def test_success_resets_failure_count(self) -> None:
        cb = CircuitBreaker("test", failure_threshold=3, recovery_timeout=60.0)
        cb.record_failure()
        cb.record_failure()
        # Not yet open — success should reset
        cb.record_success()
        self.assertFalse(cb.is_open())
        self.assertEqual(cb.state, CircuitBreaker.CLOSED)
        # One more failure must NOT open (counter was reset to 0)
        cb.record_failure()
        self.assertFalse(cb.is_open())
        self.assertEqual(cb.state, CircuitBreaker.CLOSED)

    # ------------------------------------------------------------------
    # 5. After recovery_timeout, OPEN transitions to HALF_OPEN
    # ------------------------------------------------------------------

    def test_open_transitions_to_half_open_after_timeout(self) -> None:
        cb = CircuitBreaker("test", failure_threshold=3, recovery_timeout=60.0)
        base_time = 1000.0
        with unittest.mock.patch("access_control.circuit_breaker.time.monotonic", return_value=base_time):
            cb.record_failure()
            cb.record_failure()
            cb.record_failure()
        # Advance time past recovery_timeout — is_open() should flip to HALF_OPEN
        with unittest.mock.patch("access_control.circuit_breaker.time.monotonic", return_value=base_time + 61.0):
            self.assertFalse(cb.is_open())
            self.assertEqual(cb.state, CircuitBreaker.HALF_OPEN)

    # ------------------------------------------------------------------
    # 6. Probe success in HALF_OPEN closes the circuit
    # ------------------------------------------------------------------

    def test_probe_success_closes_circuit(self) -> None:
        cb = CircuitBreaker("test", failure_threshold=3, recovery_timeout=60.0)
        base_time = 2000.0
        # Trip the circuit
        with unittest.mock.patch("access_control.circuit_breaker.time.monotonic", return_value=base_time):
            for _ in range(3):
                cb.record_failure()
        # Advance past recovery_timeout to enter HALF_OPEN
        with unittest.mock.patch("access_control.circuit_breaker.time.monotonic", return_value=base_time + 61.0):
            self.assertFalse(cb.is_open())
            self.assertEqual(cb.state, CircuitBreaker.HALF_OPEN)
        # Successful probe closes the circuit
        cb.record_success()
        self.assertFalse(cb.is_open())
        self.assertEqual(cb.state, CircuitBreaker.CLOSED)

    # ------------------------------------------------------------------
    # 7. Probe failure in HALF_OPEN re-opens the circuit
    # ------------------------------------------------------------------

    def test_probe_failure_reopens_circuit(self) -> None:
        cb = CircuitBreaker("test", failure_threshold=3, recovery_timeout=60.0)
        base_time = 3000.0
        # Trip the circuit
        with unittest.mock.patch("access_control.circuit_breaker.time.monotonic", return_value=base_time):
            for _ in range(3):
                cb.record_failure()
        # Advance past recovery_timeout to enter HALF_OPEN
        with unittest.mock.patch("access_control.circuit_breaker.time.monotonic", return_value=base_time + 61.0):
            self.assertFalse(cb.is_open())
            self.assertEqual(cb.state, CircuitBreaker.HALF_OPEN)
        # Failed probe re-opens the circuit
        with unittest.mock.patch("access_control.circuit_breaker.time.monotonic", return_value=base_time + 62.0):
            cb.record_failure()
        self.assertEqual(cb.state, CircuitBreaker.OPEN)
        # Recovery clock should have restarted from the probe failure time (base_time + 62.0)
        # Still OPEN just before new recovery_timeout elapses
        with unittest.mock.patch("access_control.circuit_breaker.time.monotonic", return_value=base_time + 62.0 + 59.0):
            self.assertTrue(cb.is_open())
        # HALF_OPEN after new recovery_timeout elapses
        with unittest.mock.patch("access_control.circuit_breaker.time.monotonic", return_value=base_time + 62.0 + 61.0):
            self.assertFalse(cb.is_open())
            self.assertEqual(cb.state, CircuitBreaker.HALF_OPEN)

    # ------------------------------------------------------------------
    # 8. Additional failures while OPEN do NOT reset the recovery clock
    # ------------------------------------------------------------------

    def test_open_does_not_reset_recovery_clock(self) -> None:
        """
        Extra record_failure() calls while already OPEN must not push _opened_at
        forward — the recovery timer must keep ticking from the original trip time.
        """
        cb = CircuitBreaker("test", failure_threshold=3, recovery_timeout=60.0)
        trip_time = 5000.0

        # Trip the circuit at trip_time
        with unittest.mock.patch("access_control.circuit_breaker.time.monotonic", return_value=trip_time):
            for _ in range(3):
                cb.record_failure()
        self.assertEqual(cb.state, CircuitBreaker.OPEN)

        # Record more failures while OPEN, far in the future — should NOT reset clock
        with unittest.mock.patch("access_control.circuit_breaker.time.monotonic", return_value=trip_time + 10.0):
            cb.record_failure()
            cb.record_failure()

        # At 59s after trip: still OPEN (not yet recovered)
        with unittest.mock.patch("access_control.circuit_breaker.time.monotonic", return_value=trip_time + 59.0):
            self.assertTrue(cb.is_open())

        # At 61s after trip: HALF_OPEN (recovery clock ticked from original trip)
        with unittest.mock.patch("access_control.circuit_breaker.time.monotonic", return_value=trip_time + 61.0):
            self.assertFalse(cb.is_open())
            self.assertEqual(cb.state, CircuitBreaker.HALF_OPEN)


class TestCircuitBreakerConcurrentProbeGuard(unittest.TestCase):
    """Audit 2026-05-24, clients-#9. Two callers must NOT both get a
    HALF_OPEN probe — only the first one gets through.
    """

    def test_only_first_caller_gets_half_open_probe(self):
        cb = CircuitBreaker("t", failure_threshold=1, recovery_timeout=60.0)
        # Trip to OPEN
        with unittest.mock.patch("access_control.circuit_breaker.time.monotonic", return_value=100.0):
            cb.record_failure()
        self.assertEqual(cb.state, CircuitBreaker.OPEN)

        # Recovery window has elapsed — first caller observes HALF_OPEN
        # and reserves the probe slot.
        with unittest.mock.patch("access_control.circuit_breaker.time.monotonic", return_value=170.0):
            first = cb.is_open()
            self.assertFalse(first)  # first caller may probe
            self.assertEqual(cb.state, CircuitBreaker.HALF_OPEN)

            # Concurrent caller (still inside the probe's in-flight window)
            # must see is_open() == True so it bails.
            second = cb.is_open()
            self.assertTrue(second)

        # Probe completes successfully — slot released, breaker closes.
        cb.record_success()
        self.assertEqual(cb.state, CircuitBreaker.CLOSED)

    def test_probe_failure_releases_slot_and_reopens(self):
        cb = CircuitBreaker("t", failure_threshold=1, recovery_timeout=60.0)
        with unittest.mock.patch("access_control.circuit_breaker.time.monotonic", return_value=100.0):
            cb.record_failure()

        with unittest.mock.patch("access_control.circuit_breaker.time.monotonic", return_value=170.0):
            self.assertFalse(cb.is_open())
            # Probe fails — back to OPEN, slot released for next cycle.
            cb.record_failure()
            self.assertEqual(cb.state, CircuitBreaker.OPEN)
            # _probe_in_flight cleared so the next recovery window can
            # legitimately HALF_OPEN again.
            self.assertFalse(cb._probe_in_flight)

    def test_aborted_probe_reopens_and_restarts_recovery_clock(self):
        cb = CircuitBreaker("t", failure_threshold=1, recovery_timeout=60.0)
        with unittest.mock.patch(
            "access_control.circuit_breaker.time.monotonic", return_value=100.0
        ):
            cb.record_failure()
        with unittest.mock.patch(
            "access_control.circuit_breaker.time.monotonic", return_value=170.0
        ):
            self.assertFalse(cb.is_open())
            self.assertEqual(cb.state, CircuitBreaker.HALF_OPEN)

        # Models cancellation or an unexpected exception after the probe slot
        # was reserved but before record_success/record_failure ran.
        with unittest.mock.patch(
            "access_control.circuit_breaker.time.monotonic", return_value=171.0
        ):
            cb.abort_probe()
        self.assertEqual(cb.state, CircuitBreaker.OPEN)
        self.assertFalse(cb._probe_in_flight)

        with unittest.mock.patch(
            "access_control.circuit_breaker.time.monotonic", return_value=230.0
        ):
            self.assertTrue(cb.is_open())
        with unittest.mock.patch(
            "access_control.circuit_breaker.time.monotonic", return_value=232.0
        ):
            self.assertFalse(cb.is_open())

    def test_abort_probe_is_noop_after_success(self):
        cb = CircuitBreaker("t", failure_threshold=1, recovery_timeout=1.0)
        with unittest.mock.patch(
            "access_control.circuit_breaker.time.monotonic", return_value=100.0
        ):
            cb.record_failure()
        with unittest.mock.patch(
            "access_control.circuit_breaker.time.monotonic", return_value=102.0
        ):
            self.assertFalse(cb.is_open())
        cb.record_success()

        cb.abort_probe()

        self.assertEqual(cb.state, CircuitBreaker.CLOSED)
        self.assertFalse(cb.is_open())
        self.assertFalse(cb._probe_in_flight)


if __name__ == "__main__":
    unittest.main()
