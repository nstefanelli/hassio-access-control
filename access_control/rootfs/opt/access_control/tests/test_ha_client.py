"""Unit tests for HAClient credential resolution (env-first token).

Regression for 2026-07-05: the Supervisor token is rotated periodically and
re-exported as ACCESS_CONTROL_HA_TOKEN. HAClient captured it at construction,
so after a rotation every lock/unlock 401'd until an add-on restart. _headers()
must resolve the token env-first on every call.
"""
from __future__ import annotations

import asyncio
import importlib
import importlib.util
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load_package() -> None:
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
HA_CLIENT_MODULE = importlib.import_module("access_control.ha_client")
HAClient = HA_CLIENT_MODULE.HAClient

_ENV = "ACCESS_CONTROL_HA_TOKEN"


class TestHAClientTokenResolution(unittest.TestCase):
    def setUp(self) -> None:
        self._saved = os.environ.pop(_ENV, None)

    def tearDown(self) -> None:
        os.environ.pop(_ENV, None)
        if self._saved is not None:
            os.environ[_ENV] = self._saved

    def test_uses_db_token_when_env_unset(self) -> None:
        """Non-Supervisor deployment: fall back to the construction token."""
        client = HAClient("http://supervisor/core", "db-token")
        self.assertEqual(client._headers()["Authorization"], "Bearer db-token")

    def test_env_token_shadows_construction_token(self) -> None:
        client = HAClient("http://supervisor/core", "stale-db-token")
        os.environ[_ENV] = "fresh-supervisor-token"
        self.assertEqual(
            client._headers()["Authorization"], "Bearer fresh-supervisor-token"
        )

    def test_rotation_picked_up_without_reconstruction(self) -> None:
        """The whole point: a rotated env token wins on the very next call."""
        client = HAClient("http://supervisor/core", "ignored")
        os.environ[_ENV] = "token-v1"
        self.assertEqual(client._headers()["Authorization"], "Bearer token-v1")
        os.environ[_ENV] = "token-v2"  # Supervisor rotated it mid-run
        self.assertEqual(client._headers()["Authorization"], "Bearer token-v2")


class TestHAClientHealthCircuitRecovery(unittest.IsolatedAsyncioTestCase):
    async def test_successful_health_probe_closes_open_circuit(self) -> None:
        class Response:
            status = 200

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            async def read(self):
                return b""

        class Session:
            closed = False

            def get(self, *args, **kwargs):
                return Response()

        client = HAClient("http://supervisor/core", "token")
        client._session = Session()
        for _ in range(3):
            client._circuit.record_failure()
        self.assertEqual(client.circuit_state, "open")

        self.assertTrue(await client.test_connection())

        self.assertTrue(client.connected)
        self.assertEqual(client.circuit_state, "closed")


class TestHAClientLifetime(unittest.IsolatedAsyncioTestCase):
    async def test_close_drains_operation_lease_and_prevents_reopen(self) -> None:
        client = HAClient("http://ha.local", "token")
        lease_started = asyncio.Event()
        release_lease = asyncio.Event()

        async def use_exact_client() -> None:
            async with client.operation_lease():
                lease_started.set()
                await release_lease.wait()

        operation = asyncio.create_task(use_exact_client())
        await lease_started.wait()
        closing = asyncio.create_task(client.close())
        await asyncio.sleep(0)

        self.assertFalse(closing.done())
        self.assertFalse(client._closed)

        release_lease.set()
        await operation
        await closing
        self.assertTrue(client._closed)
        self.assertEqual(client._active_operations, 0)

        # Some full-suite regressions reload this module to isolate environment
        # state. Resolve the current exception class from the shared module
        # object so the assertion is not coupled to a pre-reload class identity.
        with self.assertRaisesRegex(HA_CLIENT_MODULE.HAClientError, "closed"):
            await client._ensure_session()
        with self.assertRaisesRegex(HA_CLIENT_MODULE.HAClientError, "closing"):
            async with client.operation_lease():
                pass

    async def test_cancelled_close_still_drains_active_lease(self) -> None:
        client = HAClient("http://ha.local", "token")
        lease_started = asyncio.Event()
        release_lease = asyncio.Event()

        async def use_exact_client() -> None:
            async with client.operation_lease():
                lease_started.set()
                await release_lease.wait()

        operation = asyncio.create_task(use_exact_client())
        await lease_started.wait()
        closing = asyncio.create_task(client.close())
        while not client._closing:
            await asyncio.sleep(0)

        closing.cancel()
        release_lease.set()
        await operation
        with self.assertRaises(asyncio.CancelledError):
            await closing

        self.assertTrue(client._closed)
        self.assertEqual(client._active_operations, 0)
        await client.close()

    async def test_cancellation_during_lease_release_does_not_hang_close(
        self,
    ) -> None:
        """Regression: a cancellation delivered while the lease's finally
        block waits on the lifecycle Condition used to abandon the decrement,
        leaking the lease count so _close_impl's drain loop hung forever."""
        client = HAClient("http://ha.local", "token")
        lease_started = asyncio.Event()

        async def use_exact_client() -> None:
            async with client.operation_lease():
                lease_started.set()
                await asyncio.Event().wait()  # cancelled here

        operation = asyncio.create_task(use_exact_client())
        await lease_started.wait()

        # Hold the lifecycle lock so the finally-block release must wait on
        # it, then deliver the cancellations: the first lands in the lease
        # body, the second while the release is blocked on the lock.
        async with client._lifecycle:
            operation.cancel()
            await asyncio.sleep(0)
            operation.cancel()
            await asyncio.sleep(0)

        with self.assertRaises(asyncio.CancelledError):
            await operation

        await asyncio.wait_for(client.close(), timeout=1)
        self.assertTrue(client._closed)
        self.assertEqual(client._active_operations, 0)


if __name__ == "__main__":
    unittest.main()
