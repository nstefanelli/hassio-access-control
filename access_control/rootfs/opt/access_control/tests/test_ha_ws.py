"""Unit tests for HAClient WebSocket push support (CLI-6).

The client subscribes to Home Assistant ``state_changed`` events over the
WS API instead of REST-polling every 5 seconds. These tests fake the
aiohttp session/WebSocket pair and script the HA handshake protocol
(auth_required → auth → auth_ok/auth_invalid → subscribe_events → result).
"""
from __future__ import annotations

import asyncio
import importlib
import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import aiohttp

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
HAClientError = HA_CLIENT_MODULE.HAClientError

_ENV = "ACCESS_CONTROL_HA_TOKEN"
_MODULE = "access_control.ha_client"


# ----------------------------------------------------------------------
# Doubles
# ----------------------------------------------------------------------


class _WSMessage:
    def __init__(self, type_, data=None) -> None:
        self.type = type_
        self.data = data


class FakeHAWebSocket:
    """Scripted double for HA's WS endpoint speaking the auth protocol.

    Sends ``auth_required`` on connect; answers a client ``auth`` with
    ``auth_ok``/``auth_invalid`` and a ``subscribe_events`` with a
    ``result`` frame, then feeds the scripted events. With
    ``keep_open=True`` the socket stays open (tests feed/close manually).
    """

    def __init__(
        self,
        *,
        auth_ok: bool = True,
        subscribe_ok: bool = True,
        events: tuple | list = (),
        keep_open: bool = False,
        auto_ack_subscribe: bool = True,
    ) -> None:
        self._queue: asyncio.Queue = asyncio.Queue()
        self.sent: list[dict] = []
        self.closed = False
        self._auth_ok = auth_ok
        self._subscribe_ok = subscribe_ok
        self._events = list(events)
        self._keep_open = keep_open
        self._auto_ack_subscribe = auto_ack_subscribe
        self.feed_json({"type": "auth_required"})

    # -- server-side script controls ----------------------------------

    def feed_json(self, payload: object) -> None:
        self.feed_text(json.dumps(payload))

    def feed_text(self, data: str) -> None:
        self._queue.put_nowait(_WSMessage(aiohttp.WSMsgType.TEXT, data))

    def feed_closed(self) -> None:
        self._queue.put_nowait(_WSMessage(aiohttp.WSMsgType.CLOSED))

    def ack_subscribe(self, sub_id: int = 1) -> None:
        self.feed_json({"id": sub_id, "type": "result", "success": self._subscribe_ok})
        if self._subscribe_ok:
            for event in self._events:
                if isinstance(event, str):
                    self.feed_text(event)
                else:
                    self.feed_json(event)
            if not self._keep_open:
                self.feed_closed()

    # -- aiohttp ClientWebSocketResponse surface -----------------------

    async def receive(self):
        return await self._queue.get()

    async def send_json(self, payload: dict) -> None:
        self.sent.append(payload)
        if payload.get("type") == "auth":
            self.feed_json({"type": "auth_ok"} if self._auth_ok else {"type": "auth_invalid"})
        elif payload.get("type") == "subscribe_events" and self._auto_ack_subscribe:
            self.ack_subscribe(payload["id"])

    def __aiter__(self):
        return self

    async def __anext__(self):
        return await self._queue.get()

    async def close(self) -> None:
        self.closed = True


class FakeSession:
    """aiohttp.ClientSession double exposing only what HAClient touches."""

    def __init__(self, ws_factory) -> None:
        self._ws_factory = ws_factory
        self.closed = False
        self.ws_urls: list[str] = []
        self.ws_kwargs: list[dict] = []
        self.websockets: list[FakeHAWebSocket] = []

    async def ws_connect(self, url, **kwargs):
        self.ws_urls.append(url)
        self.ws_kwargs.append(kwargs)
        ws = self._ws_factory()
        if isinstance(ws, BaseException):
            raise ws
        self.websockets.append(ws)
        return ws

    async def close(self) -> None:
        self.closed = True


class Recorder:
    """Async state_changed callback that records its invocations."""

    def __init__(self, raise_for: set[str] | None = None) -> None:
        self.calls: list[tuple[str, str | None, str | None]] = []
        self._raise_for = raise_for or set()

    async def __call__(self, entity_id, old_state, new_state) -> None:
        self.calls.append((entity_id, old_state, new_state))
        if entity_id in self._raise_for:
            raise RuntimeError(f"consumer broke on {entity_id}")


def state_changed_event(entity_id: str, old: str | None, new: str | None) -> dict:
    def state_obj(state):
        if state is None:
            return None
        return {"entity_id": entity_id, "state": state, "attributes": {}}

    return {
        "id": 1,
        "type": "event",
        "event": {
            "event_type": "state_changed",
            "data": {
                "entity_id": entity_id,
                "old_state": state_obj(old),
                "new_state": state_obj(new),
            },
        },
    }


async def _wait_for(predicate, timeout: float = 2.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not predicate():
        if loop.time() > deadline:
            raise AssertionError("condition not met within timeout")
        await asyncio.sleep(0.01)


class _WSTestCase(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self._saved_env = os.environ.pop(_ENV, None)
        self._clients: list = []

    async def asyncTearDown(self) -> None:
        for client in self._clients:
            await client.stop_websocket()

    def tearDown(self) -> None:
        os.environ.pop(_ENV, None)
        if self._saved_env is not None:
            os.environ[_ENV] = self._saved_env

    def make_client(self, ws_factory, url: str = "http://supervisor/core"):
        client = HAClient(url, "token")
        client._session = FakeSession(ws_factory)
        self._clients.append(client)
        return client


# ----------------------------------------------------------------------
# Handshake, subscription, and dispatch
# ----------------------------------------------------------------------


class TestHandshakeAndDispatch(_WSTestCase):
    async def test_handshake_subscribe_and_event_dispatch(self) -> None:
        ws = FakeHAWebSocket(
            keep_open=True,
            events=[
                state_changed_event("lock.front_door", "locked", "unlocked"),
                # old_state null: brand-new entity
                state_changed_event("lock.side_door", None, "locked"),
            ],
        )
        client = self.make_client(lambda: ws)
        recorder = Recorder()
        client.start_websocket(recorder)

        await _wait_for(lambda: len(recorder.calls) == 2)
        self.assertTrue(client.ws_connected)
        self.assertEqual(
            recorder.calls,
            [
                ("lock.front_door", "locked", "unlocked"),
                ("lock.side_door", None, "locked"),
            ],
        )
        # Supervisor-proxy URL derivation + liveness heartbeat.
        self.assertEqual(client._session.ws_urls, ["ws://supervisor/core/websocket"])
        self.assertEqual(client._session.ws_kwargs[0].get("heartbeat"), 30)
        # Exact protocol frames sent.
        self.assertEqual(ws.sent[0], {"type": "auth", "access_token": "token"})
        self.assertEqual(
            ws.sent[1],
            {"id": 1, "type": "subscribe_events", "event_type": "state_changed"},
        )

        await client.stop_websocket()
        self.assertFalse(client.ws_connected)
        self.assertIsNone(client._ws_task)

    async def test_env_token_is_used_for_auth(self) -> None:
        os.environ[_ENV] = "fresh-supervisor-token"
        ws = FakeHAWebSocket(keep_open=True)
        client = self.make_client(lambda: ws)
        client.start_websocket(Recorder())

        await _wait_for(lambda: client.ws_connected)
        self.assertEqual(
            ws.sent[0], {"type": "auth", "access_token": "fresh-supervisor-token"}
        )

    async def test_ws_connected_only_after_subscription_ack(self) -> None:
        ws = FakeHAWebSocket(keep_open=True, auto_ack_subscribe=False)
        client = self.make_client(lambda: ws)
        client.start_websocket(Recorder())

        # Authenticated and subscribe sent, but no result yet → not connected.
        await _wait_for(lambda: len(ws.sent) == 2)
        self.assertFalse(client.ws_connected)

        ws.ack_subscribe()
        await _wait_for(lambda: client.ws_connected)

    async def test_url_derivation_direct_vs_supervisor(self) -> None:
        cases = [
            ("http://supervisor/core", "ws://supervisor/core/websocket"),
            ("http://supervisor/core/", "ws://supervisor/core/websocket"),
            ("http://192.168.1.10:8123", "ws://192.168.1.10:8123/api/websocket"),
            ("https://ha.example.com:8123/", "wss://ha.example.com:8123/api/websocket"),
            ("https://supervisor/core", "wss://supervisor/core/websocket"),
        ]
        for url, expected in cases:
            with self.subTest(url=url):
                self.assertEqual(HAClient(url, "token")._ws_url(), expected)

    async def test_subscription_rejected_raises_and_stays_disconnected(self) -> None:
        ws = FakeHAWebSocket(subscribe_ok=False)
        client = self.make_client(lambda: ws)
        with self.assertRaisesRegex(HAClientError, "subscription"):
            await client._ws_connect()
        self.assertFalse(client.ws_connected)

    async def test_auth_invalid_logs_error_and_raises(self) -> None:
        ws = FakeHAWebSocket(auth_ok=False)
        client = self.make_client(lambda: ws)
        with self.assertLogs(_MODULE, level="ERROR") as logs:
            with self.assertRaisesRegex(HAClientError, "authentication"):
                await client._ws_connect()
        self.assertTrue(any("auth_invalid" in line for line in logs.output))
        self.assertFalse(client.ws_connected)
        # A WS auth failure must not flip REST health or the circuit breaker.
        self.assertEqual(client.circuit_state, "closed")
        self.assertFalse(client.connected)


# ----------------------------------------------------------------------
# Event robustness
# ----------------------------------------------------------------------


class TestEventRobustness(_WSTestCase):
    async def test_malformed_events_skipped_without_killing_loop(self) -> None:
        malformed = [
            "this is not json {{",
            json.dumps([1, 2, 3]),  # non-dict payload
            json.dumps({"type": "pong", "id": 7}),  # ignored type
            json.dumps({"type": "event"}),  # no event body
            json.dumps({"type": "event", "event": {"event_type": "call_service"}}),
            json.dumps(
                {"type": "event", "event": {"event_type": "state_changed", "data": None}}
            ),
            json.dumps(
                {
                    "type": "event",
                    "event": {"event_type": "state_changed", "data": {"old_state": {}}},
                }
            ),  # missing entity_id
            json.dumps(
                {
                    "type": "event",
                    "event": {
                        "event_type": "state_changed",
                        "data": {"entity_id": 42, "new_state": {"state": "on"}},
                    },
                }
            ),  # non-string entity_id
        ]
        good = state_changed_event("lock.front_door", "unlocked", "locked")
        # Non-dict old_state and non-string state values degrade to None.
        odd_states = {
            "type": "event",
            "event": {
                "event_type": "state_changed",
                "data": {
                    "entity_id": "lock.garage",
                    "old_state": "weird",
                    "new_state": {"state": 7},
                },
            },
        }
        ws = FakeHAWebSocket(
            keep_open=True, events=[*malformed, good, odd_states]
        )
        client = self.make_client(lambda: ws)
        recorder = Recorder()
        client.start_websocket(recorder)

        await _wait_for(lambda: len(recorder.calls) == 2)
        self.assertEqual(
            recorder.calls,
            [
                ("lock.front_door", "unlocked", "locked"),
                ("lock.garage", None, None),
            ],
        )
        # The loop survived every malformed frame.
        self.assertTrue(client.ws_connected)

    async def test_callback_exception_is_logged_not_fatal(self) -> None:
        ws = FakeHAWebSocket(
            keep_open=True,
            events=[
                state_changed_event("lock.broken", "locked", "unlocked"),
                state_changed_event("lock.fine", "unlocked", "locked"),
            ],
        )
        client = self.make_client(lambda: ws)
        recorder = Recorder(raise_for={"lock.broken"})
        with self.assertLogs(_MODULE, level="ERROR") as logs:
            client.start_websocket(recorder)
            await _wait_for(lambda: len(recorder.calls) == 2)
        self.assertTrue(
            any("state_changed callback failed" in line for line in logs.output)
        )
        # Second event was still delivered and the connection is still up.
        self.assertEqual(recorder.calls[1], ("lock.fine", "unlocked", "locked"))
        self.assertTrue(client.ws_connected)

    async def test_reregister_replaces_callback_and_keeps_task(self) -> None:
        ws = FakeHAWebSocket(keep_open=True)
        client = self.make_client(lambda: ws)
        first, second = Recorder(), Recorder()

        client.start_websocket(first)
        await _wait_for(lambda: client.ws_connected)
        task = client._ws_task

        client.start_websocket(second)  # idempotent: task keeps running
        self.assertIs(client._ws_task, task)

        ws.feed_json(state_changed_event("lock.front_door", "locked", "unlocked"))
        await _wait_for(lambda: len(second.calls) == 1)
        self.assertEqual(first.calls, [])


# ----------------------------------------------------------------------
# Reconnect / backoff policy (loop driven directly, sleep patched — the
# same style as the AccessClient/ProtectClient backoff regressions)
# ----------------------------------------------------------------------


class TestReconnectBackoff(_WSTestCase):
    async def _run_loop(self, client, connect, *, stable_secs, cycles=5):
        delays: list[float] = []

        async def fake_sleep(delay):
            delays.append(delay)
            if len(delays) >= cycles:
                client._ws_running = False

        client._ws_connect = connect
        with patch(f"{_MODULE}._WS_STABLE_CONNECTION_SECS", stable_secs), patch(
            f"{_MODULE}.asyncio.sleep", new=fake_sleep
        ):
            client._ws_running = True
            await client._ws_loop()
        return delays

    async def test_immediate_close_keeps_doubling_backoff(self) -> None:
        client = self.make_client(lambda: FakeHAWebSocket())

        async def immediate_close():
            return None

        # A connect that returns instantly never reaches the stability
        # threshold, so the delay must keep doubling (within ±25% jitter).
        delays = await self._run_loop(client, immediate_close, stable_secs=30.0)
        self.assertEqual(delays[0], 5.0)
        for previous, current in zip(delays, delays[1:]):
            self.assertGreaterEqual(current, previous * 2 * 0.75)
            self.assertLessEqual(current, previous * 2 * 1.25)

    async def test_stable_connection_resets_backoff(self) -> None:
        client = self.make_client(lambda: FakeHAWebSocket())

        async def immediate_close():
            return None

        # With the stability threshold at 0 every cycle counts as stable, so
        # the delay resets to base each time (jitter only ever applies to the
        # next computed delay, which gets clamped back to 5).
        delays = await self._run_loop(client, immediate_close, stable_secs=0.0)
        for delay in delays:
            self.assertLessEqual(delay, 5.0 * 1.25)

    async def test_auth_invalid_backs_off_and_retries_without_latch(self) -> None:
        client = self.make_client(lambda: FakeHAWebSocket())
        attempts = 0

        async def flaky_auth():
            nonlocal attempts
            attempts += 1
            if attempts <= 3:
                raise HAClientError("HA WebSocket authentication failed")
            client._ws_running = False  # token rotated back in — recovered

        await self._run_loop(client, flaky_auth, stable_secs=30.0, cycles=99)
        # Three auth_invalid cycles then a clean connect: the loop retried
        # every time instead of latching a permanent auth failure.
        self.assertEqual(attempts, 4)

    async def test_loop_exits_promptly_when_client_closing(self) -> None:
        client = self.make_client(lambda: FakeHAWebSocket())

        async def connect_then_close():
            client._closing = True

        delays = await self._run_loop(
            client, connect_then_close, stable_secs=30.0, cycles=99
        )
        self.assertEqual(delays, [])  # no reconnect sleep after close began


# ----------------------------------------------------------------------
# Lifecycle
# ----------------------------------------------------------------------


class TestLifecycle(_WSTestCase):
    async def test_stop_websocket_is_idempotent(self) -> None:
        client = self.make_client(lambda: FakeHAWebSocket(keep_open=True))
        await client.stop_websocket()  # never started — safe

        client.start_websocket(Recorder())
        await _wait_for(lambda: client.ws_connected)
        await client.stop_websocket()
        await client.stop_websocket()
        self.assertFalse(client.ws_connected)
        self.assertIsNone(client._ws_task)

    async def test_stop_websocket_mid_handshake(self) -> None:
        ws = FakeHAWebSocket(keep_open=True, auto_ack_subscribe=False)
        client = self.make_client(lambda: ws)
        client.start_websocket(Recorder())
        await _wait_for(lambda: len(ws.sent) == 2)  # blocked awaiting the ack
        await asyncio.wait_for(client.stop_websocket(), timeout=2)
        self.assertFalse(client.ws_connected)
        self.assertTrue(ws.closed)

    async def test_close_stops_websocket(self) -> None:
        ws = FakeHAWebSocket(keep_open=True)
        client = self.make_client(lambda: ws)
        client.start_websocket(Recorder())
        await _wait_for(lambda: client.ws_connected)

        session = client._session
        await asyncio.wait_for(client.close(), timeout=2)

        self.assertTrue(client._closed)
        self.assertFalse(client.ws_connected)
        self.assertIsNone(client._ws_task)
        self.assertTrue(ws.closed)
        self.assertTrue(session.closed)

    async def test_start_on_closed_client_is_a_noop(self) -> None:
        client = self.make_client(lambda: FakeHAWebSocket(keep_open=True))
        await client.close()

        client.start_websocket(Recorder())
        self.assertIsNone(client._ws_task)
        self.assertFalse(client.ws_connected)

    async def test_ws_disconnect_does_not_touch_rest_connected_flag(self) -> None:
        ws = FakeHAWebSocket(keep_open=True)
        client = self.make_client(lambda: ws)
        client._connected = True  # REST health probe owns this
        client.start_websocket(Recorder())
        await _wait_for(lambda: client.ws_connected)

        ws.feed_closed()
        await _wait_for(lambda: not client.ws_connected)
        self.assertTrue(client.connected)  # untouched by the WS observation
        self.assertEqual(client.circuit_state, "closed")


if __name__ == "__main__":
    unittest.main()
