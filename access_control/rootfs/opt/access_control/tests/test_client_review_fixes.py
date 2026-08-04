"""Regressions for the 2026-08 client review fixes.

Covers:
- Protect REST 401 re-auth + non-200 logging (CLI-1)
- Protect WS deflated binary frames (CLI-2)
- Protect closed-client guard (CLI-3)
- Shared cached /api/states snapshot in HAClient (CLI-5)
- WS reconnect backoff only resets after a stable connection (CLI-7)
- list_visitors envelope handling (CLI-9)
- get_bootstrap envelope validation + tolerant topology walkers (CLI-10)
- ws_401_count resets on non-401 errors (CLI-12)
- status-only HA responses drain the body for keep-alive reuse (CLI-13)
"""
from __future__ import annotations

import asyncio
import json
import logging
import struct
import unittest
import zlib
from unittest.mock import AsyncMock, patch

import aiohttp

from access_control.access_client import AccessClient, AccessClientError
from access_control.ha_client import HAClient, _STATES_CACHE_TTL
from access_control.protect_client import ProtectClient

_MISSING = object()


class _Response:
    def __init__(self, *, status=200, payload=_MISSING, body="") -> None:
        self.status = status
        self._payload = {} if payload is _MISSING else payload
        self._body = body
        self.read_called = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    async def json(self, **_kwargs):
        return self._payload

    async def text(self):
        return self._body

    async def read(self):
        self.read_called = True
        return b""


class _RawResponse(_Response):
    """Response whose body cannot be decoded as JSON."""

    async def json(self, **_kwargs):
        raise ValueError("invalid or empty JSON")


def _ws_frame(payload: dict, *, deflated: bool) -> bytes:
    """Build one Protect binary WS frame (8-byte header + payload)."""
    raw = json.dumps(payload).encode()
    if deflated:
        raw = zlib.compress(raw)
    # packet type, payload format, deflated flag, reserved, size (uint32 BE)
    return bytes([1, 1, 1 if deflated else 0, 0]) + struct.pack(">I", len(raw)) + raw


def _ws_401() -> aiohttp.ClientResponseError:
    return aiohttp.ClientResponseError(request_info=None, history=(), status=401)


class ProtectRestReauthTests(unittest.IsolatedAsyncioTestCase):
    """CLI-1: a REST 401 must clear auth state and retry once after login."""

    @staticmethod
    def _client_with_responses(responses: list[_Response]):
        client = ProtectClient("unvr.local", "service", "secret")
        client._csrf_token = "stale-csrf"
        client._auth_cookie = "stale-cookie"

        class _Session:
            closed = False

            def __init__(self):
                self.calls = []

            def get(self_inner, url, **kwargs):
                self_inner.calls.append(kwargs)
                return responses.pop(0)

        session = _Session()
        client._session = session
        return client, session

    async def test_rest_401_reauthenticates_and_retries_once(self) -> None:
        cameras = [
            {
                "id": "cam-1",
                "name": "Door Cam",
                "type": "UVC G4 Doorbell",
                "featureFlags": {"isDoorbell": True},
                "isConnected": True,
            }
        ]
        client, session = self._client_with_responses(
            [_Response(status=401), _Response(payload=cameras)]
        )

        async def relogin() -> None:
            client._csrf_token = "fresh-csrf"
            client._auth_cookie = "fresh-cookie"

        client.login = AsyncMock(side_effect=relogin)

        result = await client.get_cameras()

        client.login.assert_awaited_once_with()
        self.assertEqual(len(session.calls), 2)
        # The retry must carry the re-authenticated credentials.
        retry_headers = session.calls[1]["headers"]
        self.assertEqual(retry_headers["X-CSRF-Token"], "fresh-csrf")
        self.assertEqual(retry_headers["Cookie"], "TOKEN=fresh-cookie")
        self.assertEqual(result[0]["id"], "cam-1")
        self.assertTrue(result[0]["is_doorbell"])

    async def test_persistent_401_returns_empty_after_single_retry(self) -> None:
        client, session = self._client_with_responses(
            [_Response(status=401), _Response(status=401)]
        )
        client.login = AsyncMock()

        with self.assertLogs("access_control.protect_client", level="WARNING"):
            result = await client.get_cameras()

        self.assertEqual(result, [])
        client.login.assert_awaited_once_with()
        self.assertEqual(len(session.calls), 2)

    async def test_non_200_is_logged_not_silent(self) -> None:
        client, _session = self._client_with_responses([_Response(status=502)])
        client.login = AsyncMock()

        with self.assertLogs(
            "access_control.protect_client", level="WARNING"
        ) as logs:
            result = await client.get_cameras()

        self.assertEqual(result, [])
        self.assertTrue(any("502" in line for line in logs.output))
        client.login.assert_not_awaited()


class ProtectWsDeflateTests(unittest.IsolatedAsyncioTestCase):
    """CLI-2: zlib-compressed action/data frames must decode and dispatch."""

    @staticmethod
    def _client_with_callback():
        client = ProtectClient("unvr.local", "service", "secret")
        events: list[dict] = []
        client.register_callback(events.append)
        return client, events

    async def test_compressed_two_frame_ring_event_fires_callback(self) -> None:
        client, events = self._client_with_callback()
        message = _ws_frame(
            {"action": "update", "modelKey": "event", "id": "evt-1"},
            deflated=True,
        ) + _ws_frame(
            {"type": "ring", "camera": "cam-9"},
            deflated=True,
        )

        client._parse_ws_message(message)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event"], "ring")
        self.assertEqual(events[0]["camera_id"], "cam-9")

    async def test_deflate_flag_is_checked_per_frame(self) -> None:
        """A plain action frame paired with a compressed data frame decodes."""
        client, events = self._client_with_callback()
        message = _ws_frame(
            {"action": "update", "modelKey": "event"},
            deflated=False,
        ) + _ws_frame(
            {
                "type": "nfcCardScanned",
                "camera": "cam-2",
                "metadata": {"nfc": {"nfcId": "card-1", "userId": "user-1"}},
            },
            deflated=True,
        )

        client._parse_ws_message(message)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event"], "nfc")
        self.assertEqual(events[0]["nfc_id"], "card-1")

    async def test_uncompressed_frames_still_parse(self) -> None:
        client, events = self._client_with_callback()
        message = _ws_frame(
            {"action": "update", "modelKey": "event"},
            deflated=False,
        ) + _ws_frame(
            {"type": "ring", "camera": "cam-3"},
            deflated=False,
        )

        client._parse_ws_message(message)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["camera_id"], "cam-3")

    async def test_repeated_parse_failures_escalate_log_level(self) -> None:
        client, events = self._client_with_callback()
        # Deflated flag set but the payload is not valid zlib data.
        garbage = bytes([1, 1, 1, 0]) + struct.pack(">I", 7) + b"garbage"

        with self.assertLogs(
            "access_control.protect_client", level="WARNING"
        ) as logs:
            for _ in range(5):
                client._parse_ws_message(garbage)

        self.assertEqual(events, [])
        self.assertEqual(client._ws_parse_failures, 5)
        levels = [record.levelno for record in logs.records]
        self.assertEqual(levels[:4], [logging.WARNING] * 4)
        self.assertEqual(levels[4], logging.ERROR)

    async def test_successful_parse_resets_failure_count(self) -> None:
        client, _events = self._client_with_callback()
        garbage = bytes([1, 1, 1, 0]) + struct.pack(">I", 7) + b"garbage"
        good = _ws_frame(
            {"action": "update", "modelKey": "event"}, deflated=True
        ) + _ws_frame({"type": "ring", "camera": "cam-1"}, deflated=True)

        with self.assertLogs("access_control.protect_client", level="WARNING"):
            client._parse_ws_message(garbage)
        self.assertEqual(client._ws_parse_failures, 1)

        client._parse_ws_message(good)
        self.assertEqual(client._ws_parse_failures, 0)


class ProtectClosedGuardTests(unittest.IsolatedAsyncioTestCase):
    """CLI-3: a closed client must never recreate a session or re-login."""

    async def test_closed_client_refuses_session_login_and_rest(self) -> None:
        client = ProtectClient("unvr.local", "service", "secret")
        await client.close()

        with self.assertRaisesRegex(RuntimeError, "closed"):
            client._get_session()
        with self.assertRaisesRegex(RuntimeError, "closed"):
            await client.login()
        with self.assertRaisesRegex(RuntimeError, "closed"):
            await client.get_cameras()
        self.assertIsNone(client._session)


class WsBackoffTests(unittest.IsolatedAsyncioTestCase):
    """CLI-7 + CLI-12 for both WS reconnect loops."""

    async def _run_loop(self, client, module: str, *, stable_secs: float):
        delays: list[float] = []

        async def fake_connect():
            return None

        async def fake_sleep(delay):
            delays.append(delay)
            if len(delays) >= 3:
                client._running = False

        client._ws_connect = fake_connect
        with patch(f"{module}._WS_STABLE_CONNECTION_SECS", stable_secs), patch(
            f"{module}.asyncio.sleep", new=fake_sleep
        ):
            client._running = True
            await client._ws_loop()
        return delays

    async def test_immediate_close_keeps_doubling_backoff_protect(self) -> None:
        client = ProtectClient("unvr.local", "service", "secret")
        delays = await self._run_loop(
            client, "access_control.protect_client", stable_secs=30.0
        )
        # Upgrade succeeds but the socket drops instantly (<30s) — the delay
        # must keep growing instead of resetting to the 5s base.
        self.assertEqual(delays[0], 5.0)
        self.assertGreaterEqual(delays[1], 7.5)
        self.assertGreaterEqual(delays[2], 11.25)

    async def test_immediate_close_keeps_doubling_backoff_access(self) -> None:
        client = AccessClient("unvr.local", "service", "secret")
        delays = await self._run_loop(
            client, "access_control.access_client", stable_secs=30.0
        )
        self.assertEqual(delays[0], 5.0)
        self.assertGreaterEqual(delays[1], 7.5)
        self.assertGreaterEqual(delays[2], 11.25)

    async def test_stable_connection_resets_backoff(self) -> None:
        for client, module in (
            (
                ProtectClient("unvr.local", "service", "secret"),
                "access_control.protect_client",
            ),
            (
                AccessClient("unvr.local", "service", "secret"),
                "access_control.access_client",
            ),
        ):
            with self.subTest(module=module):
                # Threshold 0 ⇒ every successful connect counts as stable.
                delays = await self._run_loop(client, module, stable_secs=0.0)
                for delay in delays:
                    self.assertLessEqual(delay, 5.0 * 1.25)

    async def _run_error_loop(self, client, errors: list[BaseException]):
        async def fake_connect():
            if errors:
                raise errors.pop(0)
            client._running = False

        client._ws_connect = fake_connect
        with patch("asyncio.sleep", new=AsyncMock()):
            client._running = True
            await client._ws_loop()

    async def test_non_consecutive_401s_do_not_latch_permanent_failure(
        self,
    ) -> None:
        for client in (
            ProtectClient("unvr.local", "service", "secret"),
            AccessClient("unvr.local", "service", "secret"),
        ):
            with self.subTest(client=type(client).__name__):
                # Six upgrade-401s, each followed by an ordinary network
                # error — more than the latch threshold in total, but never
                # consecutive, so the latch must not trip.
                errors: list[BaseException] = []
                for _ in range(6):
                    errors.extend([_ws_401(), OSError("network blip")])
                await self._run_error_loop(client, errors)
                self.assertFalse(client._auth_permanently_failed)

    async def test_consecutive_401s_still_latch_permanent_failure(self) -> None:
        for client in (
            ProtectClient("unvr.local", "service", "secret"),
            AccessClient("unvr.local", "service", "secret"),
        ):
            with self.subTest(client=type(client).__name__):
                await self._run_error_loop(
                    client, [_ws_401() for _ in range(5)]
                )
                self.assertTrue(client._auth_permanently_failed)


class ListVisitorsEnvelopeTests(unittest.IsolatedAsyncioTestCase):
    """CLI-9: list_visitors must handle list/dict envelopes and bad JSON."""

    @staticmethod
    def _client(response) -> AccessClient:
        client = AccessClient("unvr.local", "service", "secret")
        client._request = AsyncMock(return_value=response)
        return client

    async def test_dict_envelope_returns_data_list(self) -> None:
        visitors = [{"unique_id": "v-1"}]
        client = self._client(_Response(payload={"data": visitors}))
        self.assertEqual(await client.list_visitors(), visitors)

    async def test_top_level_list_is_returned_directly(self) -> None:
        visitors = [{"unique_id": "v-2"}]
        client = self._client(_Response(payload=visitors))
        self.assertEqual(await client.list_visitors(), visitors)

    async def test_null_data_raises_access_client_error(self) -> None:
        client = self._client(_Response(payload={"data": None}))
        with self.assertRaisesRegex(AccessClientError, "invalid visitor list"):
            await client.list_visitors()

    async def test_null_payload_raises_access_client_error(self) -> None:
        client = self._client(_Response(payload=None))
        with self.assertRaisesRegex(AccessClientError, "invalid visitor list"):
            await client.list_visitors()

    async def test_invalid_json_is_wrapped(self) -> None:
        client = self._client(_RawResponse(body="{not-json"))
        with self.assertRaisesRegex(AccessClientError, "invalid JSON"):
            await client.list_visitors()


class BootstrapValidationTests(unittest.IsolatedAsyncioTestCase):
    """CLI-10: get_bootstrap envelope validation + tolerant walkers."""

    @staticmethod
    def _client(response) -> AccessClient:
        client = AccessClient("unvr.local", "service", "secret")
        client._request = AsyncMock(return_value=response)
        return client

    async def test_valid_dict_envelope_passes_through(self) -> None:
        payload = {"data": [{"unique_id": "b-1"}]}
        client = self._client(_Response(payload=payload))
        self.assertEqual(await client.get_bootstrap(), payload)

    async def test_top_level_list_passes_through(self) -> None:
        payload = [{"unique_id": "b-1"}]
        client = self._client(_Response(payload=payload))
        self.assertEqual(await client.get_bootstrap(), payload)

    async def test_null_data_raises_access_client_error(self) -> None:
        client = self._client(_Response(payload={"data": None}))
        with self.assertRaisesRegex(AccessClientError, "invalid topology"):
            await client.get_bootstrap()

    async def test_non_dict_payload_raises_access_client_error(self) -> None:
        client = self._client(_Response(payload="nope"))
        with self.assertRaisesRegex(AccessClientError, "invalid topology"):
            await client.get_bootstrap()

    async def test_invalid_json_is_wrapped(self) -> None:
        client = self._client(_RawResponse(body="{not-json"))
        with self.assertRaisesRegex(AccessClientError, "invalid JSON"):
            await client.get_bootstrap()

    def test_walkers_tolerate_malformed_rows(self) -> None:
        client = AccessClient("unvr.local", "service", "secret")
        bootstrap = {
            "data": [
                "junk",
                {"floors": None},
                {
                    "floors": [
                        "junk",
                        {
                            "doors": [
                                None,
                                {
                                    "unique_id": "door-1",
                                    "name": "Front",
                                    "device_groups": [
                                        [
                                            "junk",
                                            {
                                                "device_type": "UAH",
                                                "unique_id": "dev-1",
                                                "alias": "Front Hub",
                                            },
                                        ]
                                    ],
                                },
                                {
                                    "unique_id": "door-2",
                                    "name": "Back",
                                    "device_groups": None,
                                },
                            ]
                        },
                    ]
                },
            ]
        }

        devices = client.parse_doors_and_devices(bootstrap)
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["device_id"], "dev-1")
        self.assertEqual(devices[0]["door_name"], "Front")

        locations = client.parse_door_locations(bootstrap)
        self.assertEqual(
            [loc["id"] for loc in locations], ["door-1", "door-2"]
        )

    def test_walkers_tolerate_null_data(self) -> None:
        client = AccessClient("unvr.local", "service", "secret")
        self.assertEqual(client.parse_doors_and_devices({"data": None}), [])
        self.assertEqual(client.parse_door_locations({"data": None}), [])


class _StatesSession:
    closed = False

    def __init__(self, payload) -> None:
        self.calls = 0
        self._payload = payload

    def get(self, url, **_kwargs):
        assert url.endswith("/api/states"), url
        self.calls += 1
        return _Response(payload=self._payload)


class HAStatesCacheTests(unittest.IsolatedAsyncioTestCase):
    """CLI-5: one shared /api/states download serves all three getters."""

    _PAYLOAD = [
        {
            "entity_id": "lock.front_door",
            "state": "locked",
            "attributes": {"friendly_name": "Front Door"},
        },
        {
            "entity_id": "camera.doorbell",
            "state": "idle",
            "attributes": {"friendly_name": "Doorbell"},
        },
        {
            "entity_id": "alarm_control_panel.home",
            "state": "disarmed",
            "attributes": {
                "friendly_name": "Home Alarm",
                "code_arm_required": True,
                "supported_features": 3,
            },
        },
        {"entity_id": "light.hall", "state": "on", "attributes": {}},
    ]

    async def test_three_getters_share_one_download(self) -> None:
        client = HAClient("http://ha.local", "token")
        session = _StatesSession(self._PAYLOAD)
        client._session = session

        locks = await client.get_lock_entities()
        cameras = await client.get_camera_entities()
        alarms = await client.get_alarm_entities()

        self.assertEqual(session.calls, 1)
        self.assertEqual(
            locks,
            [
                {
                    "entity_id": "lock.front_door",
                    "friendly_name": "Front Door",
                    "state": "locked",
                }
            ],
        )
        self.assertEqual(
            [c["entity_id"] for c in cameras], ["camera.doorbell"]
        )
        self.assertEqual(
            alarms,
            [
                {
                    "entity_id": "alarm_control_panel.home",
                    "friendly_name": "Home Alarm",
                    "state": "disarmed",
                    "code_arm_required": True,
                    "supported_features": 3,
                }
            ],
        )

    async def test_expired_ttl_refetches(self) -> None:
        client = HAClient("http://ha.local", "token")
        session = _StatesSession(self._PAYLOAD)
        client._session = session

        await client.get_lock_entities()
        self.assertEqual(session.calls, 1)

        # Within the TTL: served from cache.
        await client.get_lock_entities()
        self.assertEqual(session.calls, 1)

        client._states_cache_at -= _STATES_CACHE_TTL + 1
        await client.get_lock_entities()
        self.assertEqual(session.calls, 2)

    async def test_non_list_payload_yields_empty_and_no_poisoned_cache(
        self,
    ) -> None:
        client = HAClient("http://ha.local", "token")
        session = _StatesSession({"unexpected": "object"})
        client._session = session

        with self.assertLogs("access_control.ha_client", level="WARNING"):
            self.assertEqual(await client.get_lock_entities(), [])
        self.assertIsNone(client._states_cache)


class HAKeepAliveBodyDrainTests(unittest.IsolatedAsyncioTestCase):
    """CLI-13: status-only responses must read the body for pool reuse."""

    @staticmethod
    def _client_with_response(response: _Response):
        client = HAClient("http://ha.local", "token")

        class _Session:
            closed = False

            def get(self_inner, *_args, **_kwargs):
                return response

            def post(self_inner, *_args, **_kwargs):
                return response

        client._session = _Session()
        return client

    async def test_test_connection_drains_body(self) -> None:
        response = _Response(status=200)
        client = self._client_with_response(response)
        self.assertTrue(await client.test_connection())
        self.assertTrue(response.read_called)

    async def test_call_service_drains_body(self) -> None:
        response = _Response(status=200)
        client = self._client_with_response(response)
        self.assertTrue(await client._call_service("lock", "unlock", "lock.x"))
        self.assertTrue(response.read_called)

    async def test_fire_event_drains_body(self) -> None:
        response = _Response(status=200)
        client = self._client_with_response(response)
        self.assertTrue(await client.fire_event("test_event", {"k": "v"}))
        self.assertTrue(response.read_called)


if __name__ == "__main__":
    unittest.main()
