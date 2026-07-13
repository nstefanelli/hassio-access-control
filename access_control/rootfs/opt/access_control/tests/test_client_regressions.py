"""Focused regressions for upstream client session handling."""
from __future__ import annotations

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from access_control.access_client import AccessClient, AccessClientError


class _Response:
    def __init__(self, *, status=200, headers=None, payload=None) -> None:
        self.status = status
        self.headers = headers or {}
        self._payload = payload or {}
        self.connection = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    async def json(self, **_kwargs):
        return self._payload

    async def text(self):
        return ""


class _IdentitySession:
    closed = False

    def __init__(self, identities: list[object], gate: asyncio.Event | None = None):
        self.identities = iter(identities)
        self.gate = gate
        self.cookie_jar = MagicMock()

    def post(self, *_args, **_kwargs):
        return _Response(
            headers={
                "X-CSRF-Token": "csrf",
                "Set-Cookie": "TOKEN=cookie; Path=/; Secure",
            }
        )

    def get(self, *_args, **_kwargs):
        identity = next(self.identities)
        gate = self.gate

        class _GatedResponse(_Response):
            async def __aenter__(self_inner):
                if gate is not None:
                    gate.set()
                    await asyncio.sleep(0.05)
                return self_inner

        payload = (
            identity
            if isinstance(identity, dict)
            else {"data": {"site_id": identity}}
        )
        return _GatedResponse(payload=payload)


class _FallbackIdentitySession(_IdentitySession):
    """Emulate older firmware without the optional access-info endpoint."""

    def __init__(self, *, info_status=404, topology_status=200):
        super().__init__([])
        self.info_status = info_status
        self.topology_status = topology_status
        self.topology_requests = 0

    def get(self, url, *_args, **_kwargs):
        if url.endswith("/access/info"):
            return _Response(status=self.info_status)
        self.topology_requests += 1
        return _Response(
            status=self.topology_status,
            payload={"data": [{"unique_id": "building-stable"}]},
        )


class AccessClientRequestTests(unittest.IsolatedAsyncioTestCase):
    async def test_rest_401_releases_synchronously_then_reauthenticates(self) -> None:
        client = AccessClient("unvr.local", "service", "secret")
        client._csrf_token = "old-csrf"
        client._auth_cookie = "old-cookie"

        unauthorized = MagicMock()
        unauthorized.status = 401
        # aiohttp.ClientResponse.release is deliberately synchronous. A
        # future accidental ``await`` must make this test fail with TypeError.
        unauthorized.release = MagicMock(return_value=None)
        success = MagicMock()
        success.status = 200

        session = MagicMock()
        session.closed = False
        session.request = AsyncMock(side_effect=[unauthorized, success])
        client._session = session

        async def relogin() -> None:
            client._csrf_token = "new-csrf"
            client._auth_cookie = "new-cookie"

        client.login = AsyncMock(side_effect=relogin)

        response = await client._request("GET", "/proxy/access/test")

        self.assertIs(response, success)
        unauthorized.release.assert_called_once_with()
        client.login.assert_awaited_once_with()
        self.assertEqual(session.request.await_count, 2)
        retry_headers = session.request.await_args_list[1].kwargs["headers"]
        self.assertEqual(retry_headers["X-CSRF-Token"], "new-csrf")
        self.assertEqual(retry_headers["Cookie"], "TOKEN=new-cookie")

    async def test_login_publishes_auth_only_after_site_identity_verifies(self) -> None:
        gate = asyncio.Event()
        client = AccessClient("unvr.local", "service", "secret")
        client._session = _IdentitySession(["site-a"], gate=gate)

        login = asyncio.create_task(client.login())
        await gate.wait()
        self.assertFalse(client.connected)
        await login
        self.assertTrue(client.connected)
        self.assertIsNotNone(client.console_identity)

    async def test_every_relogin_rejects_changed_site_identity(self) -> None:
        client = AccessClient("unvr.local", "service", "secret")
        # A definite mismatch consults topology before rejecting, hence the
        # third response used by the second login.
        client._session = _IdentitySession(["site-a", "site-b", "site-b"])
        await client.login()
        original = client.console_identity

        client._csrf_token = None
        client._auth_cookie = None
        with self.assertRaisesRegex(AccessClientError, "site identity"):
            await client.login()

        self.assertFalse(client.connected)
        self.assertEqual(client.console_identity, original)

    def test_identity_field_aliases_normalize_to_same_namespace(self) -> None:
        snake = AccessClient._derive_console_identity(
            {"data": {"site_id": "stable-id"}}
        )
        camel = AccessClient._derive_console_identity(
            {"data": {"siteId": "stable-id"}}
        )
        self.assertEqual(snake, camel)

    async def test_existing_identity_matches_any_new_firmware_candidate(self) -> None:
        expected = AccessClient._derive_console_identity(
            {"data": {"site_id": "stable-site"}}
        )
        client = AccessClient(
            "unvr.local", "service", "secret", expected_identity=expected
        )
        client._session = _IdentitySession([{
            "data": {
                "console_id": "new-preferred-field",
                "site_id": "stable-site",
            }
        }])

        await client.login()

        self.assertEqual(client.console_identity, expected)
        self.assertTrue(client.connected)

    async def test_missing_access_info_falls_back_to_topology(self) -> None:
        client = AccessClient("unvr.local", "service", "secret")
        session = _FallbackIdentitySession()
        client._session = session

        await client.login()

        expected = AccessClient._derive_console_identity(
            {}, {"data": [{"unique_id": "building-stable"}]}
        )
        self.assertEqual(client.console_identity, expected)
        self.assertEqual(session.topology_requests, 1)

    async def test_incompatible_access_info_schema_falls_back_to_topology(self) -> None:
        client = AccessClient("unvr.local", "service", "secret")
        client._session = _IdentitySession([
            {"data": {"firmware_version": "legacy"}},
            {"data": [{"id": "building-legacy"}]},
        ])

        await client.login()

        expected = AccessClient._derive_console_identity(
            {}, {"data": [{"id": "building-legacy"}]}
        )
        self.assertEqual(client.console_identity, expected)

    async def test_identity_source_auth_failure_does_not_fall_back(self) -> None:
        client = AccessClient("unvr.local", "service", "secret")
        session = _FallbackIdentitySession(info_status=401)
        client._session = session

        with self.assertRaisesRegex(AccessClientError, "Authentication failed"):
            await client.login()

        self.assertFalse(client.connected)
        self.assertEqual(session.topology_requests, 0)

    async def test_websocket_reconnect_revalidates_cached_identity(self) -> None:
        client = AccessClient("unvr.local", "service", "secret")
        client._session = _IdentitySession(["site-a", "site-b", "site-b"])
        await client.login()

        with self.assertRaisesRegex(AccessClientError, "site identity"):
            await client._ws_connect()

        self.assertFalse(client.connected)
        self.assertTrue(client._auth_permanently_failed)

    async def test_malformed_user_list_fails_closed(self) -> None:
        client = AccessClient("unvr.local", "service", "secret")
        client._request = AsyncMock(
            return_value=_Response(payload={"data": {"not": "a list"}})
        )

        with self.assertRaisesRegex(AccessClientError, "invalid user list"):
            await client.fetch_users()

    async def test_non_object_user_row_fails_closed(self) -> None:
        client = AccessClient("unvr.local", "service", "secret")
        client._request = AsyncMock(
            return_value=_Response(payload={"data": ["malformed"]})
        )

        with self.assertRaisesRegex(AccessClientError, "non-object user"):
            await client.fetch_users()


class AccessClientLockRuleTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def _official_client(*responses: _Response) -> tuple[AccessClient, MagicMock]:
        client = AccessClient(
            "unvr.local:443",
            "service",
            "secret",
            api_token="open-api-secret",
        )
        session = MagicMock()
        session.closed = False
        session.request = AsyncMock(side_effect=list(responses))
        client._api_session = session
        return client, session

    async def test_official_hold_unlock_uses_door_id_bearer_and_confirms(self) -> None:
        client, session = self._official_client(
            _Response(payload={"code": "SUCCESS", "data": "success"}),
            _Response(
                payload={
                    "code": "SUCCESS",
                    "data": {"type": "keep_unlock", "ended_time": 123},
                }
            ),
            _Response(
                payload={
                    "code": "SUCCESS",
                    "data": {
                        "id": "door-1",
                        "door_lock_relay_status": "unlock",
                    },
                }
            ),
        )

        result = await client.hold_unlocked(
            "hub-device-1",
            location_id="door-1",
        )

        self.assertEqual(
            result,
            {"type": "keep_unlock", "state": "unlocked"},
        )
        put = session.request.await_args_list[0]
        self.assertEqual(put.args[0], "PUT")
        self.assertEqual(
            put.args[1],
            "https://unvr.local:12445/api/v1/developer/doors/door-1/lock_rule",
        )
        self.assertEqual(put.kwargs["json"], {"type": "keep_unlock"})
        self.assertEqual(
            put.kwargs["headers"]["Authorization"],
            "Bearer open-api-secret",
        )
        self.assertNotIn("Cookie", put.kwargs["headers"])
        self.assertNotIn("hub-device-1", put.args[1])

    async def test_explicit_official_command_semantics(self) -> None:
        cases = (
            (
                "hold_unlocked",
                "keep_unlock",
                {"type": "keep_unlock", "ended_time": None},
                "unlock",
                {"type": "keep_unlock", "state": "unlocked"},
            ),
            (
                "hold_locked",
                "keep_lock",
                {"type": "keep_lock", "ended_time": None},
                "lock",
                {"type": "keep_lock", "state": "locked"},
            ),
            (
                "force_lock",
                "lock_now",
                {"type": "lock_early", "ended_time": 456},
                "lock",
                {"type": "lock_early", "state": "locked"},
            ),
            (
                "restore_native_rule",
                "reset",
                {"type": "schedule", "ended_time": 789},
                "unlock",
                {"type": "schedule", "state": "unlocked"},
            ),
        )
        for method_name, sent_rule, observed_rule, relay, expected in cases:
            with self.subTest(method=method_name):
                client = AccessClient(
                    "unvr.local",
                    "service",
                    "secret",
                    api_token="token",
                )
                responses = [
                    "success",
                    observed_rule,
                    {
                        "id": "door-1",
                        "door_lock_relay_status": relay,
                    },
                ]
                if method_name == "restore_native_rule":
                    responses.insert(
                        0, {"type": "keep_unlock", "ended_time": None}
                    )
                client._open_api_request = AsyncMock(side_effect=responses)

                result = await getattr(client, method_name)(
                    "hub-1",
                    location_id="door-1",
                )

                self.assertEqual(result, expected)
                write = next(
                    call
                    for call in client._open_api_request.await_args_list
                    if call.args[0] == "PUT"
                )
                self.assertEqual(write.kwargs["json_body"], {"type": sent_rule})

    async def test_legacy_lock_wrapper_sends_lock_now_never_reset(self) -> None:
        client = AccessClient("unvr.local", "service", "secret")
        client._request = AsyncMock(
            side_effect=[
                _Response(payload={"code": "SUCCESS", "data": "success"}),
                _Response(payload={"data": {"lock_rule": "lock_now"}}),
            ]
        )

        result = await client.lock("hub-1")

        self.assertEqual(result, {"type": "lock_now", "state": "locked"})
        write = client._request.await_args_list[0]
        self.assertEqual(
            write.args,
            ("PUT", "/proxy/access/api/v2/device/hub-1/lock_rule"),
        )
        self.assertEqual(write.kwargs["json"], {"lock_rule": "lock_now"})
        self.assertNotEqual(write.kwargs["json"], {"lock_rule": "reset"})

    async def test_legacy_restore_is_explicit_reset_and_may_resume_schedule(self) -> None:
        client = AccessClient("unvr.local", "service", "secret")
        client._request = AsyncMock(
            side_effect=[
                _Response(
                    payload={
                        "meta": {"rc": "ok"},
                        "data": {"lock_rule": {"type": "keep_unlock"}},
                    }
                ),
                _Response(payload={"meta": {"rc": "ok"}}),
                _Response(
                    payload={
                        "meta": {"rc": "ok"},
                        "data": {
                            "lock_rule": {
                                "type": "schedule",
                                "ended_time": 1000,
                            }
                        },
                    }
                ),
            ]
        )

        result = await client.restore_native_rule("hub-1")

        self.assertEqual(result, {"type": "schedule", "state": "unlocked"})
        write = client._request.await_args_list[1]
        self.assertEqual(write.kwargs["json"], {"lock_rule": "reset"})

    async def test_restore_rejects_stale_lock_early_as_follow_schedule(self) -> None:
        client = AccessClient(
            "unvr.local", "service", "secret", api_token="token"
        )
        stale = {"type": "lock_early", "ended_time": 123}
        client._open_api_request = AsyncMock(
            side_effect=[stale, "success", stale, stale, stale]
        )

        with patch("access_control.access_client.asyncio.sleep", new=AsyncMock()):
            with self.assertRaisesRegex(AccessClientError, "not confirmed"):
                await client.restore_native_rule(
                    "hub-1", location_id="door-1"
                )

        self.assertEqual(client._open_api_request.await_count, 5)

    async def test_confirmation_is_bounded_and_rejects_stale_rule(self) -> None:
        client = AccessClient(
            "unvr.local",
            "service",
            "secret",
            api_token="token",
        )
        client._open_api_request = AsyncMock(
            side_effect=[
                "success",
                {"type": "keep_lock", "ended_time": None},
                {"type": "keep_lock", "ended_time": None},
                {"type": "keep_lock", "ended_time": None},
            ]
        )

        with patch("access_control.access_client.asyncio.sleep", new=AsyncMock()):
            with self.assertRaisesRegex(AccessClientError, "not confirmed"):
                await client.hold_unlocked("hub-1", location_id="door-1")

        self.assertEqual(client._open_api_request.await_count, 4)

    async def test_release_persistent_lock_rejects_stale_keep_lock(self) -> None:
        """A relay-locked readback must not prove that keep_lock was removed."""
        client = AccessClient(
            "unvr.local",
            "service",
            "secret",
            api_token="token",
        )
        client._open_api_request = AsyncMock(
            side_effect=[
                # Pre-command rule fingerprint.
                {"type": "keep_lock", "ended_time": None},
                "success",
                # All bounded readbacks are the unchanged persistent override.
                {"type": "keep_lock", "ended_time": None},
                {"type": "keep_lock", "ended_time": None},
                {"type": "keep_lock", "ended_time": None},
            ]
        )

        with patch("access_control.access_client.asyncio.sleep", new=AsyncMock()):
            with self.assertRaisesRegex(AccessClientError, "not confirmed"):
                await client.release_persistent_lock(
                    "hub-1",
                    location_id="door-1",
                )

        self.assertEqual(client._open_api_request.await_count, 5)

    async def test_release_persistent_lock_accepts_changed_locked_rule(self) -> None:
        client = AccessClient(
            "unvr.local",
            "service",
            "secret",
            api_token="token",
        )
        client._open_api_request = AsyncMock(
            side_effect=[
                {"type": "keep_lock", "ended_time": None},
                "success",
                {"type": "lock_early", "ended_time": 456},
                {
                    "id": "door-1",
                    "door_lock_relay_status": "lock",
                },
            ]
        )

        result = await client.release_persistent_lock(
            "hub-1",
            location_id="door-1",
        )

        self.assertEqual(result, {"type": "lock_early", "state": "locked"})
        self.assertEqual(client._open_api_request.await_count, 4)

    async def test_official_malformed_or_failed_envelope_is_rejected(self) -> None:
        for payload in (
            {"code": "CODE_OPERATION_FORBIDDEN", "data": None},
            {"code": "SUCCESS"},
            {"code": "SUCCESS", "data": "not-a-rule"},
        ):
            with self.subTest(payload=payload):
                client, _session = self._official_client(
                    _Response(payload=payload)
                )
                with self.assertRaises(AccessClientError):
                    await client.get_lock_rule(
                        "hub-1",
                        location_id="door-1",
                    )

    async def test_legacy_malformed_rule_envelope_is_rejected(self) -> None:
        client = AccessClient("unvr.local", "service", "secret")
        client._request = AsyncMock(
            return_value=_Response(payload={"data": {"unexpected": True}})
        )

        with self.assertRaisesRegex(AccessClientError, "invalid legacy"):
            await client.get_lock_rule("hub-1")

    async def test_configured_token_failure_never_falls_back_to_legacy(self) -> None:
        client, _session = self._official_client(_Response(status=403))
        client._request = AsyncMock()

        with self.assertRaisesRegex(AccessClientError, "HTTP 403"):
            await client.hold_unlocked("hub-1", location_id="door-1")

        client._request.assert_not_awaited()

    async def test_official_mode_requires_location_id_without_fallback(self) -> None:
        client = AccessClient(
            "unvr.local",
            "service",
            "secret",
            api_token="token",
        )
        client._request = AsyncMock()

        with self.assertRaisesRegex(AccessClientError, "location_id"):
            await client.force_lock("hub-1")

        client._request.assert_not_awaited()

    async def test_validate_open_api_is_read_only_and_strict(self) -> None:
        client, session = self._official_client(
            _Response(
                payload={
                    "code": "SUCCESS",
                    "data": [{"id": "door-1", "name": "Front"}],
                }
            ),
            _Response(
                payload={
                    "code": "SUCCESS",
                    "data": {"type": "schedule", "ended_time": 100},
                }
            ),
        )

        self.assertTrue(await client.validate_open_api())
        self.assertEqual(
            [item.args[0] for item in session.request.await_args_list],
            ["GET", "GET"],
        )

        no_token = AccessClient("unvr.local", "service", "secret")
        self.assertFalse(await no_token.validate_open_api())


class _ProtectLoginResponse:
    status = 200
    headers = {
        "X-CSRF-Token": "csrf",
        "Set-Cookie": "TOKEN=cookie; Path=/; Secure",
    }

    async def __aenter__(self):
        # Yield control so a racing login() reliably queues on _login_lock,
        # exercising the true concurrent path rather than a serial one.
        await asyncio.sleep(0)
        return self

    async def __aexit__(self, *_args):
        return False

    async def text(self):
        return ""


class ProtectClientLoginTests(unittest.IsolatedAsyncioTestCase):
    """Bug 3: ProtectClient.login must short-circuit like AccessClient so
    two racers do not both POST credentials."""

    @staticmethod
    def _client_with_counting_session():
        from access_control.protect_client import ProtectClient

        client = ProtectClient("unvr.local", "service", "secret")
        state = {"posts": 0}

        class _Session:
            closed = False

            def post(self_inner, *_args, **_kwargs):
                state["posts"] += 1
                return _ProtectLoginResponse()

        client._get_session = lambda: _Session()
        return client, state

    async def test_concurrent_login_posts_credentials_once(self) -> None:
        client, state = self._client_with_counting_session()

        await asyncio.gather(client.login(), client.login())

        self.assertEqual(state["posts"], 1)
        self.assertTrue(client.connected)
        self.assertEqual(client._auth_cookie, "cookie")

    async def test_login_short_circuits_when_already_authenticated(self) -> None:
        from access_control.protect_client import ProtectClient

        client = ProtectClient("unvr.local", "service", "secret")
        client._csrf_token = "existing-csrf"
        client._auth_cookie = "existing-cookie"

        class _Session:
            closed = False

            def post(self_inner, *_args, **_kwargs):
                raise AssertionError(
                    "login must not POST while already authenticated"
                )

        client._get_session = lambda: _Session()

        await client.login()  # returns without touching the session
        self.assertEqual(client._csrf_token, "existing-csrf")


if __name__ == "__main__":
    unittest.main()
