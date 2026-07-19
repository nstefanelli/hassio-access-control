"""Focused regressions for upstream client session handling."""
from __future__ import annotations

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from access_control.access_client import (
    AccessClient,
    AccessClientError,
    AccessCommandAcceptedUnconfirmedError,
    AccessCommandOutcomeUnknownError,
    AccessLegacyEndpointGoneError,
)

_MISSING = object()


class _Response:
    def __init__(
        self,
        *,
        status=200,
        headers=None,
        payload=_MISSING,
        body="",
    ) -> None:
        self.status = status
        self.headers = headers or {}
        self._payload = {} if payload is _MISSING else payload
        self._body = body
        self.connection = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    async def json(self, **_kwargs):
        return self._payload

    async def text(self):
        return self._body


class _RawResponse(_Response):
    """Response whose body cannot be decoded as JSON."""

    def __init__(self, body: str, *, status=200) -> None:
        super().__init__(status=status)
        self._body = body

    async def json(self, **_kwargs):
        raise ValueError("invalid or empty JSON")

    async def text(self):
        return self._body


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

    async def test_mutating_transport_timeout_is_outcome_unknown(self) -> None:
        client = AccessClient("unvr.local", "service", "secret")
        client._csrf_token = "csrf"
        client._auth_cookie = "cookie"
        session = MagicMock()
        session.closed = False
        session.request = AsyncMock(side_effect=asyncio.TimeoutError())
        client._session = session

        with self.assertRaises(AccessCommandOutcomeUnknownError):
            await client._request("PUT", "/proxy/access/mutate")

        with self.assertRaises(AccessClientError) as read_error:
            await client._request("GET", "/proxy/access/read")
        self.assertNotIsInstance(
            read_error.exception,
            AccessCommandOutcomeUnknownError,
        )

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


class AccessClientMutationEnvelopeTests(unittest.IsolatedAsyncioTestCase):
    _OBJECT_MUTATIONS = (
        (
            "visitor create",
            "create_visitor",
            ("Ada", "Visitor", 100, 200),
            {},
        ),
        (
            "visitor update",
            "update_visitor",
            ("visitor-1",),
            {"end_time": 300},
        ),
        ("user create", "create_user", ("Ada", "User"), {}),
        ("PIN update", "set_user_pin", ("user-1", "123456"), {}),
        ("PIN removal", "remove_user_pin", ("user-1",), {}),
    )
    _EMPTY_COMPATIBLE_MUTATIONS = (
        ("visitor delete", "delete_visitor", ("visitor-1",)),
        ("momentary unlock", "unlock_momentary", ("door-1",)),
    )

    async def test_object_mutations_return_only_object_data(self) -> None:
        expected = {"unique_id": "upstream-1"}
        for name, method, args, kwargs in self._OBJECT_MUTATIONS:
            client = AccessClient("unvr.local", "service", "secret")
            client._request = AsyncMock(
                return_value=_Response(
                    payload={
                        "code": "SUCCESS",
                        "meta": {"rc": "ok"},
                        "data": expected,
                    }
                )
            )

            with self.subTest(operation=name):
                self.assertEqual(
                    await getattr(client, method)(*args, **kwargs),
                    expected,
                )

    async def test_object_mutations_reject_explicit_failure_envelopes(self) -> None:
        failures = (
            {"code": "OPERATION_FAILED", "data": {}},
            {"meta": {"rc": "error"}, "data": {}},
            {
                "code": "SUCCESS",
                "meta": {"rc": "error"},
                "data": {},
            },
            {"success": False, "data": {}},
        )
        for payload in failures:
            for name, method, args, kwargs in self._OBJECT_MUTATIONS:
                client = AccessClient("unvr.local", "service", "secret")
                client._request = AsyncMock(
                    return_value=_Response(payload=payload)
                )
                with self.subTest(operation=name, payload=payload):
                    with self.assertRaisesRegex(
                        AccessClientError, "rejected"
                    ):
                        await getattr(client, method)(*args, **kwargs)

    async def test_object_mutations_reject_missing_or_wrong_data(self) -> None:
        malformed = (
            {},
            {"code": "SUCCESS"},
            {"data": None},
            {"data": []},
            {"data": "success"},
        )
        for payload in malformed:
            for name, method, args, kwargs in self._OBJECT_MUTATIONS:
                client = AccessClient("unvr.local", "service", "secret")
                client._request = AsyncMock(
                    return_value=_Response(payload=payload)
                )
                with self.subTest(operation=name, payload=payload):
                    with self.assertRaisesRegex(
                        AccessClientError, "invalid data"
                    ):
                        await getattr(client, method)(*args, **kwargs)

    async def test_object_mutations_reject_malformed_json_and_non_objects(
        self,
    ) -> None:
        response_factories = (
            lambda: _RawResponse(""),
            lambda: _RawResponse("{not-json"),
            lambda: _Response(payload=None),
            lambda: _Response(payload=[]),
        )
        for response_factory in response_factories:
            for name, method, args, kwargs in self._OBJECT_MUTATIONS:
                client = AccessClient("unvr.local", "service", "secret")
                client._request = AsyncMock(return_value=response_factory())
                with self.subTest(
                    operation=name,
                    response=response_factory,
                ):
                    with self.assertRaises(AccessClientError):
                        await getattr(client, method)(*args, **kwargs)

    async def test_delete_and_momentary_unlock_accept_empty_body(self) -> None:
        for response_factory in (
            lambda: _RawResponse(" \r\n"),
            lambda: _Response(payload=None, body=""),
        ):
            for name, method, args in self._EMPTY_COMPATIBLE_MUTATIONS:
                client = AccessClient("unvr.local", "service", "secret")
                client._request = AsyncMock(
                    return_value=response_factory()
                )
                with self.subTest(operation=name, response=response_factory):
                    await getattr(client, method)(*args)

    async def test_delete_and_momentary_unlock_accept_success_envelopes(
        self,
    ) -> None:
        for payload in (
            {},
            {"code": "SUCCESS"},
            {"meta": {"rc": "ok"}},
        ):
            for name, method, args in self._EMPTY_COMPATIBLE_MUTATIONS:
                client = AccessClient("unvr.local", "service", "secret")
                client._request = AsyncMock(
                    return_value=_Response(payload=payload)
                )
                with self.subTest(operation=name, payload=payload):
                    await getattr(client, method)(*args)

    async def test_delete_and_momentary_unlock_reject_explicit_failures(
        self,
    ) -> None:
        failures = (
            {"code": "OPERATION_FAILED"},
            {"meta": {"rc": "error"}},
            {"code": "SUCCESS", "meta": {"rc": "error"}},
            {"success": False},
        )
        for payload in failures:
            for name, method, args in self._EMPTY_COMPATIBLE_MUTATIONS:
                client = AccessClient("unvr.local", "service", "secret")
                client._request = AsyncMock(
                    return_value=_Response(payload=payload)
                )
                with self.subTest(operation=name, payload=payload):
                    with self.assertRaisesRegex(
                        AccessClientError, "rejected"
                    ):
                        await getattr(client, method)(*args)

    async def test_delete_and_momentary_unlock_reject_malformed_body(
        self,
    ) -> None:
        for response_factory in (
            lambda: _RawResponse("{not-json"),
            lambda: _Response(payload=None, body="null"),
            lambda: _Response(payload=[]),
        ):
            for name, method, args in self._EMPTY_COMPATIBLE_MUTATIONS:
                client = AccessClient("unvr.local", "service", "secret")
                client._request = AsyncMock(return_value=response_factory())
                with self.subTest(
                    operation=name,
                    response=response_factory,
                ):
                    with self.assertRaises(AccessClientError):
                        await getattr(client, method)(*args)


class AccessClientMomentaryConfirmationTests(unittest.IsolatedAsyncioTestCase):
    async def test_confirmed_unlock_polls_relay_after_acceptance_hook(
        self,
    ) -> None:
        client = AccessClient(
            "unvr.local",
            "service",
            "secret",
            api_token="open-api-secret",
        )
        client._request = AsyncMock(return_value=_RawResponse(""))
        hook = MagicMock()

        states = iter(("locked", "locked", "unlocked"))

        async def read_state(device_id, *, location_id=None):
            self.assertEqual(device_id, "door-1")
            self.assertEqual(location_id, "door-1")
            hook.assert_called_once_with()
            return next(states)

        client.get_door_state = AsyncMock(side_effect=read_state)
        sleep = AsyncMock()
        with patch(
            "access_control.access_client.asyncio.sleep",
            new=sleep,
        ):
            result = await client.unlock_momentary_confirmed(
                "door-1",
                on_written=hook,
            )

        self.assertEqual(result, {"state": "unlocked"})
        hook.assert_called_once_with()
        self.assertEqual(client.get_door_state.await_count, 3)
        self.assertEqual(
            [call.args[0] for call in sleep.await_args_list],
            [0.25, 0.5],
        )

    async def test_confirmed_unlock_timeout_is_accepted_unconfirmed(
        self,
    ) -> None:
        client = AccessClient(
            "unvr.local",
            "service",
            "secret",
            api_token="open-api-secret",
        )
        client._request = AsyncMock(
            return_value=_Response(payload={"code": "SUCCESS"})
        )
        client.get_door_state = AsyncMock(
            side_effect=[
                "locked",
                AccessClientError("temporary read failure"),
                "locked",
                AccessClientError("temporary read failure"),
                "locked",
                "locked",
            ]
        )
        hook = MagicMock()
        sleep = AsyncMock()

        with patch(
            "access_control.access_client.asyncio.sleep",
            new=sleep,
        ):
            with self.assertRaisesRegex(
                AccessCommandAcceptedUnconfirmedError,
                "accepted.*relay did not report unlocked",
            ):
                await client.unlock_momentary_confirmed(
                    "door-2",
                    on_written=hook,
                )

        hook.assert_called_once_with()
        self.assertEqual(client.get_door_state.await_count, 6)
        self.assertEqual(
            [call.args[0] for call in sleep.await_args_list],
            [0.25, 0.5, 1.0, 1.5, 2.0],
        )

    async def test_momentary_confirmation_has_one_wall_clock_deadline(
        self,
    ) -> None:
        client = AccessClient(
            "unvr.local",
            "service",
            "secret",
            api_token="open-api-secret",
        )
        client._request = AsyncMock(return_value=_RawResponse(""))

        async def hung_read(*_args, **_kwargs):
            await asyncio.Event().wait()

        client.get_door_state = AsyncMock(side_effect=hung_read)

        with patch(
            "access_control.access_client._LOCK_CONFIRM_WINDOW",
            0.02,
        ):
            with self.assertRaises(AccessCommandAcceptedUnconfirmedError):
                await asyncio.wait_for(
                    client.unlock_momentary_confirmed("door-deadline"),
                    timeout=0.2,
                )

    async def test_rule_confirmation_has_one_wall_clock_deadline(self) -> None:
        client = AccessClient(
            "unvr.local",
            "service",
            "secret",
            api_token="open-api-secret",
        )
        calls = 0

        async def write_then_hang(*_args, **_kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                return "success"
            await asyncio.Event().wait()

        client._open_api_request = AsyncMock(side_effect=write_then_hang)

        with patch(
            "access_control.access_client._LOCK_CONFIRM_WINDOW",
            0.02,
        ):
            with self.assertRaises(AccessCommandAcceptedUnconfirmedError):
                await asyncio.wait_for(
                    client.hold_unlocked(
                        "hub-deadline",
                        location_id="door-deadline",
                    ),
                    timeout=0.2,
                )

    async def test_confirmed_unlock_without_token_is_accepted_unconfirmed(
        self,
    ) -> None:
        client = AccessClient("unvr.local", "service", "secret")
        client._request = AsyncMock(return_value=_RawResponse(""))
        client.get_door_state = AsyncMock()
        hook = MagicMock()

        with self.assertRaisesRegex(
            AccessCommandAcceptedUnconfirmedError,
            "accepted.*Open API token is required",
        ):
            await client.unlock_momentary_confirmed(
                "door-3",
                on_written=hook,
            )

        hook.assert_called_once_with()
        client.get_door_state.assert_not_awaited()

    async def test_confirmed_unlock_preserves_prewrite_rejection(self) -> None:
        client = AccessClient(
            "unvr.local",
            "service",
            "secret",
            api_token="open-api-secret",
        )
        client._request = AsyncMock(
            return_value=_Response(
                payload={"code": "OPERATION_FAILED"}
            )
        )
        client.get_door_state = AsyncMock()
        hook = MagicMock()

        with self.assertRaises(AccessClientError) as raised:
            await client.unlock_momentary_confirmed(
                "door-4",
                on_written=hook,
            )

        self.assertNotIsInstance(
            raised.exception,
            AccessCommandAcceptedUnconfirmedError,
        )
        hook.assert_not_called()
        client.get_door_state.assert_not_awaited()


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

    async def test_official_mutation_missing_code_is_outcome_unknown(self) -> None:
        client, _session = self._official_client(
            _Response(payload={"data": "success"})
        )

        with self.assertRaises(AccessCommandOutcomeUnknownError):
            await client._open_api_request(
                "PUT",
                "/api/v1/developer/doors/door-1/lock_rule",
                json_body={"type": "keep_lock"},
            )

        rejected, _session = self._official_client(
            _Response(
                payload={
                    "code": "CODE_OPERATION_FORBIDDEN",
                    "data": None,
                }
            )
        )
        with self.assertRaises(AccessClientError) as raised:
            await rejected._open_api_request(
                "PUT",
                "/api/v1/developer/doors/door-1/lock_rule",
                json_body={"type": "keep_lock"},
            )
        self.assertNotIsInstance(
            raised.exception,
            AccessCommandOutcomeUnknownError,
        )

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

    async def test_legacy_restore_accepts_reset_without_guessing_relay_state(
        self,
    ) -> None:
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
                        "data": {"lock_rule": {"type": "reset"}},
                    }
                ),
            ]
        )

        result = await client.restore_native_rule("hub-1")

        self.assertEqual(result, {"type": "reset"})
        self.assertEqual(client._request.await_count, 3)

    async def test_restore_rejects_stale_lock_early_as_follow_schedule(self) -> None:
        client = AccessClient(
            "unvr.local", "service", "secret", api_token="token"
        )
        stale = {"type": "lock_early", "ended_time": 123}
        # 1.5.12 widened the confirm window from 3 to
        # len(_LOCK_CONFIRM_DELAYS) + 1 = 6 readbacks (pre-read + write + reads).
        client._open_api_request = AsyncMock(
            side_effect=[stale, "success", *([stale] * 6)]
        )

        with patch("access_control.access_client.asyncio.sleep", new=AsyncMock()):
            with self.assertRaisesRegex(AccessClientError, "not confirmed"):
                await client.restore_native_rule(
                    "hub-1", location_id="door-1"
                )

        self.assertEqual(client._open_api_request.await_count, 8)

    async def test_restore_rejects_changed_closed_override_as_follow_schedule(
        self,
    ) -> None:
        """Changed metadata does not turn lock_early/lock_now into a reset."""
        for override in ("lock_early", "lock_now"):
            with self.subTest(override=override):
                client = AccessClient(
                    "unvr.local", "service", "secret", api_token="token"
                )
                previous = {"type": override, "ended_time": 100}
                changed = [
                    {"type": override, "ended_time": ended}
                    for ended in range(101, 107)
                ]
                client._open_api_request = AsyncMock(
                    side_effect=[previous, "success", *changed]
                )

                with patch(
                    "access_control.access_client.asyncio.sleep",
                    new=AsyncMock(),
                ):
                    with self.assertRaises(
                        AccessCommandAcceptedUnconfirmedError
                    ):
                        await client.restore_native_rule(
                            "hub-1", location_id="door-1"
                        )

                self.assertEqual(client._open_api_request.await_count, 8)

    async def test_confirmation_is_bounded_and_rejects_stale_rule(self) -> None:
        client = AccessClient(
            "unvr.local",
            "service",
            "secret",
            api_token="token",
        )
        # 1.5.12 widened the confirm window to 6 readbacks (write + 6 GETs).
        client._open_api_request = AsyncMock(
            side_effect=[
                "success",
                *([{"type": "keep_lock", "ended_time": None}] * 6),
            ]
        )

        with patch("access_control.access_client.asyncio.sleep", new=AsyncMock()):
            with self.assertRaisesRegex(
                AccessCommandAcceptedUnconfirmedError, "not confirmed"
            ):
                await client.hold_unlocked("hub-1", location_id="door-1")

        self.assertEqual(client._open_api_request.await_count, 7)

    async def test_prewrite_rejection_is_not_accepted_unconfirmed(self) -> None:
        client = AccessClient(
            "unvr.local", "service", "secret", api_token="token"
        )
        client._open_api_request = AsyncMock(
            side_effect=AccessClientError("write rejected")
        )

        with self.assertRaises(AccessClientError) as raised:
            await client.hold_unlocked("hub-1", location_id="door-1")

        self.assertNotIsInstance(
            raised.exception, AccessCommandAcceptedUnconfirmedError
        )
        self.assertEqual(client._open_api_request.await_count, 1)

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
                # 1.5.12 widened the window to 6 readbacks.
                *([{"type": "keep_lock", "ended_time": None}] * 6),
            ]
        )

        with patch("access_control.access_client.asyncio.sleep", new=AsyncMock()):
            with self.assertRaisesRegex(AccessClientError, "not confirmed"):
                await client.release_persistent_lock(
                    "hub-1",
                    location_id="door-1",
                )

        self.assertEqual(client._open_api_request.await_count, 8)

    async def test_release_persistent_lock_rejects_changed_keep_lock_metadata(
        self,
    ) -> None:
        client = AccessClient(
            "unvr.local", "service", "secret", api_token="token"
        )
        client.get_lock_rule = AsyncMock(
            side_effect=[
                {"type": "keep_lock", "ended_time": 100},
                *(
                    {"type": "keep_lock", "ended_time": ended}
                    for ended in range(101, 107)
                ),
            ]
        )
        client.get_door_state = AsyncMock(return_value="locked")
        client._open_api_request = AsyncMock(return_value="success")

        with patch("access_control.access_client.asyncio.sleep", new=AsyncMock()):
            with self.assertRaises(AccessCommandAcceptedUnconfirmedError):
                await client.release_persistent_lock(
                    "hub-1",
                    location_id="door-1",
                )

        self.assertEqual(client.get_lock_rule.await_count, 7)
        client.get_door_state.assert_not_awaited()
        client._open_api_request.assert_awaited_once()

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

    async def test_release_persistent_lock_accepts_reset_with_locked_relay(
        self,
    ) -> None:
        client = AccessClient(
            "unvr.local", "service", "secret", api_token="token"
        )
        client._open_api_request = AsyncMock(
            side_effect=[
                {"type": "keep_lock", "ended_time": None},
                "success",
                {"type": "reset", "ended_time": 0},
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

        self.assertEqual(result, {"type": "reset", "state": "locked"})
        self.assertEqual(client._open_api_request.await_count, 4)

    # ------------------------------------------------------------------
    # 1.5.12 — extended progressive confirm window + lock_now/reset semantics.
    # sleep is patched so the ~5s window costs no wall-clock time.
    # ------------------------------------------------------------------

    @staticmethod
    def _relay(status: str) -> dict:
        return {"id": "door-1", "door_lock_relay_status": status}

    async def test_keep_unlock_confirms_when_relay_reports_late(self) -> None:
        """(i) keep_unlock: rule echoes at once but the relay only reports
        unlocked on the 4th read (~2s). The widened window confirms instead of
        timing out at <1s as the old fixed loop did."""
        client = AccessClient(
            "unvr.local", "service", "secret", api_token="token"
        )
        client._open_api_request = AsyncMock(
            side_effect=[
                "success",
                # attempts 0..2: rule accepted, relay still lagging locked.
                {"type": "keep_unlock", "ended_time": None}, self._relay("lock"),
                {"type": "keep_unlock", "ended_time": None}, self._relay("lock"),
                {"type": "keep_unlock", "ended_time": None}, self._relay("lock"),
                # attempt 3 (~1.75s): relay finally settles unlocked.
                {"type": "keep_unlock", "ended_time": None}, self._relay("unlock"),
            ]
        )

        with patch("access_control.access_client.asyncio.sleep", new=AsyncMock()):
            result = await client.hold_unlocked("hub-1", location_id="door-1")

        self.assertEqual(result, {"type": "keep_unlock", "state": "unlocked"})

    async def test_lock_now_confirms_when_relay_reports_late(self) -> None:
        """(i)/(ii) lock_now: firmware self-clears the rule to `reset` and the
        relay only reports locked on the 4th read. `reset` is accepted as the
        documented post-execution state, and the late relay read confirms."""
        client = AccessClient(
            "unvr.local", "service", "secret", api_token="token"
        )
        client._open_api_request = AsyncMock(
            side_effect=[
                "success",
                {"type": "reset", "ended_time": None}, self._relay("unlock"),
                {"type": "reset", "ended_time": None}, self._relay("unlock"),
                {"type": "reset", "ended_time": None}, self._relay("unlock"),
                {"type": "reset", "ended_time": None}, self._relay("lock"),
            ]
        )

        with patch("access_control.access_client.asyncio.sleep", new=AsyncMock()):
            result = await client.force_lock("hub-1", location_id="door-1")

        self.assertEqual(result, {"type": "reset", "state": "locked"})

    async def test_lock_now_reset_with_locked_relay_confirms_immediately(
        self,
    ) -> None:
        """(ii) lock_now + observed rule=reset + relay=lock on the first read is
        a confirmed success (momentary self-clear is not a rejection)."""
        client = AccessClient(
            "unvr.local", "service", "secret", api_token="token"
        )
        client._open_api_request = AsyncMock(
            side_effect=[
                "success",
                {"type": "reset", "ended_time": None},
                self._relay("lock"),
            ]
        )

        with patch("access_control.access_client.asyncio.sleep", new=AsyncMock()):
            result = await client.force_lock("hub-1", location_id="door-1")

        self.assertEqual(result, {"type": "reset", "state": "locked"})
        self.assertEqual(client._open_api_request.await_count, 3)

    async def test_lock_now_reset_relay_never_settles_fails_closed(self) -> None:
        """(iii) rule=reset but the relay never reads locked → the command
        stays unconfirmed and raises fail-closed, with the distinct
        rule-accepted/relay-stale message."""
        client = AccessClient(
            "unvr.local", "service", "secret", api_token="token"
        )
        client._open_api_request = AsyncMock(
            side_effect=[
                "success",
                *sum(
                    (
                        [{"type": "reset", "ended_time": None}, self._relay("unlock")]
                        for _ in range(6)
                    ),
                    [],
                ),
            ]
        )

        with patch("access_control.access_client.asyncio.sleep", new=AsyncMock()):
            with self.assertRaisesRegex(
                AccessClientError, "relay did not report locked"
            ):
                await client.force_lock("hub-1", location_id="door-1")

        # write + 6 * (rule + relay) reads.
        self.assertEqual(client._open_api_request.await_count, 13)

    async def test_missing_relay_state_mid_window_is_retried(self) -> None:
        """(iv) a relay read that returns no usable state mid-window is retried,
        not treated as a failure; a later good read confirms."""
        client = AccessClient(
            "unvr.local", "service", "secret", api_token="token"
        )
        client._open_api_request = AsyncMock(
            side_effect=[
                "success",
                # attempt 0: relay reports no state yet (mid-actuation).
                {"type": "keep_unlock", "ended_time": None}, self._relay(None),
                # attempt 1: relay settles unlocked.
                {"type": "keep_unlock", "ended_time": None}, self._relay("unlock"),
            ]
        )

        with patch("access_control.access_client.asyncio.sleep", new=AsyncMock()):
            result = await client.hold_unlocked("hub-1", location_id="door-1")

        self.assertEqual(result, {"type": "keep_unlock", "state": "unlocked"})
        self.assertEqual(client._open_api_request.await_count, 5)

    async def test_keep_unlock_stale_relay_reports_distinct_error(self) -> None:
        """The keep_unlock rule echoes but the relay stays locked for the whole
        window → a distinct 'rule accepted but relay did not report unlocked'
        error rather than the generic not-confirmed message."""
        client = AccessClient(
            "unvr.local", "service", "secret", api_token="token"
        )
        client._open_api_request = AsyncMock(
            side_effect=[
                "success",
                *sum(
                    (
                        [{"type": "keep_unlock", "ended_time": None}, self._relay("lock")]
                        for _ in range(6)
                    ),
                    [],
                ),
            ]
        )

        with patch("access_control.access_client.asyncio.sleep", new=AsyncMock()):
            with self.assertRaisesRegex(
                AccessClientError, "relay did not report unlocked"
            ):
                await client.hold_unlocked("hub-1", location_id="door-1")

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

    async def test_official_idle_door_empty_rule_type_normalizes_to_reset(
        self,
    ) -> None:
        """A door with no active override answers the Open API rule read with
        {"type": "", "ended_time": 0} (observed live, Access firmware 2026-07).
        That idle response must parse as the native-behavior "reset" rule —
        it previously raised "unknown lock rule type", which failed token
        validation against any console whose first door was idle and would
        have failed every hub-sync readback of an idle door."""
        client, _session = self._official_client(
            _Response(
                payload={
                    "code": "SUCCESS",
                    "data": {"type": "", "ended_time": 0},
                }
            ),
        )

        rule = await client.get_lock_rule("hub-1", location_id="door-1")

        self.assertEqual(rule, {"type": "reset", "ended_time": 0})

    async def test_validate_open_api_accepts_idle_first_door(self) -> None:
        client, _session = self._official_client(
            _Response(
                payload={
                    "code": "SUCCESS",
                    "data": [{"id": "door-1", "name": "Back Door"}],
                }
            ),
            _Response(
                payload={
                    "code": "SUCCESS",
                    "data": {"type": "", "ended_time": 0},
                }
            ),
        )

        self.assertTrue(await client.validate_open_api())

    async def test_legacy_empty_rule_type_stays_rejected(self) -> None:
        """The empty-type normalization is Open-API-only: legacy envelopes
        always echo a concrete type, so an empty one there is still malformed
        (fail-closed)."""
        client = AccessClient("unvr.local", "service", "secret")
        client._request = AsyncMock(
            return_value=_Response(
                payload={"code": "SUCCESS", "data": {"lock_rule": {"type": ""}}}
            )
        )

        with self.assertRaisesRegex(AccessClientError, "lock.rule"):
            await client.get_lock_rule("hub-1")

    async def test_legacy_get_404_raises_typed_endpoint_gone(self) -> None:
        """A UNVR update removed the legacy per-device lock_rule route. A 404
        on the legacy GET must surface the typed, actionable error."""
        client = AccessClient("unvr.local", "service", "secret")
        client._request = AsyncMock(
            side_effect=AccessClientError(
                "HTTP 404 from GET /proxy/access/api/v2/device/hub-1/lock_rule",
                status=404,
            )
        )

        with self.assertRaises(AccessLegacyEndpointGoneError) as ctx:
            await client.get_lock_rule("hub-1")

        message = str(ctx.exception)
        self.assertIn("legacy Access API endpoint not found", message)
        self.assertIn(
            "configure a UniFi Access Open API token", message
        )

    async def test_legacy_put_404_raises_typed_endpoint_gone(self) -> None:
        """The legacy PUT (hold_locked → _write_rule_and_confirm) must also
        raise the typed error on a 404 so the sync layer can recognise it."""
        client = AccessClient("unvr.local", "service", "secret")
        client._request = AsyncMock(
            side_effect=AccessClientError(
                "HTTP 404 from PUT /proxy/access/api/v2/device/hub-1/lock_rule",
                status=404,
            )
        )

        with self.assertRaises(AccessLegacyEndpointGoneError) as ctx:
            await client.hold_locked("hub-1")

        self.assertIn(
            "configure a UniFi Access Open API token", str(ctx.exception)
        )
        # The write failed before any readback confirmation was attempted.
        self.assertEqual(client._request.await_count, 1)

    async def test_legacy_non_404_error_is_not_reclassified(self) -> None:
        """A 5xx / transient legacy failure stays a plain AccessClientError so
        the sync layer keeps retrying it at full cadence."""
        client = AccessClient("unvr.local", "service", "secret")
        client._request = AsyncMock(
            side_effect=AccessClientError(
                "HTTP 500 from GET /proxy/access/api/v2/device/hub-1/lock_rule",
                status=500,
            )
        )

        with self.assertRaises(AccessClientError) as ctx:
            await client.get_lock_rule("hub-1")

        self.assertNotIsInstance(ctx.exception, AccessLegacyEndpointGoneError)

    async def test_open_api_404_is_not_reclassified_as_legacy_gone(self) -> None:
        """The modern Open-API branch must be unaffected: a 404 there is a
        plain AccessClientError, never the legacy-endpoint-gone signal."""
        client, _session = self._official_client(_Response(status=404))

        with self.assertRaises(AccessClientError) as ctx:
            await client.get_lock_rule("hub-1", location_id="door-1")

        self.assertNotIsInstance(ctx.exception, AccessLegacyEndpointGoneError)


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


class AccessClientLifetimeTests(unittest.IsolatedAsyncioTestCase):
    async def test_close_drains_inflight_command_confirmation(self) -> None:
        client = AccessClient(
            "access.local",
            "service",
            "secret",
            api_token="token",
        )
        confirmation_started = asyncio.Event()
        release_confirmation = asyncio.Event()

        async def slow_confirmation(*_args, **_kwargs):
            confirmation_started.set()
            await release_confirmation.wait()
            return {"type": "keep_unlock", "state": "unlocked"}

        client._write_rule_and_confirm_leased = AsyncMock(
            side_effect=slow_confirmation
        )
        command = asyncio.create_task(
            client.hold_unlocked(
                "hub-1",
                location_id="door-1",
            )
        )
        await confirmation_started.wait()

        closing = asyncio.create_task(client.close())
        await asyncio.sleep(0)
        self.assertFalse(closing.done())
        self.assertFalse(client._closed)

        release_confirmation.set()
        self.assertEqual(
            await command,
            {"type": "keep_unlock", "state": "unlocked"},
        )
        await closing
        self.assertTrue(client._closed)
        self.assertEqual(client._active_operations, 0)

        with self.assertRaisesRegex(AccessClientError, "closing"):
            await client.hold_unlocked(
                "hub-1",
                location_id="door-1",
            )

    async def test_cancelled_close_still_drains_active_command(self) -> None:
        client = AccessClient(
            "access.local",
            "service",
            "secret",
            api_token="token",
        )
        confirmation_started = asyncio.Event()
        release_confirmation = asyncio.Event()

        async def slow_confirmation(*_args, **_kwargs):
            confirmation_started.set()
            await release_confirmation.wait()
            return {"type": "keep_lock", "state": "locked"}

        client._write_rule_and_confirm_leased = AsyncMock(
            side_effect=slow_confirmation
        )
        command = asyncio.create_task(
            client.hold_locked("hub-1", location_id="door-1")
        )
        await confirmation_started.wait()
        closing = asyncio.create_task(client.close())
        while not client._closing:
            await asyncio.sleep(0)

        closing.cancel()
        release_confirmation.set()
        await command
        with self.assertRaises(asyncio.CancelledError):
            await closing

        self.assertTrue(client._closed)
        self.assertEqual(client._active_operations, 0)
        await client.close()


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
