from __future__ import annotations

import importlib
import importlib.util
import json
import sqlite3
import sys
import time
import unittest
from base64 import urlsafe_b64decode, urlsafe_b64encode
from pathlib import Path
from types import ModuleType
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch


ROOT = Path(__file__).resolve().parents[1]


def _install_fastapi_stubs() -> None:
    if importlib.util.find_spec("fastapi") is not None:
        return

    fastapi = ModuleType("fastapi")

    class HTTPException(Exception):
        def __init__(self, status_code: int, detail: str = "", headers: dict | None = None) -> None:
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail
            self.headers = headers or {}

    class Request:
        pass

    class APIRouter:
        def get(self, *args, **kwargs):
            def decorator(fn):
                return fn
            return decorator

        def post(self, *args, **kwargs):
            def decorator(fn):
                return fn
            return decorator

    def Depends(dep):
        return dep

    def Form(default=None, **kwargs):
        return default

    fastapi.APIRouter = APIRouter
    fastapi.Depends = Depends
    fastapi.Form = Form
    fastapi.HTTPException = HTTPException
    fastapi.Request = Request

    responses = ModuleType("fastapi.responses")

    class _BaseResponse:
        def __init__(self, content: str = "", status_code: int = 200, headers: dict | None = None) -> None:
            self.content = content
            self.status_code = status_code
            self.headers = headers or {}

        def set_cookie(self, key: str, value: str, **kwargs) -> None:
            self.headers["set-cookie"] = f"{key}={value}"

        def delete_cookie(self, key: str) -> None:
            self.headers["set-cookie"] = f"{key}=;"

    class HTMLResponse(_BaseResponse):
        pass

    class RedirectResponse(_BaseResponse):
        def __init__(self, url: str, status_code: int = 303) -> None:
            super().__init__("", status_code=status_code, headers={"location": url})

    responses.HTMLResponse = HTMLResponse
    responses.RedirectResponse = RedirectResponse

    templating = ModuleType("fastapi.templating")

    class Jinja2Templates:
        def __init__(self, directory: str) -> None:
            self.directory = directory
            self.env = SimpleNamespace(filters={})

        def TemplateResponse(self, request, template: str, context: dict, status_code: int = 200):
            # Modern Starlette signature: (request, name, context, status_code=200).
            return HTMLResponse(template, status_code=status_code)

    templating.Jinja2Templates = Jinja2Templates

    sys.modules["fastapi"] = fastapi
    sys.modules["fastapi.responses"] = responses
    sys.modules["fastapi.templating"] = templating


def _install_itsdangerous_stubs() -> None:
    if importlib.util.find_spec("itsdangerous") is not None:
        return

    itsdangerous = ModuleType("itsdangerous")

    class BadSignature(Exception):
        pass

    class URLSafeTimedSerializer:
        def __init__(self, secret_key: str | None) -> None:
            self.secret_key = secret_key or ""

        def dumps(self, data: dict) -> str:
            payload = json.dumps({"s": self.secret_key, "d": data}).encode()
            return urlsafe_b64encode(payload).decode()

        def loads(self, token: str, max_age: int | None = None) -> dict:
            try:
                decoded = json.loads(urlsafe_b64decode(token.encode()).decode())
            except Exception as exc:
                raise BadSignature(str(exc)) from exc
            if decoded.get("s") != self.secret_key:
                raise BadSignature("signature mismatch")
            return decoded["d"]

    itsdangerous.BadSignature = BadSignature
    itsdangerous.URLSafeTimedSerializer = URLSafeTimedSerializer
    sys.modules["itsdangerous"] = itsdangerous


def _install_cryptography_stubs() -> None:
    if importlib.util.find_spec("cryptography") is not None:
        return

    cryptography = ModuleType("cryptography")
    fernet_mod = ModuleType("cryptography.fernet")
    hazmat = ModuleType("cryptography.hazmat")
    primitives = ModuleType("cryptography.hazmat.primitives")
    hashes_mod = ModuleType("cryptography.hazmat.primitives.hashes")
    kdf_mod = ModuleType("cryptography.hazmat.primitives.kdf")
    pbkdf2_mod = ModuleType("cryptography.hazmat.primitives.kdf.pbkdf2")

    class Fernet:
        def __init__(self, key: bytes) -> None:
            self.key = key

        def encrypt(self, value: bytes) -> bytes:
            return urlsafe_b64encode(value)

        def decrypt(self, value: bytes) -> bytes:
            return urlsafe_b64decode(value)

    class SHA256:
        pass

    class PBKDF2HMAC:
        def __init__(self, algorithm, length: int, salt: bytes, iterations: int) -> None:
            self.length = length

        def derive(self, data: bytes) -> bytes:
            return (data * ((self.length // len(data)) + 1))[: self.length]

    fernet_mod.Fernet = Fernet
    hashes_mod.SHA256 = SHA256
    pbkdf2_mod.PBKDF2HMAC = PBKDF2HMAC

    sys.modules["cryptography"] = cryptography
    sys.modules["cryptography.fernet"] = fernet_mod
    sys.modules["cryptography.hazmat"] = hazmat
    sys.modules["cryptography.hazmat.primitives"] = primitives
    sys.modules["cryptography.hazmat.primitives.hashes"] = hashes_mod
    sys.modules["cryptography.hazmat.primitives.kdf"] = kdf_mod
    sys.modules["cryptography.hazmat.primitives.kdf.pbkdf2"] = pbkdf2_mod


def _install_aiohttp_stubs() -> None:
    if importlib.util.find_spec("aiohttp") is not None:
        return

    aiohttp = ModuleType("aiohttp")

    class ClientError(Exception):
        pass

    class ClientResponseError(ClientError):
        def __init__(self, status: int = 500) -> None:
            self.status = status

    class ClientTimeout:
        def __init__(self, total: int | None = None) -> None:
            self.total = total

    class TCPConnector:
        def __init__(self, ssl=None) -> None:
            self.ssl = ssl

    class CookieJar:
        def __init__(self, unsafe: bool = False) -> None:
            self.unsafe = unsafe

        def clear(self) -> None:
            return None

    class DummyResponse:
        status = 200
        headers: dict[str, str] = {}

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def text(self):
            return ""

        async def json(self, content_type=None):
            return {}

        async def release(self):
            return None

    class ClientSession:
        def __init__(self, *args, **kwargs) -> None:
            self.closed = False
            self.cookie_jar = kwargs.get("cookie_jar") or CookieJar()

        async def request(self, *args, **kwargs):
            return DummyResponse()

        async def post(self, *args, **kwargs):
            return DummyResponse()

        async def get(self, *args, **kwargs):
            return DummyResponse()

        async def ws_connect(self, *args, **kwargs):
            raise ClientResponseError(status=401)

        async def close(self):
            self.closed = True

    class WSMsgType:
        TEXT = "TEXT"
        BINARY = "BINARY"
        ERROR = "ERROR"
        CLOSE = "CLOSE"
        CLOSING = "CLOSING"
        CLOSED = "CLOSED"

    aiohttp.ClientError = ClientError
    aiohttp.ClientResponseError = ClientResponseError
    aiohttp.ClientResponse = DummyResponse
    aiohttp.ClientSession = ClientSession
    aiohttp.ClientTimeout = ClientTimeout
    aiohttp.CookieJar = CookieJar
    aiohttp.TCPConnector = TCPConnector
    aiohttp.WSMsgType = WSMsgType
    sys.modules["aiohttp"] = aiohttp


def _install_aiosqlite_stubs() -> None:
    if importlib.util.find_spec("aiosqlite") is not None:
        return

    aiosqlite = ModuleType("aiosqlite")

    class Row(dict):
        pass

    class Connection:
        row_factory = None

    async def connect(path):
        return Connection()

    aiosqlite.Row = Row
    aiosqlite.Connection = Connection
    aiosqlite.connect = connect
    sys.modules["aiosqlite"] = aiosqlite


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


_install_fastapi_stubs()
_install_itsdangerous_stubs()
_install_cryptography_stubs()
_install_aiohttp_stubs()
_install_aiosqlite_stubs()
_load_package()

config = importlib.import_module("access_control.config")
web_auth = importlib.import_module("access_control.web_auth")
web_routes = importlib.import_module("access_control.web_routes")
auth_engine_module = importlib.import_module("access_control.auth_engine")


class FakeDB:
    def __init__(self) -> None:
        self.config_values: list[tuple[str, str]] = []
        self.log_entries: list[dict] = []
        self.ui_cache: dict[str, object] = {}
        self.create_group = AsyncMock()
        self.set_config = AsyncMock(side_effect=self._set_config)
        self.add_api_key = AsyncMock()
        self.get_config = AsyncMock()
        self.get_lock = AsyncMock()
        self.log_access = AsyncMock(side_effect=self._log_access)
        self.get_all_alarm_panels = AsyncMock(return_value=[])
        self.is_rate_limited = AsyncMock(return_value=False)
        self.record_rate_limit_failure = AsyncMock(return_value=False)
        self.clear_rate_limit = AsyncMock()
        self.consume_rate_limit = AsyncMock(return_value=True)
        self.get_ui_cache = AsyncMock(side_effect=self._get_ui_cache)
        self.set_ui_cache = AsyncMock(side_effect=self._set_ui_cache)

    async def _set_config(self, key: str, value: str) -> None:
        self.config_values.append((key, value))

    async def _log_access(self, **kwargs) -> int:
        self.log_entries.append(kwargs)
        return len(self.log_entries)

    async def _get_ui_cache(self, key: str):
        return self.ui_cache.get(key)

    async def _set_ui_cache(self, key: str, value, ttl: int) -> None:
        self.ui_cache[key] = value


class FakeHAClient:
    def __init__(self) -> None:
        self.unlock_calls: list[str] = []
        self.lock_calls: list[str] = []

    async def unlock(self, entity_id: str) -> bool:
        self.unlock_calls.append(entity_id)
        return True

    async def lock(self, entity_id: str) -> bool:
        self.lock_calls.append(entity_id)
        return True

    async def fire_event(self, event_type: str, data: dict) -> bool:
        return True

    async def get_entity_state(self, entity_id: str) -> str | None:
        return "disarmed"

    async def alarm_disarm(self, entity_id: str, code: str | None = None) -> bool:
        return True


class FakeAccessClient:
    def __init__(self) -> None:
        self.unlock_calls: list[str] = []

    async def unlock_momentary(self, location_id: str) -> None:
        self.unlock_calls.append(location_id)


class SetupAndAuthTests(unittest.IsolatedAsyncioTestCase):
    async def test_setup_initializes_runtime(self) -> None:
        db = FakeDB()
        # First-run setup: admin_username must be unset so the C1 guard
        # (audit 2026-05-24) doesn't refuse with 404. Also: setup_post
        # now checks the rate limit before doing real work — return
        # not-limited.
        db.get_config = AsyncMock(return_value=None)
        db.is_rate_limited = AsyncMock(return_value=False)
        db.record_rate_limit_failure = AsyncMock()
        request = SimpleNamespace(
            scope={},
            state=SimpleNamespace(),
            client=SimpleNamespace(host="127.0.0.1"),
            app=SimpleNamespace(
                state=SimpleNamespace(
                    db=db,
                    configured=False,
                    initialize_configured_state=AsyncMock(),
                )
            )
        )

        access_client = SimpleNamespace(login=AsyncMock(), close=AsyncMock())
        ha_client = SimpleNamespace(test_connection=AsyncMock(return_value=True), close=AsyncMock())

        with patch.object(web_routes, "AccessClient", return_value=access_client), patch.object(
            web_routes, "HAClient", return_value=ha_client
        ):
            response = await web_routes.setup_post(
                request,
                admin_username="admin",
                admin_password="password",
                unvr_host="unvr.local",
                unvr_username="unvr-user",
                unvr_password="unvr-pass",
                ha_url="http://ha.local",
                ha_token="ha-token",
            )

        self.assertEqual(response.status_code, 303)
        self.assertTrue(request.app.state.configured)
        request.app.state.initialize_configured_state.assert_awaited_once()
        db.add_api_key.assert_awaited_once()
        self.assertIn(("admin_username", "admin"), db.config_values)

    async def test_setup_post_refuses_when_already_configured(self) -> None:
        """Audit 2026-05-24, C1: after first-run, /setup POST must refuse.

        Without this guard a network-reachable attacker (or a malicious
        HA admin via ingress) could re-run setup, overwrite admin
        credentials, and rotate the encryption_salt — orphaning every
        previously-encrypted UNVR/HA token and visitor PIN.
        """
        from fastapi import HTTPException
        db = FakeDB()
        # Simulate post-first-run state: admin_username is already set.
        db.get_config = AsyncMock(return_value="admin")
        db.is_rate_limited = AsyncMock(return_value=False)
        request = SimpleNamespace(
            scope={},
            state=SimpleNamespace(),
            client=SimpleNamespace(host="1.2.3.4"),
            app=SimpleNamespace(state=SimpleNamespace(db=db, configured=True)),
        )
        with self.assertRaises(HTTPException) as ctx:
            await web_routes.setup_post(
                request,
                admin_username="attacker",
                admin_password="hijack",
                unvr_host="evil.example",
                unvr_username="x",
                unvr_password="x",
                ha_url="http://evil/",
                ha_token="x",
            )
        self.assertEqual(ctx.exception.status_code, 404)
        # No config writes should have happened on the rejected attempt.
        self.assertNotIn(("admin_username", "attacker"), db.config_values)

    async def test_login_post_sets_session_cookie(self) -> None:
        web_auth.SECRET_KEY = "test-secret"
        db = FakeDB()
        hashed = config.hash_password("password")
        db.get_config = AsyncMock(side_effect=["admin", hashed])
        request = SimpleNamespace(
            scope={},
            state=SimpleNamespace(),
            client=SimpleNamespace(host="127.0.0.1"),
            app=SimpleNamespace(state=SimpleNamespace(db=db)),
        )

        response = await web_routes.login_post(request, username="admin", password="password")

        self.assertEqual(response.status_code, 303)
        self.assertIn("session=", response.headers.get("set-cookie", ""))


class FlowTests(unittest.IsolatedAsyncioTestCase):
    async def test_auth_engine_grants_access_and_unlocks_lock(self) -> None:
        db = SimpleNamespace(
            get_user_by_ulp_id=AsyncMock(return_value={"id": 1, "name": "Nick", "status": "ACTIVE"}),
            get_user_groups=AsyncMock(return_value=[]),
            get_locks_for_location=AsyncMock(return_value=[{"id": 10, "type": "ha_external", "entity_id": "lock.front", "name": "Front Door"}]),
            get_locks_by_entry_device=AsyncMock(return_value=[]),
            get_rules_for_user_and_lock=AsyncMock(return_value={"enabled": 1, "schedule_enabled": 0}),
            log_access=AsyncMock(),
            get_all_alarm_panels=AsyncMock(return_value=[]),
        )
        access_client = FakeAccessClient()
        ha_client = FakeHAClient()
        engine = auth_engine_module.AuthEngine(db=db, access_client=access_client, ha_client=ha_client, relock_tasks={})

        result = await engine.process_event("ulp-1", "door-1", method="nfc")

        self.assertTrue(result["granted"])
        self.assertEqual(ha_client.unlock_calls, ["lock.front"])
        self.assertTrue(db.log_access.await_count >= 1)

    async def test_manual_unlock_updates_state_and_logs(self) -> None:
        db = FakeDB()
        db.get_lock = AsyncMock(return_value={"id": 4, "type": "ha_external", "entity_id": "lock.back", "name": "Back Door"})
        ha_client = FakeHAClient()
        request = SimpleNamespace(
            scope={},
            state=SimpleNamespace(),
            app=SimpleNamespace(
                state=SimpleNamespace(
                    db=db,
                    access_client=None,
                    ha_client=ha_client,
                    lock_states={},
                    relock_tasks={},
                    relock_manager=None,
                )
            )
        )

        response = await web_routes._lock_action(4, "unlock", "admin", request)

        self.assertEqual(response.status_code, 303)
        self.assertEqual(request.app.state.lock_states["lock.back"], "unlocked")
        self.assertEqual(db.log_entries[0]["method"], "manual_unlock")

    async def test_create_group_duplicate_name_returns_error_redirect(self) -> None:
        db = FakeDB()
        db.create_group = AsyncMock(side_effect=sqlite3.IntegrityError("UNIQUE constraint failed: groups.name"))
        request = SimpleNamespace(
            scope={},
            state=SimpleNamespace(),
            app=SimpleNamespace(state=SimpleNamespace(db=db)),
            form=AsyncMock(return_value={"name": "Family", "description": ""}),
            client=SimpleNamespace(host="127.0.0.1"),
        )

        response = await web_routes.create_group(request, user="admin")

        self.assertEqual(response.status_code, 303)
        self.assertIn("/groups?error=", response.headers["location"])

    async def test_unlock_route_is_rate_limited(self) -> None:
        request = SimpleNamespace(
            scope={},
            state=SimpleNamespace(),
            client=SimpleNamespace(host="127.0.0.1"),
            app=SimpleNamespace(state=SimpleNamespace()),
        )
        with patch.object(web_routes, "_enforce_action_rate_limit", return_value=web_routes.HTMLResponse("limited", status_code=429)):
            response = await web_routes.unlock_lock(1, request, user="admin")
        self.assertEqual(response.status_code, 429)

    async def test_locks_list_uses_cached_topology_and_cameras(self) -> None:
        db = FakeDB()
        db.get_all_locks = AsyncMock(return_value=[{"id": 1, "type": "ha_external", "entity_id": "lock.front", "name": "Front"}])
        db.get_entry_devices_for_locks = AsyncMock(return_value={1: []})
        access_client = SimpleNamespace(connected=True, get_bootstrap=AsyncMock(), parse_door_locations=AsyncMock())
        protect_client = SimpleNamespace(connected=True, get_cameras=AsyncMock())
        request = SimpleNamespace(
            scope={},
            state=SimpleNamespace(),
            app=SimpleNamespace(
                state=SimpleNamespace(
                    db=db,
                    ha_client=None,
                    access_client=access_client,
                    protect_client=protect_client,
                    lock_states={},
                )
            ),
            cookies={},
        )
        db.ui_cache["locks_access_locations"] = [{"id": "1", "name": "Front Door"}]
        db.ui_cache["locks_protect_cameras"] = [[{"id": "cam1"}], [{"id": "cam2"}]]

        response = await web_routes.locks_list(request, user="admin")

        self.assertEqual(response.status_code, 200)
        access_client.get_bootstrap.assert_not_called()
        protect_client.get_cameras.assert_not_called()


if __name__ == "__main__":
    unittest.main()
