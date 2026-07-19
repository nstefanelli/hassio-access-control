from __future__ import annotations

import asyncio
import importlib
import importlib.util
import json
import sys
import unittest
from base64 import urlsafe_b64decode, urlsafe_b64encode
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]


def _stub_not_installed(name: str) -> bool:
    """Return True if the module is not yet in sys.modules."""
    return name not in sys.modules


def _install_fastapi_stubs() -> None:
    if not _stub_not_installed("fastapi"):
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
            # Real Jinja2Templates exposes an `env` attribute with a
            # `filters` dict. The app registers a custom filter at import
            # time; expose a minimal `env` so it can do so.
            self.env = SimpleNamespace(filters={})

        def TemplateResponse(self, request, template: str, context: dict, status_code: int = 200):
            # Modern Starlette signature: (request, name, context, status_code=200).
            return HTMLResponse(template, status_code=status_code)

    templating.Jinja2Templates = Jinja2Templates

    # Set __spec__ so importlib.util.find_spec() returns a truthy value
    # instead of raising ValueError when another test module runs its own guard.
    _spec = importlib.util.spec_from_loader("fastapi", loader=None)
    fastapi.__spec__ = _spec
    responses.__spec__ = importlib.util.spec_from_loader("fastapi.responses", loader=None)
    templating.__spec__ = importlib.util.spec_from_loader("fastapi.templating", loader=None)

    sys.modules["fastapi"] = fastapi
    sys.modules["fastapi.responses"] = responses
    sys.modules["fastapi.templating"] = templating


def _install_itsdangerous_stubs() -> None:
    if not _stub_not_installed("itsdangerous"):
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
    itsdangerous.__spec__ = importlib.util.spec_from_loader("itsdangerous", loader=None)
    sys.modules["itsdangerous"] = itsdangerous


def _install_cryptography_stubs() -> None:
    if not _stub_not_installed("cryptography"):
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

    cryptography.__spec__ = importlib.util.spec_from_loader("cryptography", loader=None)
    sys.modules["cryptography"] = cryptography
    sys.modules["cryptography.fernet"] = fernet_mod
    sys.modules["cryptography.hazmat"] = hazmat
    sys.modules["cryptography.hazmat.primitives"] = primitives
    sys.modules["cryptography.hazmat.primitives.hashes"] = hashes_mod
    sys.modules["cryptography.hazmat.primitives.kdf"] = kdf_mod
    sys.modules["cryptography.hazmat.primitives.kdf.pbkdf2"] = pbkdf2_mod


def _install_aiohttp_stubs() -> None:
    if not _stub_not_installed("aiohttp"):
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
    aiohttp.__spec__ = importlib.util.spec_from_loader("aiohttp", loader=None)
    sys.modules["aiohttp"] = aiohttp


def _install_aiosqlite_stubs() -> None:
    if not _stub_not_installed("aiosqlite"):
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
    aiosqlite.__spec__ = importlib.util.spec_from_loader("aiosqlite", loader=None)
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

auth_engine_module = importlib.import_module("access_control.auth_engine")
AuthEngine = auth_engine_module.AuthEngine
AccessCommandAcceptedUnconfirmedError = (
    auth_engine_module.AccessCommandAcceptedUnconfirmedError
)


# ---------------------------------------------------------------------------
# DB / client factory helpers
# ---------------------------------------------------------------------------

def make_db(
    user=None,
    groups=None,
    locks=None,
    rules=None,
    alarm_panels=None,
    group_locks=None,
):
    """Return a SimpleNamespace that mocks the Database methods used by AuthEngine."""
    return SimpleNamespace(
        get_user_by_ulp_id=AsyncMock(return_value=user),
        get_user_groups=AsyncMock(return_value=groups or []),
        get_locks_for_location=AsyncMock(return_value=locks or []),
        get_locks_by_entry_device=AsyncMock(return_value=[]),
        get_rules_for_user_and_lock=AsyncMock(return_value=rules),
        get_group_locks=AsyncMock(return_value=group_locks or []),
        get_all_alarm_panels=AsyncMock(return_value=alarm_panels or []),
        log_access=AsyncMock(return_value=1),
        get_config=AsyncMock(return_value=None),
        set_config=AsyncMock(return_value=None),
    )


def make_ha(alarm_state="disarmed"):
    """Return a mock HA client with controllable alarm state."""
    ha = MagicMock()
    ha.unlock = AsyncMock(return_value=True)
    ha.lock = AsyncMock(return_value=True)
    ha.fire_event = AsyncMock(return_value=True)
    ha.get_entity_state = AsyncMock(
        side_effect=lambda entity_id: (
            "unlocked" if entity_id.startswith("lock.") else alarm_state
        )
    )
    ha.alarm_disarm = AsyncMock(return_value=True)
    return ha


def make_active_user(user_id=1, name="Nick"):
    return {"id": user_id, "name": name, "status": "ACTIVE"}


def make_lock(lock_id=10, entity_id="lock.front", name="Front Door"):
    return {"id": lock_id, "type": "ha_external", "entity_id": entity_id, "name": name}


def make_engine(db, ha=None, access_client=None):
    if ha is None:
        ha = make_ha()
    return AuthEngine(db=db, access_client=access_client, ha_client=ha, relock_tasks={})


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestAuthEngineUnknownUser(unittest.IsolatedAsyncioTestCase):
    async def test_unknown_user_denies(self) -> None:
        db = make_db(user=None)
        engine = make_engine(db)
        result = await engine.process_event("ulp-unknown", "door-1", method="nfc")
        self.assertFalse(result["granted"])
        # Reason should mention user not found / unknown
        reason = result["reason"].lower()
        self.assertTrue("unknown" in reason or "not found" in reason or "ulp-unknown" in reason)


class TestAuthEngineDisabledUser(unittest.IsolatedAsyncioTestCase):
    async def test_disabled_user_denies(self) -> None:
        user = {"id": 1, "name": "Bob", "status": "DISABLED"}
        db = make_db(user=user)
        engine = make_engine(db)
        result = await engine.process_event("ulp-1", "door-1", method="nfc")
        self.assertFalse(result["granted"])
        self.assertIn("not active", result["reason"])


class TestAuthEngineLockdown(unittest.IsolatedAsyncioTestCase):
    async def test_lockdown_denies(self) -> None:
        user = make_active_user()
        db = make_db(user=user)
        engine = make_engine(db)
        await engine.set_lockdown(True)
        result = await engine.process_event("ulp-1", "door-1", method="nfc")
        self.assertFalse(result["granted"])
        self.assertIn("Lockdown", result["reason"])


class TestAuthEngineNoLocks(unittest.IsolatedAsyncioTestCase):
    async def test_no_locks_for_location_denies(self) -> None:
        user = make_active_user()
        db = make_db(user=user, locks=[])
        engine = make_engine(db)
        result = await engine.process_event("ulp-1", "door-99", method="nfc")
        self.assertFalse(result["granted"])
        self.assertIn("No locks", result["reason"])


class TestAuthEngineGroupAllLocks(unittest.IsolatedAsyncioTestCase):
    async def test_group_all_locks_grants_and_unlocks(self) -> None:
        """Group with all_locks=True and no schedule should grant access and call HA unlock."""
        user = make_active_user()
        group = {
            "id": 5,
            "name": "Admins",
            "all_locks": True,
            "schedule_enabled": False,
            "blocked_when_armed_away": False,
            "blocked_when_armed_home": False,
            "can_disarm": False,
        }
        lock = make_lock()
        ha = make_ha(alarm_state="disarmed")
        db = make_db(user=user, groups=[group], locks=[lock])
        engine = make_engine(db, ha=ha)

        result = await engine.process_event("ulp-1", "door-1", method="nfc")

        self.assertTrue(result["granted"])
        ha.unlock.assert_awaited_once_with("lock.front")


class TestAuthEngineScheduleInactiveDenies(unittest.IsolatedAsyncioTestCase):
    async def test_group_schedule_inactive_denies(self) -> None:
        """Group with schedule_enabled=True and a day that doesn't match today → denied."""
        user = make_active_user()
        # Use "mon" as the allowed day so we can mock now() to return a Wednesday
        group = {
            "id": 6,
            "name": "WeekdayGroup",
            "all_locks": True,
            "schedule_enabled": True,
            "schedule_days": "mon",
            "schedule_start": "00:00",
            "schedule_end": "23:59",
            "blocked_when_armed_away": False,
            "blocked_when_armed_home": False,
            "can_disarm": False,
        }
        lock = make_lock()
        ha = make_ha(alarm_state="disarmed")
        db = make_db(user=user, groups=[group], locks=[lock])
        engine = make_engine(db, ha=ha)

        # Patch datetime.now inside auth_engine to return a Wednesday (weekday=2)
        from datetime import datetime
        from zoneinfo import ZoneInfo
        wednesday = datetime(2026, 4, 22, 12, 0, 0, tzinfo=ZoneInfo("America/New_York"))  # 2026-04-22 is a Wednesday
        with patch("access_control.auth_engine.datetime") as mock_dt:
            mock_dt.now.return_value = wednesday
            result = await engine.process_event("ulp-1", "door-1", method="nfc")

        self.assertFalse(result["granted"])
        ha.unlock.assert_not_awaited()

    async def test_enabled_schedule_with_only_one_time_bound_fails_closed(self) -> None:
        """A partially saved schedule must never degrade into all-day access."""
        user = make_active_user()
        group = {
            "id": 61,
            "name": "Incomplete schedule",
            "all_locks": True,
            "schedule_enabled": True,
            "schedule_days": "",
            "schedule_start": "08:00",
            "schedule_end": None,
            "blocked_when_armed_away": False,
            "blocked_when_armed_home": False,
            "can_disarm": False,
        }
        ha = make_ha(alarm_state="disarmed")
        db = make_db(user=user, groups=[group], locks=[make_lock()])
        engine = make_engine(db, ha=ha)

        result = await engine.process_event("ulp-1", "door-1", method="nfc")

        self.assertFalse(result["granted"])
        ha.unlock.assert_not_awaited()

    async def test_enabled_empty_schedule_fails_closed(self) -> None:
        engine = make_engine(make_db())
        self.assertFalse(engine._check_schedule({
            "schedule_days": "",
            "schedule_start": None,
            "schedule_end": None,
        }))


class TestAuthEngineBlockedArmedAway(unittest.IsolatedAsyncioTestCase):
    async def test_blocked_when_armed_away_denies(self) -> None:
        """Group with blocked_when_armed_away=True and alarm armed_away → denied."""
        user = make_active_user()
        group = {
            "id": 7,
            "name": "RegularUsers",
            "all_locks": True,
            "schedule_enabled": False,
            "blocked_when_armed_away": True,
            "blocked_when_armed_home": False,
            "can_disarm": False,
        }
        lock = make_lock()
        panel = {"entity_id": "alarm_control_panel.main"}
        ha = make_ha(alarm_state="armed_away")
        db = make_db(user=user, groups=[group], locks=[lock], alarm_panels=[panel])
        engine = make_engine(db, ha=ha)

        result = await engine.process_event("ulp-1", "door-1", method="nfc")
        self.assertFalse(result["granted"])
        self.assertIn("armed away", result["reason"])


class TestAuthEngineIndividualRuleGrants(unittest.IsolatedAsyncioTestCase):
    async def test_individual_rule_grants(self) -> None:
        """User has no groups, but has an enabled individual rule → granted."""
        user = make_active_user()
        lock = make_lock()
        rule = {"enabled": 1, "schedule_enabled": 0}
        ha = make_ha(alarm_state="disarmed")
        db = make_db(user=user, groups=[], locks=[lock], rules=rule)
        engine = make_engine(db, ha=ha)

        result = await engine.process_event("ulp-1", "door-1", method="nfc")
        self.assertTrue(result["granted"])
        ha.unlock.assert_awaited_once_with("lock.front")


class TestAuthEngineIndividualRuleDisabledDenies(unittest.IsolatedAsyncioTestCase):
    async def test_individual_rule_disabled_denies(self) -> None:
        """User has an individual rule with enabled=0 → denied."""
        user = make_active_user()
        lock = make_lock()
        rule = {"enabled": 0, "schedule_enabled": 0}
        ha = make_ha(alarm_state="disarmed")
        db = make_db(user=user, groups=[], locks=[lock], rules=rule)
        engine = make_engine(db, ha=ha)

        result = await engine.process_event("ulp-1", "door-1", method="nfc")
        self.assertFalse(result["granted"])
        self.assertIn("disabled", result["reason"].lower())


class TestAuthEngineCanDisarmTriggersDisarm(unittest.IsolatedAsyncioTestCase):
    async def test_can_disarm_group_triggers_alarm_disarm_when_armed_home(self) -> None:
        """
        User in a group with can_disarm=True and blocked_when_armed_home=False.
        Alarm is armed_home.  Access should be granted AND alarm_disarm should be called.
        """
        user = make_active_user()
        group = {
            "id": 8,
            "name": "Owners",
            "all_locks": True,
            "schedule_enabled": False,
            "blocked_when_armed_away": False,
            "blocked_when_armed_home": False,
            "can_disarm": True,
        }
        lock = make_lock()
        panel = {"entity_id": "alarm_control_panel.main", "disarm_code_encrypted": None}
        ha = make_ha(alarm_state="armed_home")
        db = make_db(user=user, groups=[group], locks=[lock], alarm_panels=[panel])
        engine = make_engine(db, ha=ha)

        result = await engine.process_event("ulp-1", "door-1", method="nfc")
        self.assertTrue(result["granted"])
        ha.unlock.assert_awaited_once_with("lock.front")
        ha.alarm_disarm.assert_awaited_once_with("alarm_control_panel.main", code=None)


class TestAuthEngineNativeMomentaryConfirmation(
    unittest.IsolatedAsyncioTestCase
):
    @staticmethod
    def _group(*, can_disarm: bool = False) -> dict:
        return {
            "id": 80,
            "name": "Native access",
            "all_locks": True,
            "schedule_enabled": False,
            "blocked_when_armed_away": False,
            "blocked_when_armed_home": False,
            "can_disarm": can_disarm,
        }

    @staticmethod
    def _lock() -> dict:
        return {
            "id": 81,
            "type": "access_native",
            "device_id": "hub-native",
            "location_id": "door-native",
            "name": "Native Door",
        }

    async def test_accepted_unconfirmed_native_unlock_is_not_granted(
        self,
    ) -> None:
        panel = {
            "entity_id": "alarm_control_panel.main",
            "disarm_code_encrypted": None,
        }
        db = make_db(
            user=make_active_user(),
            groups=[self._group(can_disarm=True)],
            locks=[self._lock()],
            alarm_panels=[panel],
        )
        ha = make_ha(alarm_state="armed_home")
        access = SimpleNamespace(
            unlock_momentary_confirmed=AsyncMock(
                side_effect=AccessCommandAcceptedUnconfirmedError(
                    "bounded relay readback expired"
                )
            )
        )
        cache_update = MagicMock()
        engine = AuthEngine(
            db=db,
            access_client=access,
            ha_client=ha,
            on_lock_state=cache_update,
        )

        result = await engine.process_event(
            "ulp-native",
            "door-native",
            method="nfc",
        )

        self.assertFalse(result["granted"])
        self.assertEqual(result["locks"], [])
        self.assertIn("did not confirm unlocked", result["reason"])
        access.unlock_momentary_confirmed.assert_awaited_once()
        cache_update.assert_called_once_with("hub-native", "unknown")
        ha.fire_event.assert_not_awaited()
        ha.alarm_disarm.assert_not_awaited()
        db.log_access.assert_awaited_once_with(
            method="nfc",
            result="accepted_unconfirmed",
            user_id=1,
            user_name="Nick",
            lock_id=81,
            lock_name="Native Door",
            reason=result["reason"],
        )

    async def test_confirmed_native_unlock_is_granted_and_cached(
        self,
    ) -> None:
        db = make_db(
            user=make_active_user(),
            groups=[self._group()],
            locks=[self._lock()],
        )
        ha = make_ha()
        access = SimpleNamespace(
            unlock_momentary_confirmed=AsyncMock(
                return_value={"state": "unlocked"}
            )
        )
        cache_update = MagicMock()
        engine = AuthEngine(
            db=db,
            access_client=access,
            ha_client=ha,
            on_lock_state=cache_update,
        )

        result = await engine.process_event(
            "ulp-native",
            "door-native",
            method="face",
        )

        self.assertTrue(result["granted"])
        self.assertEqual(result["locks"], ["Native Door"])
        cache_update.assert_called_once_with("hub-native", "unlocked")
        ha.fire_event.assert_awaited_once()
        db.log_access.assert_awaited_once_with(
            method="face",
            result="granted",
            user_id=1,
            user_name="Nick",
            lock_id=81,
            lock_name="Native Door",
            reason=None,
        )

    async def test_cancel_after_native_write_marks_unknown_and_audits(
        self,
    ) -> None:
        wrote = asyncio.Event()

        async def accepted_then_wait(location_id, *, on_written=None):
            self.assertEqual(location_id, "door-native")
            if on_written is not None:
                on_written()
            wrote.set()
            await asyncio.Event().wait()

        db = make_db(
            user=make_active_user(),
            groups=[self._group()],
            locks=[self._lock()],
        )
        cache_update = MagicMock()
        engine = AuthEngine(
            db=db,
            access_client=SimpleNamespace(
                unlock_momentary_confirmed=accepted_then_wait
            ),
            ha_client=make_ha(),
            on_lock_state=cache_update,
        )

        task = asyncio.create_task(
            engine.process_event(
                "ulp-native",
                "door-native",
                method="nfc",
            )
        )
        await wrote.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task

        cache_update.assert_called_once_with("hub-native", "unknown")
        self.assertTrue(
            any(
                call.kwargs.get("result") == "accepted_unconfirmed"
                and call.kwargs.get("lock_id") == 81
                for call in db.log_access.await_args_list
            )
        )

    async def test_native_confirmation_does_not_hold_command_barrier(
        self,
    ) -> None:
        confirmation_started = asyncio.Event()
        release_confirmation = asyncio.Event()

        async def confirm_after_write(
            location_id: str,
            *,
            on_written=None,
        ) -> dict:
            self.assertEqual(location_id, "door-native")
            self.assertIsNotNone(on_written)
            on_written()
            confirmation_started.set()
            await release_confirmation.wait()
            return {"state": "unlocked"}

        db = make_db(
            user=make_active_user(),
            groups=[self._group()],
            locks=[self._lock()],
        )
        command_lock = asyncio.Lock()
        engine = AuthEngine(
            db=db,
            access_client=SimpleNamespace(
                unlock_momentary_confirmed=confirm_after_write
            ),
            ha_client=make_ha(),
            command_lock=command_lock,
        )
        task = asyncio.create_task(
            engine.process_event(
                "ulp-native",
                "door-native",
                method="nfc",
            )
        )

        acquired = False
        try:
            await asyncio.wait_for(confirmation_started.wait(), timeout=1)
            await asyncio.wait_for(command_lock.acquire(), timeout=0.25)
            acquired = True
        finally:
            if acquired:
                command_lock.release()
            release_confirmation.set()

        result = await asyncio.wait_for(task, timeout=1)
        self.assertTrue(result["granted"])


class TestAuthEngineRestrictiveAlarmStates(unittest.IsolatedAsyncioTestCase):
    """Regression: armed_night / arming / pending must block like armed_away.

    Before the 2026-07-05 fix, _get_alarm_state() could return these states
    but the block gate only recognised triggered/armed_away/armed_home/unknown,
    so a blocked-when-armed user walked in during night-arm or the entry/exit
    delay window (and could auto-disarm on a single tap).
    """

    def _blocked_group(self):
        return {
            "id": 20, "name": "Cleaners", "all_locks": True,
            "schedule_enabled": False,
            "blocked_when_armed_away": True, "blocked_when_armed_home": False,
            "can_disarm": False,
        }

    async def test_armed_night_blocks(self) -> None:
        user = make_active_user()
        panel = {"entity_id": "alarm_control_panel.main"}
        ha = make_ha(alarm_state="armed_night")
        db = make_db(user=user, groups=[self._blocked_group()],
                     locks=[make_lock()], alarm_panels=[panel])
        engine = make_engine(db, ha=ha)
        result = await engine.process_event("ulp-1", "door-1", method="nfc")
        self.assertFalse(result["granted"])
        self.assertIn("armed night", result["reason"])
        ha.unlock.assert_not_awaited()

    async def test_pending_entry_delay_blocks(self) -> None:
        user = make_active_user()
        panel = {"entity_id": "alarm_control_panel.main"}
        ha = make_ha(alarm_state="pending")
        db = make_db(user=user, groups=[self._blocked_group()],
                     locks=[make_lock()], alarm_panels=[panel])
        engine = make_engine(db, ha=ha)
        result = await engine.process_event("ulp-1", "door-1", method="nfc")
        self.assertFalse(result["granted"])
        ha.unlock.assert_not_awaited()

    async def test_arming_exit_delay_blocks(self) -> None:
        user = make_active_user()
        panel = {"entity_id": "alarm_control_panel.main"}
        ha = make_ha(alarm_state="arming")
        db = make_db(user=user, groups=[self._blocked_group()],
                     locks=[make_lock()], alarm_panels=[panel])
        engine = make_engine(db, ha=ha)
        result = await engine.process_event("ulp-1", "door-1", method="nfc")
        self.assertFalse(result["granted"])
        ha.unlock.assert_not_awaited()

    async def test_armed_night_no_autodisarm_for_blocked_can_disarm_group(self) -> None:
        """M1: a can_disarm group that is blocked for the state must neither
        grant nor auto-disarm the panel. Before the fix, armed_night skipped
        the block gate and the bare any(can_disarm) auto-disarmed from night."""
        user = make_active_user()
        group = {
            "id": 21, "name": "BlockedButCanDisarm", "all_locks": True,
            "schedule_enabled": False,
            "blocked_when_armed_away": True, "blocked_when_armed_home": False,
            "can_disarm": True,
        }
        panel = {"entity_id": "alarm_control_panel.main"}
        ha = make_ha(alarm_state="armed_night")
        db = make_db(user=user, groups=[group], locks=[make_lock()],
                     alarm_panels=[panel])
        engine = make_engine(db, ha=ha)
        result = await engine.process_event("ulp-1", "door-1", method="nfc")
        self.assertFalse(result["granted"])
        ha.unlock.assert_not_awaited()
        ha.alarm_disarm.assert_not_awaited()

    async def test_literal_unknown_state_blocks(self) -> None:
        """HA's literal ``unknown`` state is not equivalent to disarmed."""
        user = make_active_user()
        panel = {"entity_id": "alarm_control_panel.main"}
        ha = make_ha(alarm_state="unknown")
        db = make_db(
            user=user,
            groups=[self._blocked_group()],
            locks=[make_lock()],
            alarm_panels=[panel],
        )
        engine = make_engine(db, ha=ha)

        result = await engine.process_event("ulp-1", "door-1", method="nfc")

        self.assertFalse(result["granted"])
        self.assertIn("unknown", result["reason"])
        ha.unlock.assert_not_awaited()

    async def test_configured_panel_without_ha_is_unknown_not_disarmed(self) -> None:
        panel = {"entity_id": "alarm_control_panel.main"}
        db = make_db(alarm_panels=[panel])
        engine = AuthEngine(
            db=db,
            access_client=None,
            ha_client=None,
            relock_tasks={},
        )

        self.assertEqual(await engine._get_alarm_state(), "unknown")

    async def test_mixed_armed_modes_are_restrictive(self) -> None:
        """Away+home panels must not collapse to one mode and bypass a flag."""
        user = make_active_user()
        group = {
            **self._blocked_group(),
            "blocked_when_armed_away": False,
            "blocked_when_armed_home": True,
        }
        panels = [
            {"entity_id": "alarm_control_panel.house"},
            {"entity_id": "alarm_control_panel.garage"},
        ]
        ha = make_ha()
        ha.get_entity_state = AsyncMock(side_effect=["armed_away", "armed_home"])
        db = make_db(
            user=user,
            groups=[group],
            locks=[make_lock()],
            alarm_panels=panels,
        )
        engine = make_engine(db, ha=ha)

        result = await engine.process_event("ulp-1", "door-1", method="nfc")

        self.assertFalse(result["granted"])
        self.assertIn("unknown", result["reason"])
        ha.unlock.assert_not_awaited()

    async def test_disarmed_result_is_never_cached(self) -> None:
        """A panel that arms just after a permissive read must be re-read."""
        panel = {"entity_id": "alarm_control_panel.main"}
        db = make_db(alarm_panels=[panel])
        ha = make_ha()
        ha.get_entity_state = AsyncMock(side_effect=["disarmed", "armed_away"])
        engine = make_engine(db, ha=ha)

        self.assertEqual(await engine._get_alarm_state(), "disarmed")
        self.assertEqual(await engine._get_alarm_state(), "armed_away")
        self.assertEqual(ha.get_entity_state.await_count, 2)


class TestAuthEngineLastMomentLockdown(unittest.IsolatedAsyncioTestCase):
    async def test_lockdown_enabled_during_rule_lookup_prevents_unlock(self) -> None:
        """A concurrent lockdown wins until the physical command is issued."""
        user = make_active_user()
        ha = make_ha(alarm_state="disarmed")
        db = make_db(user=user, groups=[], locks=[make_lock()])
        engine = make_engine(db, ha=ha)

        async def authorize_then_lock_down(*_args):
            engine._lockdown = True
            return {"enabled": 1, "schedule_enabled": 0}

        db.get_rules_for_user_and_lock = AsyncMock(
            side_effect=authorize_then_lock_down
        )

        result = await engine.process_event("ulp-1", "door-1", method="nfc")

        self.assertFalse(result["granted"])
        self.assertIn("Lockdown", result["reason"])
        ha.unlock.assert_not_awaited()


class TestAuthEngineLocationResolution(unittest.IsolatedAsyncioTestCase):
    async def test_access_location_resolves_inverse_protect_camera_mapping(self) -> None:
        """Access events carry a location id while pairing stores camera id."""
        lock = make_lock()
        db = make_db(locks=[])

        async def paired_locks(device_type, *, device_id):
            if device_type == "protect_doorbell" and device_id == "camera-g6":
                return [lock]
            return []

        db.get_locks_by_entry_device = AsyncMock(side_effect=paired_locks)
        engine = AuthEngine(
            db=db,
            access_client=None,
            ha_client=make_ha(),
            relock_tasks={},
            camera_map_getter=lambda: {"camera-g6": "location-front"},
        )

        locks = await engine.get_locks_for_location("location-front")

        self.assertEqual(locks, [lock])
        db.get_locks_by_entry_device.assert_any_await(
            "protect_doorbell", device_id="camera-g6"
        )


class TestAuthEngineLockdownPersistence(unittest.IsolatedAsyncioTestCase):
    """Regression: lockdown must persist across restart (2026-07-05 fix)."""

    async def test_set_lockdown_persists_to_config(self) -> None:
        db = make_db(user=make_active_user())
        engine = make_engine(db)
        await engine.set_lockdown(True)
        self.assertTrue(engine.lockdown)
        db.set_config.assert_awaited_once_with("lockdown", "1")
        await engine.set_lockdown(False)
        db.set_config.assert_awaited_with("lockdown", "0")

    async def test_load_persisted_lockdown_restores_enabled(self) -> None:
        db = make_db(user=make_active_user())
        db.get_config = AsyncMock(return_value="1")
        engine = make_engine(db)
        self.assertFalse(engine.lockdown)
        await engine.load_persisted_lockdown()
        self.assertTrue(engine.lockdown)

    async def test_load_persisted_lockdown_defaults_disabled(self) -> None:
        db = make_db(user=make_active_user())
        db.get_config = AsyncMock(return_value=None)
        engine = make_engine(db)
        await engine.load_persisted_lockdown()
        self.assertFalse(engine.lockdown)

    async def test_load_persisted_lockdown_read_error_fails_closed(self) -> None:
        db = make_db(user=make_active_user())
        db.get_config = AsyncMock(side_effect=OSError("database unavailable"))
        engine = make_engine(db)

        await engine.load_persisted_lockdown()

        self.assertTrue(engine.lockdown)

    async def test_failed_disable_remains_fail_closed(self) -> None:
        db = make_db(user=make_active_user())
        engine = make_engine(db)
        engine._lockdown = True
        db.set_config = AsyncMock(side_effect=RuntimeError("disk full"))

        with self.assertRaises(RuntimeError):
            await engine.set_lockdown(False)

        self.assertTrue(engine.lockdown)

    async def test_concurrent_transitions_are_serialized(self) -> None:
        db = make_db(user=make_active_user())
        writes: list[str] = []
        disable_started = asyncio.Event()
        release_disable = asyncio.Event()

        async def persist(_key, value):
            writes.append(value)
            if value == "0":
                disable_started.set()
                await release_disable.wait()

        db.set_config = AsyncMock(side_effect=persist)
        engine = make_engine(db)
        engine._lockdown = True

        disable = asyncio.create_task(engine.set_lockdown(False))
        await disable_started.wait()
        enable = asyncio.create_task(engine.set_lockdown(True))
        await asyncio.sleep(0)
        self.assertTrue(engine.lockdown)
        release_disable.set()
        await asyncio.gather(disable, enable)

        self.assertEqual(writes, ["0", "1"])
        self.assertTrue(engine.lockdown)

    async def test_enforcement_failure_surfaces_but_keeps_lockdown_enabled(self) -> None:
        db = make_db(user=make_active_user())
        enforce = AsyncMock(side_effect=RuntimeError("hub still open"))
        engine = AuthEngine(
            db=db,
            access_client=None,
            ha_client=make_ha(),
            on_lockdown_enabled=enforce,
        )

        with self.assertRaises(RuntimeError):
            await engine.set_lockdown(True)

        self.assertTrue(engine.lockdown)
        enforce.assert_awaited_once()


class TestScheduleTimezone(unittest.TestCase):
    """Schedules must evaluate in the site's timezone, not a hardcoded one
    (e2e review 2026-07-12: _TZ was pinned to America/New_York)."""

    def test_set_timezone_valid_and_invalid(self) -> None:
        engine = make_engine(make_db())
        self.assertTrue(engine.set_timezone("Europe/Berlin"))
        self.assertEqual(str(engine.tz), "Europe/Berlin")
        # Invalid zone is rejected and the current zone is kept.
        self.assertFalse(engine.set_timezone("Not/AZone"))
        self.assertEqual(str(engine.tz), "Europe/Berlin")

    def test_schedule_day_follows_configured_timezone(self) -> None:
        from datetime import datetime
        from zoneinfo import ZoneInfo

        engine = make_engine(make_db())
        day_names = auth_engine_module.DAY_NAMES

        # Etc/GMT-14 is UTC+14 and Etc/GMT+12 is UTC-12 — 26 hours apart,
        # so the calendar date (and therefore weekday) ALWAYS differs
        # between them at any instant. A day-restricted schedule must
        # follow the configured zone's weekday.
        east = "Etc/GMT-14"
        west = "Etc/GMT+12"
        east_day = day_names[datetime.now(ZoneInfo(east)).weekday()]
        west_day = day_names[datetime.now(ZoneInfo(west)).weekday()]
        self.assertNotEqual(east_day, west_day)

        rule = {"schedule_days": east_day, "schedule_start": None, "schedule_end": None}
        self.assertTrue(engine.set_timezone(east))
        self.assertTrue(engine._check_schedule(rule))
        # Same rule, same instant — a zone on the other side of the date
        # line is on a different weekday, so the schedule must deny.
        self.assertTrue(engine.set_timezone(west))
        self.assertFalse(engine._check_schedule(rule))


class TestCredentialHaUnlockSafety(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def _lock(**overrides):
        lock = {
            "id": 30,
            "type": "ha_external",
            "entity_id": "lock.credential",
            "name": "Credential Door",
            "relock_on_device_auth": 1,
            "relock_duration": 30,
        }
        lock.update(overrides)
        return lock

    @staticmethod
    def _db(lock):
        return make_db(
            user=make_active_user(),
            groups=[
                {
                    "id": 1,
                    "all_locks": True,
                    "schedule_enabled": False,
                }
            ],
            locks=[lock],
        )

    @staticmethod
    def _manager(intent):
        return SimpleNamespace(
            schedule=AsyncMock(return_value=intent),
            retain_after_uncertain_unlock=AsyncMock(return_value=True),
            extend_after_success=AsyncMock(return_value=True),
            pause=AsyncMock(return_value=None),
            resume=AsyncMock(return_value=True),
            cancel=AsyncMock(),
        )

    async def test_releases_barrier_then_confirms_and_updates_cache_callback(
        self,
    ) -> None:
        lock = self._lock()
        db = self._db(lock)
        intent = object()
        manager = self._manager(intent)
        barrier = asyncio.Lock()
        confirmation_started = asyncio.Event()
        confirmation_release = asyncio.Event()
        cache_update = MagicMock()
        ha = make_ha()

        async def confirm(entity_id):
            self.assertEqual(entity_id, "lock.credential")
            confirmation_started.set()
            await confirmation_release.wait()
            return "unlocked"

        ha.get_entity_state = AsyncMock(side_effect=confirm)
        engine = AuthEngine(
            db=db,
            access_client=None,
            ha_client=ha,
            relock_manager=manager,
            command_lock=barrier,
            on_lock_state=cache_update,
        )

        task = asyncio.create_task(
            engine.process_event("ulp-1", "door-1", method="nfc")
        )
        await confirmation_started.wait()

        # The HA write has returned, so confirmation must not own the app-wide
        # physical-command barrier and the credential is not granted yet.
        await asyncio.wait_for(barrier.acquire(), timeout=0.2)
        barrier.release()
        self.assertFalse(task.done())
        cache_update.assert_not_called()

        confirmation_release.set()
        result = await task

        self.assertTrue(result["granted"])
        cache_update.assert_called_once_with("lock.credential", "unlocked")
        manager.extend_after_success.assert_awaited_once_with(intent, 30)
        manager.retain_after_uncertain_unlock.assert_not_awaited()

    async def test_unconfirmed_unlock_is_not_granted_and_retains_intent(
        self,
    ) -> None:
        lock = self._lock()
        db = self._db(lock)
        intent = object()
        manager = self._manager(intent)
        cache_update = MagicMock()
        ha = make_ha()
        ha.get_entity_state = AsyncMock(return_value="locked")
        engine = AuthEngine(
            db=db,
            access_client=None,
            ha_client=ha,
            relock_manager=manager,
            on_lock_state=cache_update,
        )

        with patch.object(auth_engine_module, "_HA_CONFIRM_INTERVAL", 0):
            result = await engine.process_event(
                "ulp-1", "door-1", method="nfc"
            )

        self.assertFalse(result["granted"])
        self.assertEqual(ha.get_entity_state.await_count, 3)
        cache_update.assert_called_once_with("lock.credential", "unknown")
        manager.retain_after_uncertain_unlock.assert_awaited_once_with(intent)
        manager.extend_after_success.assert_not_awaited()
        self.assertTrue(
            any(
                call.kwargs.get("result") == "accepted_unconfirmed"
                and call.kwargs.get("lock_id") == 30
                for call in db.log_access.await_args_list
            )
        )

    async def test_cancelled_confirmation_retains_intent_before_propagating(
        self,
    ) -> None:
        lock = self._lock()
        db = self._db(lock)
        intent = object()
        confirmation_started = asyncio.Event()
        retain_started = asyncio.Event()
        retain_release = asyncio.Event()

        async def confirm(_entity_id):
            confirmation_started.set()
            await asyncio.Event().wait()

        async def retain(received_intent):
            self.assertIs(received_intent, intent)
            retain_started.set()
            await retain_release.wait()
            return True

        manager = self._manager(intent)
        manager.retain_after_uncertain_unlock = AsyncMock(side_effect=retain)
        ha = make_ha()
        ha.get_entity_state = AsyncMock(side_effect=confirm)
        engine = AuthEngine(
            db=db,
            access_client=None,
            ha_client=ha,
            relock_manager=manager,
        )

        task = asyncio.create_task(
            engine.process_event("ulp-1", "door-1", method="nfc")
        )
        await confirmation_started.wait()
        task.cancel()
        await retain_started.wait()
        self.assertFalse(task.done())

        retain_release.set()
        with self.assertRaises(asyncio.CancelledError):
            await task

        manager.retain_after_uncertain_unlock.assert_awaited_once_with(intent)
        manager.extend_after_success.assert_not_awaited()


class TestDeviceAuthMomentaryLease(unittest.IsolatedAsyncioTestCase):
    """Change 1: a device-auth timed unlock on a synced lock leases a momentary
    Access hold so the hub poller does not echo it back as keep_unlock."""

    def _relock(self):
        return SimpleNamespace(
            schedule=AsyncMock(return_value=object()),
            extend_after_success=AsyncMock(),
            cancel=AsyncMock(),
            pause=AsyncMock(return_value=None),
            resume=AsyncMock(),
        )

    def _engine(self, relock, hub_sync):
        ha = make_ha()
        ha.get_entity_state = AsyncMock(return_value="unlocked")
        return AuthEngine(
            db=make_db(),
            access_client=None,
            ha_client=ha,
            relock_tasks={},
            relock_manager=relock,
            hub_sync_getter=lambda: hub_sync,
        )

    async def test_relock_enabled_synced_lock_leases_momentary(self) -> None:
        relock = self._relock()
        hub_sync = SimpleNamespace(mark_access_momentary=MagicMock())
        engine = self._engine(relock, hub_sync)
        lock = {
            "id": 10, "type": "ha_external", "entity_id": "lock.front",
            "name": "Front", "relock_on_device_auth": 1,
            "sync_hub_state": 1, "relock_duration": 45,
        }
        await engine._unlock(lock)
        relock.schedule.assert_awaited_once()
        hub_sync.mark_access_momentary.assert_called_once_with("lock.front", 45.0)

    async def test_relock_enabled_unsynced_lock_does_not_lease(self) -> None:
        relock = self._relock()
        hub_sync = SimpleNamespace(mark_access_momentary=MagicMock())
        engine = self._engine(relock, hub_sync)
        lock = {
            "id": 10, "type": "ha_external", "entity_id": "lock.front",
            "name": "Front", "relock_on_device_auth": 1,
            "sync_hub_state": 0, "relock_duration": 30,
        }
        await engine._unlock(lock)
        relock.schedule.assert_awaited_once()
        hub_sync.mark_access_momentary.assert_not_called()

    async def test_relock_disabled_synced_lock_does_not_lease(self) -> None:
        relock = self._relock()
        hub_sync = SimpleNamespace(
            mark_access_momentary=MagicMock(),
            mark_app_initiated_unlock=MagicMock(),
        )
        engine = self._engine(relock, hub_sync)
        lock = {
            "id": 10, "type": "ha_external", "entity_id": "lock.front",
            "name": "Front", "relock_on_device_auth": 0,
            "sync_hub_state": 1, "relock_duration": 30,
        }
        await engine._unlock(lock)
        relock.schedule.assert_not_awaited()
        hub_sync.mark_access_momentary.assert_not_called()

    async def test_relock_disabled_tap_marks_app_initiated_hold_open(self) -> None:
        # relock_on_device_auth OFF means an authorized tap is a chosen
        # hold-open (the success path cancels any pending timer). It must be
        # marked app-initiated so relock_on_ha_origin — which covers external
        # unlocks only — cannot silently re-time it; the same exclusion the
        # manual dashboard Unlock gets.
        relock = self._relock()
        hub_sync = SimpleNamespace(
            mark_access_momentary=MagicMock(),
            mark_app_initiated_unlock=MagicMock(),
        )
        engine = self._engine(relock, hub_sync)
        lock = {
            "id": 10, "type": "ha_external", "entity_id": "lock.front",
            "name": "Front", "relock_on_device_auth": 0,
            "sync_hub_state": 1, "relock_duration": 30,
        }
        await engine._unlock(lock)
        hub_sync.mark_app_initiated_unlock.assert_called_once_with("lock.front")

    async def test_relock_disabled_unsynced_tap_does_not_mark(self) -> None:
        relock = self._relock()
        hub_sync = SimpleNamespace(
            mark_access_momentary=MagicMock(),
            mark_app_initiated_unlock=MagicMock(),
        )
        engine = self._engine(relock, hub_sync)
        lock = {
            "id": 10, "type": "ha_external", "entity_id": "lock.front",
            "name": "Front", "relock_on_device_auth": 0,
            "sync_hub_state": 0, "relock_duration": 30,
        }
        await engine._unlock(lock)
        hub_sync.mark_app_initiated_unlock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
