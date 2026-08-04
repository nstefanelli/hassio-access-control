"""Regression tests for the 2026-08 core review findings in main.py.

- CORE-2: the resolved HA timezone is persisted and reloaded at startup so
  a boot while HA Core is down does not evaluate schedules in
  container-local time (UTC on stock HAOS) until the next health tick.
- CORE-3: only door-relevant WS events refresh the ws_last_event guard —
  periodic non-door chatter (motion, device status, insights) must not
  hold the scheduled maintenance reboot off forever.
- CORE-4: a failed topology sync during Access bring-up schedules a
  short-interval capped-backoff retry instead of leaving door-event
  intake fail-closed for up to 15 minutes until the periodic resync.
"""
from __future__ import annotations

import asyncio
import contextlib
import importlib
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

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


def _reload_access_control_modules():
    _load_package()
    module_names = [
        "access_control.database",
        "access_control.config",
        "access_control.web_auth",
        "access_control.api_auth",
        "access_control.access_client",
        "access_control.protect_client",
        "access_control.ha_client",
        "access_control.auth_engine",
        "access_control.api_routes",
        "access_control.web_routes",
        "access_control.main",
    ]
    # Only database.py captures DATA_DIR at import and main.py owns the app
    # singleton that must be rebuilt around that database — same rationale
    # as test_event_dispatch.py.
    reload_names = {
        "access_control.database",
        "access_control.main",
    }
    loaded = {}
    for name in module_names:
        if name in reload_names and name in sys.modules:
            loaded[name] = importlib.reload(sys.modules[name])
        else:
            loaded[name] = importlib.import_module(name)
    return loaded


def _make_engine_mock() -> MagicMock:
    engine = MagicMock()
    engine.process_event = AsyncMock(return_value={
        "granted": True, "user_name": "User", "reason": "ok",
        "locks": ["Front Door"],
    })
    engine.get_locks_for_location = AsyncMock(return_value=[])
    return engine


def _deps_available() -> bool:
    for name in ("fastapi", "aiohttp", "aiosqlite"):
        try:
            if importlib.util.find_spec(name) is None:
                return False
        except ValueError:
            return False
    return True


_ZERO_TOPOLOGY_STATS = {
    "users_seen": 0,
    "users_inserted": 0,
    "users_updated": 0,
    "users_marked_deleted": 0,
    "users_unchanged": 0,
    "locks_seen": 0,
    "locks_inserted": 0,
    "locks_updated": 0,
    "locks_unchanged": 0,
}


class _ConsoleMock:
    """Minimal Access/Protect console double for configured bring-up."""

    def __init__(self) -> None:
        self.connected = True
        self.open_api_configured = False
        self.login = AsyncMock()
        self.validate_open_api = AsyncMock(return_value=False)
        self.close = AsyncMock()
        self.start_websocket = AsyncMock()
        self.stop_websocket = MagicMock()
        self.register_callback = MagicMock()
        self.get_console_identity = AsyncMock(return_value="site-identity")
        self.verify_console_identity = AsyncMock(return_value="site-identity")
        self.fetch_users = AsyncMock(return_value=[])
        self.get_bootstrap = AsyncMock(return_value={"data": []})
        self.parse_doors_and_devices = MagicMock(return_value=[])


@unittest.skipIf(
    not _deps_available(),
    "fastapi/aiohttp/aiosqlite not importable in this environment",
)
class CoreReviewRegressionBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self._old_data_dir = os.environ.get("DATA_DIR")
        os.environ["DATA_DIR"] = self.tempdir.name
        self.modules = _reload_access_control_modules()

    def tearDown(self) -> None:
        if self._old_data_dir is None:
            os.environ.pop("DATA_DIR", None)
        else:
            os.environ["DATA_DIR"] = self._old_data_dir
        self.tempdir.cleanup()

    def _run_in_lifespan(self, body, patches=()) -> None:
        app_module = self.modules["access_control.main"]
        app = app_module.app

        # A failure must NOT propagate through the lifespan's yield point:
        # exit the context cleanly first, then re-raise (see
        # test_event_dispatch for the rationale).
        async def go():
            failure: list[BaseException] = []
            with contextlib.ExitStack() as stack:
                for patcher in patches:
                    stack.enter_context(patcher)
                async with app_module.lifespan(app):
                    try:
                        await body(app)
                    except BaseException as exc:  # noqa: BLE001 — re-raised
                        failure.append(exc)
            if failure:
                raise failure[0]

        asyncio.run(go())


class DoorEventStampTests(CoreReviewRegressionBase):
    """CORE-3: ws_last_event must record door-relevant events only."""

    def test_non_door_protect_chatter_does_not_stamp_guard(self) -> None:
        async def body(app):
            app.state.event_topology_ready = True
            app.state.auth_engine = _make_engine_mock()

            app.state.on_protect_event(
                {"event": "motion", "camera_id": "cam-1"}
            )
            app.state.on_protect_event(
                {"event": "device_status", "camera_id": "cam-1"}
            )
            await asyncio.sleep(0.05)

            self.assertIsNone(app.state.ws_last_event["protect"])

        self._run_in_lifespan(body)

    def test_protect_ring_and_nfc_stamp_guard(self) -> None:
        async def body(app):
            app.state.event_topology_ready = True
            app.state.auth_engine = _make_engine_mock()

            app.state.on_protect_event(
                {"event": "ring", "camera_id": "cam-1"}
            )
            await asyncio.sleep(0.05)
            self.assertIsNotNone(app.state.ws_last_event["protect"])

            app.state.ws_last_event["protect"] = None
            app.state.on_protect_event(
                {"event": "nfc", "camera_id": "cam-1", "ulp_id": "u-1"}
            )
            await asyncio.sleep(0.1)
            self.assertIsNotNone(app.state.ws_last_event["protect"])

        self._run_in_lifespan(body)

    def test_non_door_access_chatter_does_not_stamp_guard(self) -> None:
        async def body(app):
            app.state.event_topology_ready = True
            app.state.auth_engine = _make_engine_mock()

            # Insights chatter and unrelated event types are filtered out
            # before any door handling — neither may refresh the guard.
            app.state.on_access_event(
                {"event": "access.logs.insights.add", "data": {}}
            )
            app.state.on_access_event(
                {"event": "access.device.update", "data": {}}
            )
            await asyncio.sleep(0.05)

            self.assertIsNone(app.state.ws_last_event["access"])

        self._run_in_lifespan(body)

    def test_access_door_event_stamps_guard(self) -> None:
        async def body(app):
            app.state.event_topology_ready = True
            app.state.auth_engine = _make_engine_mock()

            app.state.on_access_event({
                "event": "entry",
                "data": {"ulp_id": "u-1", "location_id": "door-1"},
            })
            await asyncio.sleep(0.1)

            self.assertIsNotNone(app.state.ws_last_event["access"])

        self._run_in_lifespan(body)


class TopologyBringupRetryTests(CoreReviewRegressionBase):
    """CORE-4: the bring-up retry helper drives sync_users to success."""

    def _fast_retry_patches(self):
        app_module = self.modules["access_control.main"]
        return (
            patch.object(
                app_module, "_TOPOLOGY_RETRY_INITIAL_DELAY_SECONDS", 0.01
            ),
            patch.object(
                app_module, "_TOPOLOGY_RETRY_MAX_DELAY_SECONDS", 0.05
            ),
        )

    def test_retry_repeats_with_backoff_until_sync_succeeds(self) -> None:
        async def body(app):
            app.state.access_client = MagicMock()
            app.state.event_topology_ready = False
            sync_calls: list[int] = []

            async def flaky_sync():
                sync_calls.append(1)
                if len(sync_calls) < 3:
                    raise RuntimeError("flaky topology fetch")
                app.state.event_topology_ready = True

            app.state.sync_users = flaky_sync
            app.state.schedule_topology_bringup_retry()
            task = app.state.topology_retry_task
            self.assertIsNotNone(task)

            for _ in range(300):
                if app.state.event_topology_ready:
                    break
                await asyncio.sleep(0.01)

            self.assertTrue(app.state.event_topology_ready)
            self.assertEqual(len(sync_calls), 3)
            await asyncio.wait_for(task, timeout=1)

        self._run_in_lifespan(body, patches=self._fast_retry_patches())

    def test_schedule_is_single_flight(self) -> None:
        async def body(app):
            app.state.access_client = MagicMock()
            app.state.event_topology_ready = False

            async def never_succeeds():
                raise RuntimeError("still down")

            app.state.sync_users = never_succeeds
            app.state.schedule_topology_bringup_retry()
            first = app.state.topology_retry_task
            app.state.schedule_topology_bringup_retry()

            self.assertIs(app.state.topology_retry_task, first)
            first.cancel()
            await asyncio.gather(first, return_exceptions=True)

        self._run_in_lifespan(body, patches=self._fast_retry_patches())

    def test_retry_stops_when_client_is_gone(self) -> None:
        async def body(app):
            app.state.access_client = None
            app.state.event_topology_ready = False
            sync = AsyncMock()
            app.state.sync_users = sync

            app.state.schedule_topology_bringup_retry()
            await asyncio.wait_for(app.state.topology_retry_task, timeout=1)

            sync.assert_not_awaited()

        self._run_in_lifespan(body, patches=self._fast_retry_patches())

    def test_pending_retry_is_cancelled_on_shutdown(self) -> None:
        pending: list[asyncio.Task] = []

        async def body(app):
            app.state.access_client = MagicMock()
            app.state.event_topology_ready = False

            async def never_succeeds():
                raise RuntimeError("console still booting")

            app.state.sync_users = never_succeeds
            app.state.schedule_topology_bringup_retry()
            pending.append(app.state.topology_retry_task)
            await asyncio.sleep(0.05)
            self.assertFalse(pending[0].done())
            # Returning enters lifespan shutdown, which must cancel the
            # tracked retry before clients/SQLite are closed underneath it.

        self._run_in_lifespan(body, patches=self._fast_retry_patches())
        self.assertTrue(pending[0].cancelled())


class ConfiguredStartupWiringTests(CoreReviewRegressionBase):
    """Configured-lifespan wiring for CORE-2 and CORE-4, with all
    external dependencies patched (mirrors StartupSafetyWiringTests)."""

    _CONFIG_VALUES = {
        "admin_username": "admin",
        "admin_password_hash": "hash",
        "encryption_salt": "00" * 16,
        "secret_key": "secret",
        "secret_key_source": "database",
        "secret_key_fingerprint": "fingerprint",
        "unvr_host": "unvr.local",
        "unvr_username": "unvr-user",
        "unvr_password": "unvr-pass",
        "ha_url": "http://ha.local",
        "ha_token": "ha-token",
    }

    def _db(self, config_values: dict) -> SimpleNamespace:
        return SimpleNamespace(
            connect=AsyncMock(),
            close=AsyncMock(),
            get_config=AsyncMock(
                side_effect=lambda key: config_values.get(key)
            ),
            set_config=AsyncMock(),
            get_all_locks=AsyncMock(return_value=[]),
            get_user_count=AsyncMock(return_value=0),
            sync_topology=AsyncMock(return_value=dict(_ZERO_TOPOLOGY_STATS)),
            prune_runtime_state=AsyncMock(),
        )

    def _configured_patches(self, *, db, access, protect, ha, engine):
        app_module = self.modules["access_control.main"]
        relock = SimpleNamespace(
            rehydrate=AsyncMock(),
            sweep_overdue=AsyncMock(return_value=0),
            shutdown=AsyncMock(),
            schedule=AsyncMock(),
        )
        hub = SimpleNamespace(
            recover=AsyncMock(return_value=0),
            enforce_lockdown=AsyncMock(return_value=0),
            poll_once=AsyncMock(return_value=0),
            shutdown=AsyncMock(return_value=0),
        )

        class HubFactory:
            POLL_INTERVAL = 60

            def __call__(self, **_kwargs):
                return hub

        return [
            patch.object(app_module, "Database", return_value=db),
            patch.object(app_module, "AccessClient", return_value=access),
            patch.object(app_module, "ProtectClient", return_value=protect),
            patch.object(app_module, "HAClient", return_value=ha),
            patch.object(
                app_module, "RelockManager", return_value=relock
            ),
            patch.object(app_module, "HubSyncManager", new=HubFactory()),
            patch.object(app_module, "AuthEngine", return_value=engine),
            patch.object(
                app_module,
                "resolve_secret_key",
                return_value=("secret", "database"),
            ),
            patch.object(app_module, "derive_key", return_value=b"k" * 32),
            patch.object(
                app_module, "decrypt_value", side_effect=lambda value, _key: value
            ),
        ]

    def _run_configured(self, patches, body) -> None:
        app_module = self.modules["access_control.main"]
        app = SimpleNamespace(state=SimpleNamespace())

        async def go():
            failure: list[BaseException] = []
            with contextlib.ExitStack() as stack:
                for patcher in patches:
                    stack.enter_context(patcher)
                async with app_module.lifespan(app):
                    try:
                        await body(app)
                    except BaseException as exc:  # noqa: BLE001 — re-raised
                        failure.append(exc)
            if failure:
                raise failure[0]

        asyncio.run(go())

    def test_persisted_timezone_is_loaded_at_boot_while_ha_down(self) -> None:
        """CORE-2 load wiring: with HA unreachable at boot, the persisted
        ha_timezone must be applied before event processing starts."""
        config_values = dict(
            self._CONFIG_VALUES, ha_timezone="Pacific/Auckland"
        )
        db = self._db(config_values)
        access = _ConsoleMock()
        protect = _ConsoleMock()
        ha = SimpleNamespace(
            connected=False,
            test_connection=AsyncMock(return_value=False),
            close=AsyncMock(),
        )
        engine = SimpleNamespace(
            lockdown=False,
            tz=None,
            load_persisted_lockdown=AsyncMock(),
            set_timezone=MagicMock(return_value=True),
            get_locks_for_location=AsyncMock(return_value=[]),
        )

        async def body(app):
            engine.set_timezone.assert_any_call("Pacific/Auckland")
            # HA never answered, so no upstream zone overrode the load.
            self.assertTrue(app.state.ha_unhealthy)

        self._run_configured(
            self._configured_patches(
                db=db, access=access, protect=protect, ha=ha, engine=engine
            ),
            body,
        )

    def test_boot_timezone_fetch_uses_persisting_apply(self) -> None:
        """CORE-2 persist wiring: a successful boot-time HA timezone fetch
        must go through apply_ha_timezone (which persists) rather than
        the memory-only set_timezone."""
        db = self._db(dict(self._CONFIG_VALUES))
        access = _ConsoleMock()
        protect = _ConsoleMock()
        ha = SimpleNamespace(
            connected=True,
            test_connection=AsyncMock(return_value=True),
            get_timezone=AsyncMock(return_value="Europe/Berlin"),
            close=AsyncMock(),
        )
        engine = SimpleNamespace(
            lockdown=False,
            tz=None,
            load_persisted_lockdown=AsyncMock(),
            set_timezone=MagicMock(return_value=True),
            apply_ha_timezone=AsyncMock(return_value=True),
            get_locks_for_location=AsyncMock(return_value=[]),
        )

        async def body(app):
            engine.apply_ha_timezone.assert_awaited_once_with("Europe/Berlin")

        self._run_configured(
            self._configured_patches(
                db=db, access=access, protect=protect, ha=ha, engine=engine
            ),
            body,
        )

    def test_bringup_sync_failure_schedules_retry_until_topology_ready(
        self,
    ) -> None:
        """CORE-4 wiring: a failed sync_users() during Access bring-up must
        schedule the short-interval retry, which recovers event intake
        without waiting for the 900s periodic resync."""
        app_module = self.modules["access_control.main"]
        db = self._db(dict(self._CONFIG_VALUES))
        access = _ConsoleMock()
        fetch_calls: list[int] = []

        async def flaky_fetch_users():
            fetch_calls.append(1)
            if len(fetch_calls) == 1:
                raise RuntimeError("flaky bring-up fetch")
            return []

        access.fetch_users = AsyncMock(side_effect=flaky_fetch_users)
        protect = _ConsoleMock()
        ha = SimpleNamespace(
            connected=False,
            test_connection=AsyncMock(return_value=False),
            close=AsyncMock(),
        )
        engine = SimpleNamespace(
            lockdown=False,
            tz=None,
            load_persisted_lockdown=AsyncMock(),
            set_timezone=MagicMock(return_value=True),
            get_locks_for_location=AsyncMock(return_value=[]),
        )
        patches = self._configured_patches(
            db=db, access=access, protect=protect, ha=ha, engine=engine
        )
        patches.extend([
            patch.object(
                app_module, "_TOPOLOGY_RETRY_INITIAL_DELAY_SECONDS", 0.01
            ),
            patch.object(
                app_module, "_TOPOLOGY_RETRY_MAX_DELAY_SECONDS", 0.05
            ),
        ])

        async def body(app):
            # The failed bring-up sync must have armed the retry task.
            self.assertIsNotNone(app.state.topology_retry_task)
            for _ in range(300):
                if app.state.event_topology_ready:
                    break
                await asyncio.sleep(0.01)
            self.assertTrue(app.state.event_topology_ready)
            self.assertGreaterEqual(len(fetch_calls), 2)

        self._run_configured(patches, body)


if __name__ == "__main__":
    unittest.main()
