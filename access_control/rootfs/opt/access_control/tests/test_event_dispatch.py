"""Regression tests for main.py's WS event dispatch closures, driven
through the real lifespan (unconfigured mode still registers the
callbacks on app.state).

Covers two e2e-review 2026-07-12 findings:

- Protect nfc/fingerprint events bypassed dedup entirely, so a single
  G6 tap that arrives via BOTH the Protect and Access WS paths unlocked
  (and auto-disarmed) twice.
- The remote-unlock relock path resolved locks with the bare DB column
  lookup, missing entry-device-paired locks — a remote unlock never
  scheduled a relock and the door stayed open.
"""
from __future__ import annotations

import asyncio
import importlib
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

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
    loaded = {}
    for name in module_names:
        if name in sys.modules:
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
    """True when fastapi/aiohttp/aiosqlite are importable — either the
    real packages (CI) or the stub modules the unit-test files install
    when run as a full suite. Standalone runs without either skip, same
    as test_integration."""
    for name in ("fastapi", "aiohttp", "aiosqlite"):
        try:
            if importlib.util.find_spec(name) is None:
                return False
        except ValueError:
            return False
    return True


@unittest.skipIf(
    not _deps_available(),
    "fastapi/aiohttp/aiosqlite not importable in this environment",
)
class EventDispatchTests(unittest.TestCase):
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

    def _run_in_lifespan(self, body) -> None:
        app_module = self.modules["access_control.main"]
        app = app_module.app

        # A failure must NOT propagate through the lifespan's yield point:
        # that skips the shutdown block (no try/finally around the yield),
        # leaking the aiosqlite connection thread — pytest then hangs at
        # exit on the non-daemon thread. Exit the context cleanly first,
        # then re-raise.
        async def go():
            failure: list[BaseException] = []
            async with app_module.lifespan(app):
                try:
                    await body(app)
                except BaseException as exc:  # noqa: BLE001 — re-raised below
                    failure.append(exc)
            if failure:
                raise failure[0]

        asyncio.run(go())

    def test_protect_nfc_deduped_across_redelivery(self) -> None:
        """The same Protect nfc event delivered twice must process once."""
        async def body(app):
            engine = _make_engine_mock()
            app.state.auth_engine = engine
            app.state.camera_to_location = {"cam-1": "door-loc-1"}

            message = {"event": "nfc", "camera_id": "cam-1", "ulp_id": "u-1"}
            app.state.on_protect_event(message)
            app.state.on_protect_event(dict(message))
            await asyncio.sleep(0.2)

            self.assertEqual(engine.process_event.await_count, 1)

        self._run_in_lifespan(body)

    def test_protect_nfc_dedups_against_access_ws_path(self) -> None:
        """One physical tap arrives via Protect (camera id) AND the Access
        WS (door location id). The Protect path must record the mapped
        door location so the Access-path duplicate is suppressed."""
        async def body(app):
            engine = _make_engine_mock()
            app.state.auth_engine = engine
            app.state.camera_to_location = {"cam-1": "door-loc-1"}

            app.state.on_protect_event(
                {"event": "nfc", "camera_id": "cam-1", "ulp_id": "u-1"}
            )
            await asyncio.sleep(0.1)
            # Same tap surfaces on the Access WS with the door location.
            app.state.on_access_event({
                "event": "entry",
                "data": {"ulp_id": "u-1", "location_id": "door-loc-1"},
            })
            await asyncio.sleep(0.2)

            self.assertEqual(engine.process_event.await_count, 1)

        self._run_in_lifespan(body)

    def test_protect_nfc_without_mapping_still_dedups_by_camera(self) -> None:
        async def body(app):
            engine = _make_engine_mock()
            app.state.auth_engine = engine
            app.state.camera_to_location = {}

            message = {"event": "nfc", "camera_id": "cam-9", "ulp_id": "u-2"}
            app.state.on_protect_event(message)
            app.state.on_protect_event(dict(message))
            await asyncio.sleep(0.2)

            self.assertEqual(engine.process_event.await_count, 1)

        self._run_in_lifespan(body)

    def test_remote_relock_covers_entry_device_paired_locks(self) -> None:
        """Remote unlock must schedule relocks for locks resolved through
        the auth engine (entry_devices included), not just the bare DB
        location-column lookup."""
        async def body(app):
            engine = _make_engine_mock()
            # Simulates an HA lock paired ONLY via Entry Devices — the
            # old db.get_locks_for_location(loc) returned nothing for it.
            engine.get_locks_for_location = AsyncMock(return_value=[{
                "id": 5, "type": "ha_external", "entity_id": "lock.front",
                "name": "Front Deadbolt", "relock_on_remote": 1,
                "relock_duration": 30,
            }])
            app.state.auth_engine = engine
            rm = MagicMock()
            rm.schedule = AsyncMock()
            app.state.relock_manager = rm

            app.state.on_access_event({
                "event": "remote_unlock",
                "data": {"ulp_id": "u-1", "location_id": "door-loc-1"},
            })
            await asyncio.sleep(0.2)

            engine.get_locks_for_location.assert_awaited_once_with("door-loc-1")
            rm.schedule.assert_awaited_once_with(
                entity_id="lock.front", duration=30, lock_id=5,
                lock_name="Front Deadbolt", source="remote",
            )

        self._run_in_lifespan(body)


if __name__ == "__main__":
    unittest.main()
