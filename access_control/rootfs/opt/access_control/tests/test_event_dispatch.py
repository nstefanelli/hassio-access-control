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
    # Only database.py captures DATA_DIR at import and main.py owns the app
    # singleton that must be rebuilt around that database. Reloading client and
    # policy modules creates new exception classes while already-collected test
    # modules retain the old identities, making results depend on file order.
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
            app.state.event_topology_ready = True
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
            app.state.event_topology_ready = True
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
            app.state.event_topology_ready = True
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
            app.state.event_topology_ready = True
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

    def test_remote_relock_does_not_require_optional_actor_id(self) -> None:
        async def body(app):
            app.state.event_topology_ready = True
            engine = _make_engine_mock()
            engine.get_locks_for_location = AsyncMock(return_value=[{
                "id": 6,
                "type": "ha_external",
                "entity_id": "lock.side",
                "name": "Side Door",
                "relock_on_remote": 1,
                "relock_duration": 20,
            }])
            app.state.auth_engine = engine
            rm = MagicMock()
            rm.schedule = AsyncMock()
            app.state.relock_manager = rm

            app.state.on_access_event({
                "event": "remote_unlock",
                "data": {"location_id": "door-side"},
            })
            await asyncio.sleep(0.2)

            rm.schedule.assert_awaited_once_with(
                entity_id="lock.side",
                duration=20,
                lock_id=6,
                lock_name="Side Door",
                source="remote",
            )

        self._run_in_lifespan(body)

    def test_direct_schedule_event_triggers_critical_location_reconcile(self) -> None:
        async def body(app):
            app.state.event_topology_ready = True
            app.state.auth_engine = _make_engine_mock()
            hub = MagicMock()
            hub.is_access_state_event = MagicMock(return_value=True)
            hub.reconcile_location = AsyncMock(return_value=1)
            app.state.hub_sync_manager = hub

            app.state.on_access_event({
                "event": "access.unlock_schedule.activate",
                "data": {"unique_id": "door-scheduled"},
            })
            await asyncio.sleep(0.2)

            hub.reconcile_location.assert_awaited_once_with(
                "door-scheduled", "access.unlock_schedule.activate"
            )
        self._run_in_lifespan(body)

    def test_structured_schedule_deactivation_bypasses_missing_actor(self) -> None:
        async def body(app):
            app.state.event_topology_ready = True
            app.state.auth_engine = _make_engine_mock()
            hub = MagicMock()
            hub.is_access_state_event = MagicMock(return_value=True)
            hub.reconcile_location = AsyncMock(return_value=1)
            app.state.hub_sync_manager = hub

            app.state.on_access_event({
                "event": "access.logs.add",
                "data": {
                    "_id": "schedule-event-1",
                    "_source": {
                        "event": {
                            "event_type": "access.unlock_schedule.deactivate"
                        },
                        "door": {"id": "door-scheduled"},
                    },
                },
            })
            await asyncio.sleep(0.2)

            hub.reconcile_location.assert_awaited_once_with(
                "door-scheduled", "access.unlock_schedule.deactivate"
            )
            app.state.auth_engine.process_event.assert_not_awaited()
        self._run_in_lifespan(body)

    def test_remote_unlock_of_synced_pair_unlocks_and_confirms_ha(self) -> None:
        async def body(app):
            app.state.event_topology_ready = True
            engine = _make_engine_mock()
            engine.lockdown = False
            engine.get_locks_for_location = AsyncMock(return_value=[{
                "id": 7,
                "type": "ha_external",
                "entity_id": "lock.front",
                "name": "Front Door",
                "relock_on_remote": 1,
                "relock_duration": 20,
                "sync_hub_state": 1,
            }])
            app.state.auth_engine = engine

            order: list[str] = []
            intent = MagicMock()

            async def schedule(**_kwargs):
                order.append("persist")
                return intent

            rm = MagicMock()
            rm.schedule = AsyncMock(side_effect=schedule)
            rm.extend_after_success = AsyncMock()
            rm.retain_after_uncertain_unlock = AsyncMock()
            app.state.relock_manager = rm

            ha = MagicMock()
            ha.connected = True

            async def unlock(_eid):
                order.append("unlock")
                return True

            ha.unlock = AsyncMock(side_effect=unlock)
            ha.get_entity_state = AsyncMock(return_value="unlocked")
            app.state.ha_client = ha
            hub = MagicMock()
            hub.mark_access_momentary = MagicMock()
            app.state.hub_sync_manager = hub

            app.state.on_access_event({
                "event": "remote_unlock",
                "data": {"location_id": "door-front"},
            })
            await asyncio.sleep(0.3)

            self.assertEqual(order[:2], ["persist", "unlock"])
            ha.unlock.assert_awaited_once_with("lock.front")
            ha.get_entity_state.assert_awaited_once_with("lock.front")
            hub.mark_access_momentary.assert_called_once_with("lock.front", 20.0)
            rm.extend_after_success.assert_awaited_once_with(intent, 20.0)
            rm.retain_after_uncertain_unlock.assert_not_awaited()
        self._run_in_lifespan(body)

    def test_unconfirmed_remote_ha_mirror_marks_cache_unknown(self) -> None:
        async def body(app):
            app.state.event_topology_ready = True
            engine = _make_engine_mock()
            engine.lockdown = False
            engine.get_locks_for_location = AsyncMock(return_value=[{
                "id": 8,
                "type": "ha_external",
                "entity_id": "lock.side",
                "name": "Side Door",
                "relock_on_remote": 1,
                "relock_duration": 20,
                "sync_hub_state": 1,
            }])
            app.state.auth_engine = engine

            intent = MagicMock()
            rm = MagicMock()
            rm.schedule = AsyncMock(return_value=intent)
            rm.extend_after_success = AsyncMock()
            rm.retain_after_uncertain_unlock = AsyncMock()
            app.state.relock_manager = rm

            ha = MagicMock()
            ha.connected = True
            ha.unlock = AsyncMock(return_value=True)
            ha.get_entity_state = AsyncMock(return_value="locked")
            app.state.ha_client = ha
            app.state.lock_states["lock.side"] = "locked"
            app.state.hub_sync_manager = MagicMock()

            app.state.on_access_event({
                "event": "remote_unlock",
                "data": {"location_id": "door-side-unconfirmed"},
            })
            await asyncio.sleep(1)

            self.assertEqual(app.state.lock_states["lock.side"], "unknown")
            rm.retain_after_uncertain_unlock.assert_awaited_once_with(intent)
            rm.extend_after_success.assert_not_awaited()
        self._run_in_lifespan(body)

    def test_empty_user_snapshot_keeps_topology_fail_closed(self) -> None:
        async def body(app):
            await app.state.db.upsert_user(
                "u-existing", "Existing", None, "active"
            )
            await app.state.db.upsert_native_lock(
                "hub-front", "door-front", "Front"
            )
            access = MagicMock()
            access.fetch_users = AsyncMock(return_value=[])
            access.get_bootstrap = AsyncMock(return_value={"data": []})
            access.parse_doors_and_devices = MagicMock(return_value=[])
            access.verify_console_identity = AsyncMock(
                return_value="site-identity"
            )
            app.state.access_client = access
            app.state.event_topology_ready = False

            with self.assertRaisesRegex(RuntimeError, "no valid users"):
                await app.state.sync_users()

            self.assertFalse(app.state.event_topology_ready)
            self.assertEqual(
                (await app.state.db.get_user_by_ulp_id("u-existing"))["status"],
                "active",
            )
            self.assertIsNotNone(
                await app.state.db.get_lock_by_location("door-front")
            )

        self._run_in_lifespan(body)

    def test_all_invalid_user_snapshot_keeps_topology_fail_closed(self) -> None:
        async def body(app):
            await app.state.db.upsert_user(
                "u-existing", "Existing", None, "active"
            )
            access = MagicMock()
            # AccessClient deliberately preserves upstream rows and can emit
            # one whose identifier is empty. A non-empty Python list is not
            # proof that the snapshot contains an authorizable user.
            access.fetch_users = AsyncMock(return_value=[{
                "ulp_id": "",
                "name": "Malformed",
                "email": None,
                "status": "active",
            }])
            access.get_bootstrap = AsyncMock(return_value={"data": []})
            access.parse_doors_and_devices = MagicMock(return_value=[])
            access.verify_console_identity = AsyncMock(
                return_value="site-identity"
            )
            app.state.access_client = access
            app.state.event_topology_ready = False

            with self.assertRaisesRegex(RuntimeError, "no valid users"):
                await app.state.sync_users()

            self.assertFalse(app.state.event_topology_ready)
            self.assertEqual(
                (await app.state.db.get_user_by_ulp_id("u-existing"))["status"],
                "active",
            )

        self._run_in_lifespan(body)

    def test_all_invalid_door_snapshot_keeps_topology_fail_closed(self) -> None:
        async def body(app):
            await app.state.db.upsert_user(
                "u-existing", "Existing", None, "active"
            )
            await app.state.db.upsert_native_lock(
                "hub-front", "door-front", "Front"
            )
            access = MagicMock()
            access.fetch_users = AsyncMock(return_value=[{
                "ulp_id": "u-existing",
                "name": "Existing",
                "email": None,
                "status": "active",
            }])
            access.get_bootstrap = AsyncMock(return_value={"data": []})
            access.parse_doors_and_devices = MagicMock(return_value=[{
                "device_id": "",
                "location_id": "",
                "name": "Malformed",
            }])
            access.verify_console_identity = AsyncMock(
                return_value="site-identity"
            )
            app.state.access_client = access
            app.state.event_topology_ready = False

            with self.assertRaisesRegex(RuntimeError, "no valid doors"):
                await app.state.sync_users()

            self.assertFalse(app.state.event_topology_ready)
            self.assertIsNotNone(
                await app.state.db.get_lock_by_location("door-front")
            )

        self._run_in_lifespan(body)

    def test_shutdown_waits_for_critical_remote_relock_persistence(self) -> None:
        completed = False
        cancelled = False

        async def body(app):
            nonlocal completed, cancelled
            app.state.event_topology_ready = True
            engine = _make_engine_mock()
            engine.get_locks_for_location = AsyncMock(return_value=[{
                "id": 5,
                "type": "ha_external",
                "entity_id": "lock.front",
                "name": "Front Deadbolt",
                "relock_on_remote": 1,
                "relock_duration": 30,
            }])
            app.state.auth_engine = engine
            started = asyncio.Event()
            release = asyncio.Event()

            async def persist_relock(**_kwargs):
                nonlocal completed, cancelled
                started.set()
                try:
                    await release.wait()
                except asyncio.CancelledError:
                    cancelled = True
                    raise
                completed = True

            rm = MagicMock()
            rm.schedule = AsyncMock(side_effect=persist_relock)
            app.state.relock_manager = rm

            app.state.on_access_event({
                "event": "remote_unlock",
                "data": {"ulp_id": "u-1", "location_id": "door-loc-1"},
            })
            await asyncio.wait_for(started.wait(), timeout=1)
            # Returning from this body enters lifespan shutdown. The release
            # happens only after teardown has had time to cancel ordinary
            # event tasks, proving critical durability work is awaited.
            asyncio.get_running_loop().call_later(0.05, release.set)

        self._run_in_lifespan(body)
        self.assertFalse(cancelled)
        self.assertTrue(completed)


if __name__ == "__main__":
    unittest.main()
