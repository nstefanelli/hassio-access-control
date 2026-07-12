"""Unit tests for HubSyncManager — desired-state mirroring of HA lock
state onto paired Access hubs.

Semantics under test (v2, field report 2026-07-12): the hub CONVERGES to
the lock's current state — enabling the option or restarting drives the
hub to match within one poll, not only after the next change.
"""
from __future__ import annotations

import asyncio
import importlib
import importlib.util
import sys
import time as _time
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


_load_package()
hs_module = importlib.import_module("access_control.hub_sync")
HubSyncManager = hs_module.HubSyncManager


HUB = {
    "id": 1, "type": "access_native", "device_id": "dev-hub-1",
    "location_id": "loc-1", "name": "Front Door Hub",
}

HA_LOCK = {
    "id": 2, "type": "ha_external", "entity_id": "lock.front",
    "name": "Front Deadbolt", "access_location_id": "loc-1",
    "sync_hub_state": 1,
}


def _make_db(locks, location_map=None, entry_devices=None) -> MagicMock:
    """Build a MagicMock DB with the methods HubSyncManager uses."""
    db = MagicMock()
    db.get_all_locks = AsyncMock(return_value=locks)
    db.get_locks_for_location = AsyncMock(
        side_effect=lambda loc, include_hidden=False: (location_map or {}).get(loc, [])
    )
    db.get_entry_devices_for_locks = AsyncMock(return_value=entry_devices or {})
    db.log_access = AsyncMock()
    return db


def _make_ha(states: dict[str, str]) -> MagicMock:
    ha = MagicMock()
    ha.connected = True
    ha.get_entity_state = AsyncMock(side_effect=lambda eid: states.get(eid))
    ha.fire_event = AsyncMock(return_value=True)
    return ha


def _make_access(connected: bool = True) -> MagicMock:
    access = MagicMock()
    access.connected = connected
    access.lock = AsyncMock()
    access.unlock_persistent = AsyncMock()
    return access


def _make_mgr(db, ha, access, on_hub_state=None, lockdown=None, camera_map=None) -> HubSyncManager:
    return HubSyncManager(
        db=db,
        ha_client_getter=lambda: ha,
        access_client_getter=lambda: access,
        on_hub_state=on_hub_state,
        lockdown_getter=lockdown,
        camera_map_getter=(lambda: camera_map) if camera_map is not None else None,
    )


def _clear_damping(mgr: HubSyncManager, eid: str = "lock.front") -> None:
    """Backdate the min-apply-interval clock so the next change applies."""
    mgr._last_applied_at[eid] = (
        _time.monotonic() - hs_module._MIN_APPLY_INTERVAL - 1
    )


def _run(coro):
    return asyncio.run(coro)


class TestConvergence(unittest.TestCase):
    def test_first_poll_converges_hub_to_unlocked(self) -> None:
        """THE field-reported behavior: lock is unlocked when sync starts
        → the paired hub must be driven to hold-open, immediately."""
        async def go():
            states = {"lock.front": "unlocked"}
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            access = _make_access()
            cache: dict[str, str] = {}
            mgr = _make_mgr(
                db, _make_ha(states), access,
                on_hub_state=lambda dev, st: cache.__setitem__(dev, st),
            )
            applied = await mgr.poll_once()
            self.assertEqual(applied, 1)
            access.unlock_persistent.assert_awaited_once_with("dev-hub-1")
            access.lock.assert_not_awaited()
            self.assertEqual(cache, {"dev-hub-1": "unlocked"})
            db.log_access.assert_awaited_once()
        _run(go())

    def test_first_poll_converges_hub_to_locked(self) -> None:
        async def go():
            states = {"lock.front": "locked"}
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            access = _make_access()
            mgr = _make_mgr(db, _make_ha(states), access)
            self.assertEqual(await mgr.poll_once(), 1)
            access.lock.assert_awaited_once_with("dev-hub-1")
            access.unlock_persistent.assert_not_awaited()
        _run(go())

    def test_steady_state_does_nothing_after_convergence(self) -> None:
        async def go():
            states = {"lock.front": "locked"}
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            access = _make_access()
            mgr = _make_mgr(db, _make_ha(states), access)
            await mgr.poll_once()
            await mgr.poll_once()
            await mgr.poll_once()
            self.assertEqual(access.lock.await_count, 1)
        _run(go())

    def test_transition_follows_after_convergence(self) -> None:
        async def go():
            states = {"lock.front": "locked"}
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            access = _make_access()
            mgr = _make_mgr(db, _make_ha(states), access)
            await mgr.poll_once()  # converge: locked
            states["lock.front"] = "unlocked"
            _clear_damping(mgr)
            self.assertEqual(await mgr.poll_once(), 1)
            access.unlock_persistent.assert_awaited_once_with("dev-hub-1")
        _run(go())

    def test_non_actionable_states_never_acted_on(self) -> None:
        async def go():
            states = {"lock.front": "unavailable"}
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            access = _make_access()
            mgr = _make_mgr(db, _make_ha(states), access)
            await mgr.poll_once()
            access.lock.assert_not_awaited()
            access.unlock_persistent.assert_not_awaited()
            # Recovery into an actionable state converges normally.
            states["lock.front"] = "unlocked"
            self.assertEqual(await mgr.poll_once(), 1)
            access.unlock_persistent.assert_awaited_once_with("dev-hub-1")
        _run(go())

    def test_unavailable_blip_after_convergence_is_ignored(self) -> None:
        async def go():
            states = {"lock.front": "locked"}
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            access = _make_access()
            mgr = _make_mgr(db, _make_ha(states), access)
            await mgr.poll_once()  # converge: locked (1 drive)
            states["lock.front"] = "unavailable"
            _clear_damping(mgr)
            await mgr.poll_once()
            states["lock.front"] = "locked"
            await mgr.poll_once()
            self.assertEqual(access.lock.await_count, 1)
        _run(go())


class TestPairing(unittest.TestCase):
    def test_pairing_via_entry_device_access_reader(self) -> None:
        async def go():
            ha_lock = dict(HA_LOCK, access_location_id=None)
            entry_devices = {
                2: [{"id": 9, "lock_id": 2, "type": "access_reader",
                     "device_id": "loc-1", "name": "Front Reader"}],
            }
            states = {"lock.front": "unlocked"}
            db = _make_db(
                [ha_lock, HUB],
                location_map={"loc-1": [HUB]},
                entry_devices=entry_devices,
            )
            access = _make_access()
            mgr = _make_mgr(db, _make_ha(states), access)
            self.assertEqual(await mgr.poll_once(), 1)
            access.unlock_persistent.assert_awaited_once_with("dev-hub-1")
        _run(go())

    def test_pairing_via_protect_doorbell_camera_map(self) -> None:
        """G6 Entry setup: the lock is linked to the door only via a
        Protect doorbell entry device — the camera→location map must
        resolve it to the hub (field report 2026-07-12)."""
        async def go():
            ha_lock = dict(HA_LOCK, access_location_id=None)
            entry_devices = {
                2: [{"id": 9, "lock_id": 2, "type": "protect_doorbell",
                     "device_id": "cam-1", "name": "Front G6"}],
            }
            states = {"lock.front": "unlocked"}
            db = _make_db(
                [ha_lock, HUB],
                location_map={"loc-1": [HUB]},
                entry_devices=entry_devices,
            )
            access = _make_access()
            mgr = _make_mgr(
                db, _make_ha(states), access,
                camera_map={"cam-1": "loc-1"},
            )
            self.assertEqual(await mgr.poll_once(), 1)
            access.unlock_persistent.assert_awaited_once_with("dev-hub-1")
        _run(go())

    def test_hidden_hub_still_resolves(self) -> None:
        """Hiding the native hub card is cosmetic — sync must still find
        it (field report 2026-07-12)."""
        async def go():
            hidden_hub = dict(HUB, hidden=1)
            states = {"lock.front": "unlocked"}
            db = _make_db([HA_LOCK, hidden_hub])
            # Only the include_hidden=True lookup returns the hub —
            # mirrors the real WHERE hidden=0 filter.
            db.get_locks_for_location = AsyncMock(
                side_effect=lambda loc, include_hidden=False: (
                    [hidden_hub] if include_hidden else []
                )
            )
            access = _make_access()
            mgr = _make_mgr(db, _make_ha(states), access)
            self.assertEqual(await mgr.poll_once(), 1)
            access.unlock_persistent.assert_awaited_once_with("dev-hub-1")
        _run(go())

    def test_no_paired_hub_warns_and_never_drives(self) -> None:
        async def go():
            ha_lock = dict(HA_LOCK, access_location_id=None)
            states = {"lock.front": "unlocked"}
            db = _make_db([ha_lock], location_map={})
            access = _make_access()
            mgr = _make_mgr(db, _make_ha(states), access)
            await mgr.poll_once()
            states["lock.front"] = "locked"
            _clear_damping(mgr)
            await mgr.poll_once()
            access.lock.assert_not_awaited()
            access.unlock_persistent.assert_not_awaited()
        _run(go())


class TestOptIn(unittest.TestCase):
    def test_lock_without_option_is_ignored(self) -> None:
        async def go():
            plain = dict(HA_LOCK, sync_hub_state=0)
            states = {"lock.front": "unlocked"}
            ha = _make_ha(states)
            db = _make_db([plain, HUB], location_map={"loc-1": [HUB]})
            access = _make_access()
            mgr = _make_mgr(db, ha, access)
            await mgr.poll_once()
            ha.get_entity_state.assert_not_awaited()
            access.unlock_persistent.assert_not_awaited()
        _run(go())

    def test_reenable_reconverges_to_current_state(self) -> None:
        async def go():
            states = {"lock.front": "locked"}
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            access = _make_access()
            mgr = _make_mgr(db, _make_ha(states), access)
            await mgr.poll_once()  # converge: locked

            # Option off; lock flips while sync is disabled.
            db.get_all_locks = AsyncMock(
                return_value=[dict(HA_LOCK, sync_hub_state=0), HUB]
            )
            states["lock.front"] = "unlocked"
            await mgr.poll_once()
            access.unlock_persistent.assert_not_awaited()

            # Re-enable → converge to the CURRENT state (unlocked).
            db.get_all_locks = AsyncMock(return_value=[HA_LOCK, HUB])
            self.assertEqual(await mgr.poll_once(), 1)
            access.unlock_persistent.assert_awaited_once_with("dev-hub-1")
        _run(go())


class TestLockdown(unittest.TestCase):
    def test_unlocked_convergence_suppressed_during_lockdown(self) -> None:
        async def go():
            states = {"lock.front": "unlocked"}
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            access = _make_access()
            locked_down = {"on": True}
            mgr = _make_mgr(
                db, _make_ha(states), access,
                lockdown=lambda: locked_down["on"],
            )
            self.assertEqual(await mgr.poll_once(), 0)
            access.unlock_persistent.assert_not_awaited()

            # The state was recorded as applied, so lifting lockdown must
            # NOT pop the door open.
            locked_down["on"] = False
            self.assertEqual(await mgr.poll_once(), 0)
            access.unlock_persistent.assert_not_awaited()

            # A fresh change after lockdown lifts applies normally.
            states["lock.front"] = "locked"
            await mgr.poll_once()
            access.lock.assert_awaited_once_with("dev-hub-1")
        _run(go())

    def test_lock_direction_still_applies_during_lockdown(self) -> None:
        async def go():
            states = {"lock.front": "unlocked"}
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            access = _make_access()
            mgr = _make_mgr(db, _make_ha(states), access, lockdown=lambda: True)
            await mgr.poll_once()  # unlocked recorded, suppressed
            states["lock.front"] = "locked"
            self.assertEqual(await mgr.poll_once(), 1)
            access.lock.assert_awaited_once_with("dev-hub-1")
        _run(go())

    def test_lockdown_getter_raising_fails_closed(self) -> None:
        async def go():
            states = {"lock.front": "unlocked"}
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            access = _make_access()

            def boom() -> bool:
                raise RuntimeError("broken getter")

            mgr = _make_mgr(db, _make_ha(states), access, lockdown=boom)
            self.assertEqual(await mgr.poll_once(), 0)
            access.unlock_persistent.assert_not_awaited()
        _run(go())


class TestFlapDamping(unittest.TestCase):
    def test_rapid_second_change_deferred_then_applied(self) -> None:
        async def go():
            states = {"lock.front": "locked"}
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            access = _make_access()
            mgr = _make_mgr(db, _make_ha(states), access)
            await mgr.poll_once()  # converge: locked (drive 1)
            access.lock.assert_awaited_once_with("dev-hub-1")

            # Immediate flip — deferred by the min-apply interval, and
            # not lost: applied state is unchanged.
            states["lock.front"] = "unlocked"
            self.assertEqual(await mgr.poll_once(), 0)
            access.unlock_persistent.assert_not_awaited()

            _clear_damping(mgr)
            self.assertEqual(await mgr.poll_once(), 1)
            access.unlock_persistent.assert_awaited_once_with("dev-hub-1")
        _run(go())

    def test_sustained_flapping_suspends_and_fails_safe(self) -> None:
        async def go():
            states = {"lock.front": "locked"}
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            ha = _make_ha(states)
            access = _make_access()
            mgr = _make_mgr(db, ha, access)

            now = _time.monotonic()
            mgr._apply_times["lock.front"] = [
                now - 5 * i for i in range(1, hs_module._FLAP_THRESHOLD + 1)
            ]
            mgr._applied["lock.front"] = "unlocked"
            mgr._held_open["lock.front"] = [HUB]
            _clear_damping(mgr)

            states["lock.front"] = "locked"
            self.assertEqual(await mgr.poll_once(), 0)
            self.assertGreater(
                mgr._suspended_until.get("lock.front", 0), _time.monotonic()
            )
            ha.fire_event.assert_awaited_once_with(
                "access_control_hub_sync_failed",
                {"entity_id": "lock.front", "lock_name": "Front Deadbolt",
                 "reason": "flapping"},
            )
            # Held-open hub fail-safes to reset (release queue processed
            # at the start of the next poll).
            await mgr.poll_once()
            access.lock.assert_awaited_once_with("dev-hub-1")
            access.unlock_persistent.assert_not_awaited()

            # While suspended the entity is not followed at all.
            states["lock.front"] = "unlocked"
            self.assertEqual(await mgr.poll_once(), 0)
            access.unlock_persistent.assert_not_awaited()
        _run(go())

    def test_normal_test_toggling_does_not_suspend(self) -> None:
        """A person hand-testing the feature (a few toggles in a couple
        of minutes) must never trip suspension — that was mistakable for
        'sync is broken' (field report 2026-07-12)."""
        async def go():
            states = {"lock.front": "locked"}
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            access = _make_access()
            mgr = _make_mgr(db, _make_ha(states), access)
            # Converge + 4 toggles = 5 drives, well under the threshold.
            await mgr.poll_once()
            for next_state in ("unlocked", "locked", "unlocked", "locked"):
                states["lock.front"] = next_state
                _clear_damping(mgr)
                self.assertEqual(await mgr.poll_once(), 1)
            self.assertNotIn("lock.front", mgr._suspended_until)
        _run(go())


class TestReleaseOnDrop(unittest.TestCase):
    def test_deleted_lock_releases_held_open_hub(self) -> None:
        async def go():
            states = {"lock.front": "unlocked"}
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            access = _make_access()
            mgr = _make_mgr(db, _make_ha(states), access)
            await mgr.poll_once()  # converge: hub held open
            access.unlock_persistent.assert_awaited_once_with("dev-hub-1")

            # Lock deleted — row gone; release resolves from the
            # in-memory held-open record.
            db.get_all_locks = AsyncMock(return_value=[HUB])
            await mgr.poll_once()
            access.lock.assert_awaited_once_with("dev-hub-1")
            self.assertNotIn("lock.front", mgr._applied)
            self.assertEqual(mgr._pending_release, {})
        _run(go())

    def test_opt_out_releases_via_lock_row_without_held_memory(self) -> None:
        async def go():
            # Lockdown-suppressed convergence records applied="unlocked"
            # WITHOUT driving (so no held-open memory) — release must
            # still resolve hubs from the lock row.
            states = {"lock.front": "unlocked"}
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            access = _make_access()
            mgr = _make_mgr(db, _make_ha(states), access, lockdown=lambda: True)
            await mgr.poll_once()  # suppressed: applied recorded, no drive
            access.unlock_persistent.assert_not_awaited()

            db.get_all_locks = AsyncMock(
                return_value=[dict(HA_LOCK, sync_hub_state=0), HUB]
            )
            await mgr.poll_once()
            access.lock.assert_awaited_once_with("dev-hub-1")
        _run(go())

    def test_release_retries_until_access_recovers(self) -> None:
        async def go():
            states = {"lock.front": "unlocked"}
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            access = _make_access()
            mgr = _make_mgr(db, _make_ha(states), access)
            await mgr.poll_once()  # converge: hub held open

            access.connected = False
            db.get_all_locks = AsyncMock(return_value=[HUB])
            await mgr.poll_once()  # release queued but Access is down
            access.lock.assert_not_awaited()
            self.assertIn("lock.front", mgr._pending_release)

            access.connected = True
            mgr._release_backoff.clear()
            await mgr.poll_once()
            access.lock.assert_awaited_once_with("dev-hub-1")
            self.assertEqual(mgr._pending_release, {})
        _run(go())

    def test_drop_while_locked_releases_nothing(self) -> None:
        async def go():
            states = {"lock.front": "locked"}
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            access = _make_access()
            mgr = _make_mgr(db, _make_ha(states), access)
            await mgr.poll_once()  # converge: locked (1 drive)
            db.get_all_locks = AsyncMock(return_value=[HUB])
            await mgr.poll_once()
            self.assertEqual(access.lock.await_count, 1)  # no release drive
            access.unlock_persistent.assert_not_awaited()
        _run(go())


class TestFailureHandling(unittest.TestCase):
    def test_failed_drive_backs_off_and_notifies_once(self) -> None:
        async def go():
            states = {"lock.front": "unlocked"}
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            ha = _make_ha(states)
            access = _make_access()
            access.unlock_persistent = AsyncMock(side_effect=RuntimeError("boom"))
            mgr = _make_mgr(db, ha, access)

            hs_module._APPLY_RETRY_DELAY = 0.0
            self.assertEqual(await mgr.poll_once(), 0)
            self.assertEqual(access.unlock_persistent.await_count, 2)
            ha.fire_event.assert_awaited_once_with(
                "access_control_hub_sync_failed",
                {"entity_id": "lock.front", "lock_name": "Front Deadbolt",
                 "reason": "apply_failed"},
            )
            db.log_access.assert_not_awaited()

            # Within the backoff window nothing is retried.
            await mgr.poll_once()
            self.assertEqual(access.unlock_persistent.await_count, 2)

            # After backoff the convergence is retried (applied state was
            # not advanced) and succeeds; no second failure event.
            mgr._backoff_until.clear()
            access.unlock_persistent = AsyncMock()
            self.assertEqual(await mgr.poll_once(), 1)
            access.unlock_persistent.assert_awaited_once_with("dev-hub-1")
            self.assertEqual(ha.fire_event.await_count, 1)
        _run(go())

    def test_access_client_down_defers_convergence(self) -> None:
        async def go():
            states = {"lock.front": "unlocked"}
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            access = _make_access(connected=False)
            mgr = _make_mgr(db, _make_ha(states), access)
            self.assertEqual(await mgr.poll_once(), 0)
            access.unlock_persistent.assert_not_awaited()

            access.connected = True
            mgr._backoff_until.clear()
            self.assertEqual(await mgr.poll_once(), 1)
            access.unlock_persistent.assert_awaited_once_with("dev-hub-1")
        _run(go())

    def test_ha_disconnected_is_a_noop(self) -> None:
        async def go():
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            ha = _make_ha({"lock.front": "locked"})
            ha.connected = False
            mgr = _make_mgr(db, ha, _make_access())
            self.assertEqual(await mgr.poll_once(), 0)
            db.get_all_locks.assert_not_awaited()
        _run(go())


if __name__ == "__main__":
    unittest.main()
