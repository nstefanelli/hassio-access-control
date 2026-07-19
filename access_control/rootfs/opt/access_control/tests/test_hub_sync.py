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
import tempfile
import time as _time
import unittest
from pathlib import Path
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


_load_package()
hs_module = importlib.import_module("access_control.hub_sync")
HubSyncManager = hs_module.HubSyncManager
Database = importlib.import_module("access_control.database").Database
_client_module = importlib.import_module("access_control.access_client")
AccessClientError = _client_module.AccessClientError
AccessLegacyEndpointGoneError = _client_module.AccessLegacyEndpointGoneError


HUB = {
    "id": 1, "type": "access_native", "device_id": "dev-hub-1",
    "location_id": "loc-1", "name": "Front Door Hub",
}

HUB_2 = {
    "id": 3, "type": "access_native", "device_id": "dev-hub-2",
    "location_id": "loc-1", "name": "Front Door Hub 2",
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
    db.record_hub_sync_hold = AsyncMock()
    db.clear_hub_sync_hold = AsyncMock()
    db.get_hub_sync_holds = AsyncMock(return_value=[])
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


def _make_bidirectional_access(
    rules: dict[str, dict],
    states: dict[str, str],
    connected: bool = True,
    *,
    authoritative_relay: bool = True,
) -> MagicMock:
    """Access fixture exposing the confirmed rule/state primitives."""
    access = _make_access(connected=connected)
    access.open_api_configured = authoritative_relay
    access.get_lock_rule = AsyncMock(
        side_effect=lambda device_id, location_id=None: dict(rules[device_id])
    )
    access.get_door_state = AsyncMock(
        side_effect=lambda device_id, location_id=None: states[device_id]
    )

    async def hold_unlocked(device_id, location_id=None):
        rules[device_id] = {"type": "keep_unlock"}
        states[device_id] = "unlocked"
        return {"type": "keep_unlock", "state": "unlocked"}

    async def force_lock(device_id, location_id=None):
        rules[device_id] = {"type": "lock_early"}
        states[device_id] = "locked"
        return {"type": "lock_early", "state": "locked"}

    async def hold_locked(device_id, location_id=None):
        rules[device_id] = {"type": "keep_lock"}
        states[device_id] = "locked"
        return {"type": "keep_lock", "state": "locked"}

    async def restore_native_rule(device_id, location_id=None):
        rules[device_id] = {"type": "reset"}
        states[device_id] = "locked"
        return {"type": "reset", "state": "locked"}

    access.hold_unlocked = AsyncMock(side_effect=hold_unlocked)
    access.force_lock = AsyncMock(side_effect=force_lock)
    access.hold_locked = AsyncMock(side_effect=hold_locked)
    access.restore_native_rule = AsyncMock(side_effect=restore_native_rule)
    return access


def _make_bidirectional_ha(states: dict[str, str]) -> MagicMock:
    ha = _make_ha(states)

    async def unlock(entity_id):
        states[entity_id] = "unlocked"
        return True

    async def lock(entity_id):
        states[entity_id] = "locked"
        return True

    ha.unlock = AsyncMock(side_effect=unlock)
    ha.lock = AsyncMock(side_effect=lock)
    return ha


def _make_mgr(
    db,
    ha,
    access,
    on_hub_state=None,
    lockdown=None,
    camera_map=None,
    access_getter=None,
    command_lock=None,
) -> HubSyncManager:
    return HubSyncManager(
        db=db,
        ha_client_getter=lambda: ha,
        access_client_getter=access_getter or (lambda: access),
        on_hub_state=on_hub_state,
        lockdown_getter=lockdown,
        camera_map_getter=(lambda: camera_map) if camera_map is not None else None,
        command_lock=command_lock,
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
            # The legacy command confirms intent only, not relay position.
            self.assertEqual(cache, {"dev-hub-1": "unknown"})
            db.log_access.assert_awaited_once()
        _run(go())

    def test_first_unlock_is_not_damped_during_low_monotonic_uptime(self) -> None:
        async def go():
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            access = _make_access()
            mgr = _make_mgr(
                db, _make_ha({"lock.front": "unlocked"}), access
            )

            # A fresh VM/container may legitimately report monotonic uptime
            # below the 10-second damping interval. Absence of a prior apply
            # must not be confused with an apply at timestamp zero.
            with patch("access_control.hub_sync.time.monotonic", return_value=1.0):
                self.assertEqual(await mgr.poll_once(), 1)
            access.unlock_persistent.assert_awaited_once_with("dev-hub-1")
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

    def test_no_paired_hub_retries_and_converges_after_pairing(self) -> None:
        async def go():
            ha_lock = dict(HA_LOCK, access_location_id=None)
            states = {"lock.front": "unlocked"}
            db = _make_db([ha_lock], location_map={})
            access = _make_access()
            mgr = _make_mgr(db, _make_ha(states), access)
            self.assertEqual(await mgr.poll_once(), 0)
            access.lock.assert_not_awaited()
            access.unlock_persistent.assert_not_awaited()

            # Pairing can arrive later via topology refresh without any HA
            # state transition. The unapplied state must be retried.
            db.get_locks_for_location = AsyncMock(
                side_effect=lambda loc, include_hidden=False: (
                    [HUB] if loc == "loc-1" else []
                )
            )
            ha_lock["access_location_id"] = "loc-1"
            mgr._backoff_until.clear()
            self.assertEqual(await mgr.poll_once(), 1)
            access.unlock_persistent.assert_awaited_once_with("dev-hub-1")
        _run(go())

    def test_unlocked_pairing_change_resets_old_before_opening_new(self) -> None:
        async def go():
            hub_b = dict(
                HUB_2,
                location_id="loc-2",
                name="Back Door Hub",
            )
            logical = dict(HA_LOCK)
            location_map = {"loc-1": [HUB], "loc-2": [hub_b]}
            db = _make_db(
                [logical, HUB, hub_b], location_map=location_map
            )
            states = {"lock.front": "unlocked"}
            access = _make_access()
            commands: list[tuple[str, str]] = []

            async def unlock(device_id: str) -> None:
                commands.append(("unlock", device_id))

            async def lock(device_id: str) -> None:
                commands.append(("lock", device_id))

            access.unlock_persistent = AsyncMock(side_effect=unlock)
            access.lock = AsyncMock(side_effect=lock)
            mgr = _make_mgr(db, _make_ha(states), access)

            self.assertEqual(await mgr.poll_once(), 1)
            logical["access_location_id"] = "loc-2"
            commands.clear()

            self.assertEqual(await mgr.poll_once(), 1)
            self.assertEqual(
                commands,
                [("lock", "dev-hub-1"), ("unlock", "dev-hub-2")],
            )
            self.assertEqual(
                mgr._pairing_signature["lock.front"], ("dev-hub-2",)
            )
            self.assertEqual(
                [hub["device_id"] for hub in mgr._held_open["lock.front"]],
                ["dev-hub-2"],
            )
            db.clear_hub_sync_hold.assert_awaited_with(
                "lock.front", "dev-hub-1"
            )
        _run(go())

    def test_pairing_change_reset_failure_blocks_new_hold(self) -> None:
        async def go():
            hub_b = dict(HUB_2, location_id="loc-2", name="Back Door Hub")
            logical = dict(HA_LOCK)
            db = _make_db(
                [logical, HUB, hub_b],
                location_map={"loc-1": [HUB], "loc-2": [hub_b]},
            )
            access = _make_access()
            mgr = _make_mgr(
                db, _make_ha({"lock.front": "unlocked"}), access
            )
            await mgr.poll_once()
            logical["access_location_id"] = "loc-2"
            access.lock = AsyncMock(side_effect=RuntimeError("reset failed"))
            old_delay = hs_module._APPLY_RETRY_DELAY
            hs_module._APPLY_RETRY_DELAY = 0.0
            try:
                self.assertEqual(await mgr.poll_once(), 0)
            finally:
                hs_module._APPLY_RETRY_DELAY = old_delay

            self.assertIn("lock.front", mgr._pending_release)
            access.unlock_persistent.assert_awaited_once_with("dev-hub-1")

            access.lock = AsyncMock()
            mgr._release_backoff.clear()
            self.assertEqual(await mgr.poll_once(), 1)
            access.lock.assert_awaited_once_with("dev-hub-1")
            access.unlock_persistent.assert_awaited_with("dev-hub-2")
            self.assertNotIn("lock.front", mgr._pending_release)
        _run(go())

    def test_duplicate_entity_rows_are_one_owner_with_union_hubs(self) -> None:
        async def go():
            hub_b = dict(HUB_2, location_id="loc-2", name="Back Door Hub")
            duplicate = dict(
                HA_LOCK,
                id=4,
                name="Front Deadbolt Duplicate",
                access_location_id="loc-2",
            )
            db = _make_db(
                [HA_LOCK, duplicate, HUB, hub_b],
                location_map={"loc-1": [HUB], "loc-2": [hub_b]},
            )
            ha = _make_ha({"lock.front": "unlocked"})
            access = _make_access()
            mgr = _make_mgr(db, ha, access)

            self.assertEqual(await mgr.poll_once(), 1)
            ha.get_entity_state.assert_awaited_once_with("lock.front")
            self.assertEqual(
                {call.args[0] for call in access.unlock_persistent.await_args_list},
                {"dev-hub-1", "dev-hub-2"},
            )
            self.assertEqual(
                mgr._pairing_signature["lock.front"],
                ("dev-hub-1", "dev-hub-2"),
            )
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
    def test_lockdown_flip_during_durable_write_never_sends_unlock(self) -> None:
        async def go():
            entered_write = asyncio.Event()
            finish_write = asyncio.Event()

            async def slow_record(*_args, **_kwargs) -> None:
                entered_write.set()
                await finish_write.wait()

            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            db.record_hub_sync_hold = AsyncMock(side_effect=slow_record)
            access = _make_access()
            locked_down = {"on": False}
            mgr = _make_mgr(
                db,
                _make_ha({"lock.front": "unlocked"}),
                access,
                lockdown=lambda: locked_down["on"],
            )

            poll = asyncio.create_task(mgr.poll_once())
            await entered_write.wait()
            locked_down["on"] = True
            finish_write.set()
            self.assertEqual(await poll, 0)
            access.unlock_persistent.assert_not_awaited()
        _run(go())

    def test_cold_start_persisted_lockdown_resets_without_ha(self) -> None:
        async def go():
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            db.get_hub_sync_holds = AsyncMock(return_value=[{
                "entity_id": "lock.front",
                "hub_device_id": "dev-hub-1",
                "hub_lock_id": 1,
                "hub_name": "Front Door Hub",
                "created_at": 1.0,
            }])
            ha = _make_ha({})
            ha.connected = False
            access = _make_access()
            mgr = _make_mgr(db, ha, access, lockdown=lambda: True)

            # Recovery closes the persisted override, then active-lockdown
            # reconciliation reasserts it because this legacy fixture cannot
            # provide authenticated rule/relay readback.
            self.assertEqual(await mgr.recover(), 2)
            self.assertEqual(access.lock.await_count, 2)
            self.assertTrue(all(
                call.args == ("dev-hub-1",)
                for call in access.lock.await_args_list
            ))
            ha.get_entity_state.assert_not_awaited()
            db.record_hub_sync_hold.assert_awaited_with(
                "lock.front",
                "dev-hub-1",
                1,
                "Front Door Hub",
                hub_location_id="loc-1",
                override_type="keep_lock",
            )
            db.clear_hub_sync_hold.assert_not_awaited()
        _run(go())

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
            self.assertEqual(await mgr.poll_once(), 1)
            access.unlock_persistent.assert_not_awaited()
            access.lock.assert_awaited_once_with("dev-hub-1")

            # The underlying unlocked state was recorded after the fail-safe
            # reset, so lifting lockdown must NOT pop the door open.
            locked_down["on"] = False
            self.assertEqual(await mgr.poll_once(), 0)
            access.unlock_persistent.assert_not_awaited()

            # A fresh change after lockdown lifts applies normally.
            states["lock.front"] = "locked"
            _clear_damping(mgr)
            await mgr.poll_once()
            self.assertEqual(access.lock.await_count, 2)
        _run(go())

    def test_lockdown_force_resets_hub_that_was_already_held_open(self) -> None:
        async def go():
            states = {"lock.front": "unlocked"}
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            access = _make_access()
            locked_down = {"on": False}
            mgr = _make_mgr(
                db,
                _make_ha(states),
                access,
                lockdown=lambda: locked_down["on"],
            )
            await mgr.poll_once()
            access.unlock_persistent.assert_awaited_once_with("dev-hub-1")

            # The HA state is unchanged, so this specifically guards the old
            # state==prev fast-path ordering bug.
            locked_down["on"] = True
            self.assertEqual(await mgr.poll_once(), 1)
            access.lock.assert_awaited_once_with("dev-hub-1")

            locked_down["on"] = False
            self.assertEqual(await mgr.poll_once(), 0)
            self.assertEqual(access.unlock_persistent.await_count, 1)
        _run(go())

    def test_pairing_change_during_lockdown_resets_new_hub(self) -> None:
        async def go():
            hub_b = dict(HUB_2, location_id="loc-2", name="Back Door Hub")
            logical = dict(HA_LOCK)
            db = _make_db(
                [logical, HUB, hub_b],
                location_map={"loc-1": [HUB], "loc-2": [hub_b]},
            )
            access = _make_access()
            mgr = _make_mgr(
                db,
                _make_ha({"lock.front": "unlocked"}),
                access,
                lockdown=lambda: True,
            )
            self.assertEqual(await mgr.poll_once(), 1)
            access.lock.assert_awaited_once_with("dev-hub-1")

            logical["access_location_id"] = "loc-2"
            access.lock.reset_mock()
            self.assertEqual(await mgr.poll_once(), 1)
            self.assertEqual(
                [call.args[0] for call in access.lock.await_args_list],
                ["dev-hub-1", "dev-hub-2"],
            )
            self.assertEqual(mgr.lockdown_unresolved, ())
        _run(go())

    def test_lock_direction_still_applies_during_lockdown(self) -> None:
        async def go():
            states = {"lock.front": "unlocked"}
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            access = _make_access()
            mgr = _make_mgr(db, _make_ha(states), access, lockdown=lambda: True)
            await mgr.poll_once()  # unlocked recorded, hub fail-safed closed
            access.lock.assert_awaited_once_with("dev-hub-1")
            states["lock.front"] = "locked"
            # Without authenticated rule/relay readback, lockdown cannot trust
            # the earlier acknowledgement and reasserts the safe direction.
            self.assertEqual(await mgr.poll_once(), 1)
            self.assertEqual(access.lock.await_count, 2)
        _run(go())

    def test_lockdown_getter_raising_fails_closed(self) -> None:
        async def go():
            states = {"lock.front": "unlocked"}
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            access = _make_access()

            def boom() -> bool:
                raise RuntimeError("broken getter")

            mgr = _make_mgr(db, _make_ha(states), access, lockdown=boom)
            self.assertEqual(await mgr.poll_once(), 1)
            access.unlock_persistent.assert_not_awaited()
            access.lock.assert_awaited_once_with("dev-hub-1")
        _run(go())

    def test_urgent_lockdown_preempts_normal_poll_retry(self) -> None:
        async def go():
            states = {"lock.front": "unlocked"}
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            access = _make_access()
            locked_down = {"on": False}
            mgr = _make_mgr(
                db,
                _make_ha(states),
                access,
                lockdown=lambda: locked_down["on"],
            )
            await mgr.poll_once()  # establish durable hold-open ownership

            entered = asyncio.Event()
            release = asyncio.Event()
            attempts = 0

            async def fail_first_then_reset(_device_id: str) -> None:
                nonlocal attempts
                attempts += 1
                if attempts == 1:
                    entered.set()
                    await release.wait()
                    raise RuntimeError("stale normal-poll failure")

            access.lock = AsyncMock(side_effect=fail_first_then_reset)
            states["lock.front"] = "locked"
            _clear_damping(mgr)
            old_delay = hs_module._APPLY_RETRY_DELAY
            hs_module._APPLY_RETRY_DELAY = 60.0
            try:
                stale_poll = asyncio.create_task(mgr.poll_once())
                await entered.wait()
                locked_down["on"] = True
                enforcement = asyncio.create_task(mgr.enforce_lockdown())
                await asyncio.sleep(0)  # publish the urgent marker
                release.set()
                await asyncio.wait_for(
                    asyncio.gather(stale_poll, enforcement), timeout=1.0
                )
            finally:
                hs_module._APPLY_RETRY_DELAY = old_delay

            # One failed stale request, one prioritized ownership reset, then
            # one continuous-lockdown reassertion because this legacy fixture
            # has no authenticated rule/relay readback. A normal retry would
            # delay the safety pass by 60 seconds.
            self.assertEqual(access.lock.await_count, 3)
            self.assertEqual(mgr._pending_release, {})
            self.assertEqual(mgr.lockdown_unresolved, ())
            self.assertFalse(mgr._urgent_lockdown.is_set())
        _run(go())

    def test_lockdown_attempts_later_held_hub_before_retrying_failure(self) -> None:
        async def go():
            db = _make_db([HUB, HUB_2])
            db.get_hub_sync_holds = AsyncMock(return_value=[
                {
                    "entity_id": "lock.front",
                    "hub_device_id": "dev-hub-1",
                    "hub_lock_id": 1,
                    "hub_location_id": "loc-1",
                    "hub_name": "Broken Hub",
                    "created_at": 1.0,
                },
                {
                    "entity_id": "lock.front",
                    "hub_device_id": "dev-hub-2",
                    "hub_lock_id": 3,
                    "hub_location_id": "loc-1",
                    "hub_name": "Open Hub",
                    "created_at": 1.0,
                },
            ])
            access = _make_access()
            attempts: list[str] = []

            async def reset(device_id: str) -> None:
                attempts.append(device_id)
                if device_id == "dev-hub-1":
                    raise RuntimeError("first hub unavailable")

            access.lock = AsyncMock(side_effect=reset)
            mgr = _make_mgr(
                db,
                _make_ha({}),
                access,
                lockdown=lambda: True,
            )
            old_delay = hs_module._APPLY_RETRY_DELAY
            hs_module._APPLY_RETRY_DELAY = 60.0
            try:
                with self.assertRaisesRegex(RuntimeError, "unresolved"):
                    await asyncio.wait_for(mgr.enforce_lockdown(), timeout=1.0)
            finally:
                hs_module._APPLY_RETRY_DELAY = old_delay

            # The first hub remains durable/pending, but it cannot consume a
            # 60-second retry delay before the second held-open hub gets its
            # first reset attempt. A later convergence phase may retry the bad
            # hub only after that breadth-first pass.
            self.assertEqual(attempts[:2], ["dev-hub-1", "dev-hub-2"])
            self.assertEqual(attempts.count("dev-hub-2"), 1)
            db.record_hub_sync_hold.assert_any_await(
                "lock.front",
                "dev-hub-2",
                3,
                "Open Hub",
                hub_location_id="loc-1",
                override_type="keep_lock",
            )
            db.clear_hub_sync_hold.assert_not_awaited()
            self.assertEqual(
                [hub["device_id"] for hub in mgr._pending_release["lock.front"]],
                ["dev-hub-1"],
            )
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
            # Safe reset bypasses historical flap/damping state.
            self.assertEqual(await mgr.poll_once(), 1)
            access.lock.assert_awaited_once_with("dev-hub-1")

            # The next unsafe transition observes the flap history and
            # suspends before issuing another hold-open.
            _clear_damping(mgr)
            states["lock.front"] = "unlocked"
            self.assertEqual(await mgr.poll_once(), 0)
            self.assertGreater(
                mgr._suspended_until.get("lock.front", 0), _time.monotonic()
            )
            ha.fire_event.assert_awaited_once_with(
                "access_control_hub_sync_failed",
                {"entity_id": "lock.front", "lock_name": "Front Deadbolt",
                 "reason": "flapping"},
            )
            access.unlock_persistent.assert_not_awaited()

            # While suspended the entity is not followed at all.
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
            # Lockdown convergence records the underlying unlocked state but
            # fail-safes the hub closed. Opting out must not leave tracking.
            states = {"lock.front": "unlocked"}
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            access = _make_access()
            lockdown = {"active": True}
            mgr = _make_mgr(
                db,
                _make_ha(states),
                access,
                lockdown=lambda: lockdown["active"],
            )
            await mgr.poll_once()
            access.unlock_persistent.assert_not_awaited()
            access.lock.assert_awaited_once_with("dev-hub-1")

            db.get_all_locks = AsyncMock(
                return_value=[dict(HA_LOCK, sync_hub_state=0), HUB]
            )
            await mgr.poll_once()
            # Opting out cannot restore a potentially open native schedule
            # while lockdown is still active.
            self.assertIn("lock.front", mgr._applied)
            self.assertEqual(access.lock.await_count, 1)

            lockdown["active"] = False
            await mgr.poll_once()
            self.assertNotIn("lock.front", mgr._applied)
            # The first post-lockdown pass deliberately releases ownership.
            self.assertEqual(access.lock.await_count, 2)
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


class TestDurableHoldLifecycle(unittest.TestCase):
    def test_new_manager_recovers_hold_from_same_database(self) -> None:
        async def go():
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "hub-holds.db"
                db = Database(path=path)
                await db.connect()
                try:
                    hub_id = await db.upsert_native_lock(
                        "dev-hub-1", "loc-1", "Front Door Hub"
                    )
                    external_id = await db.add_external_lock(
                        "lock.front", "Front Deadbolt"
                    )
                    await db.update_lock_settings(
                        external_id,
                        buzz_enabled=True,
                        relock_duration=30,
                        access_location_id="loc-1",
                        sync_hub_state=True,
                    )
                    first_access = _make_access()
                    first = _make_mgr(
                        db,
                        _make_ha({"lock.front": "unlocked"}),
                        first_access,
                    )
                    self.assertEqual(await first.poll_once(), 1)
                    holds = await db.get_hub_sync_holds()
                    self.assertEqual(
                        [(row["entity_id"], row["hub_device_id"], row["hub_lock_id"])
                         for row in holds],
                        [("lock.front", "dev-hub-1", hub_id)],
                    )
                finally:
                    await db.close()

                # Simulate an unclean process exit: no manager shutdown, a
                # brand-new Database connection and manager instance.
                restarted_db = Database(path=path)
                await restarted_db.connect()
                try:
                    offline_ha = _make_ha({})
                    offline_ha.connected = False
                    recovered_access = _make_access()
                    recovered = _make_mgr(
                        restarted_db, offline_ha, recovered_access
                    )
                    self.assertEqual(await recovered.recover(), 1)
                    recovered_access.lock.assert_awaited_once_with("dev-hub-1")
                    offline_ha.get_entity_state.assert_not_awaited()
                    recovered_rows = await restarted_db.get_hub_sync_holds()
                    self.assertEqual(len(recovered_rows), 1)
                    self.assertEqual(recovered_rows[0]["override_type"], "keep_lock")
                    self.assertEqual(recovered_rows[0]["hub_location_id"], "loc-1")
                    self.assertEqual(recovered_rows[0]["hub_device_id"], "dev-hub-1")
                finally:
                    await restarted_db.close()
        _run(go())

    def test_failed_recovery_retains_row_and_retries(self) -> None:
        async def go():
            with tempfile.TemporaryDirectory() as tmp:
                db = Database(path=Path(tmp) / "hub-holds.db")
                await db.connect()
                try:
                    await db.record_hub_sync_hold(
                        "lock.front", "dev-hub-1", 1, "Front Door Hub"
                    )
                    access = _make_access()
                    access.lock = AsyncMock(side_effect=RuntimeError("offline"))
                    mgr = _make_mgr(db, _make_ha({}), access)
                    old_delay = hs_module._APPLY_RETRY_DELAY
                    hs_module._APPLY_RETRY_DELAY = 0.0
                    try:
                        self.assertEqual(await mgr.recover(), 0)
                    finally:
                        hs_module._APPLY_RETRY_DELAY = old_delay
                    self.assertEqual(len(await db.get_hub_sync_holds()), 1)
                    self.assertIn("lock.front", mgr._pending_release)

                    access.lock = AsyncMock()
                    self.assertEqual(await mgr.recover(), 1)
                    access.lock.assert_awaited_once_with("dev-hub-1")
                    held_rows = await db.get_hub_sync_holds()
                    self.assertEqual(len(held_rows), 1)
                    self.assertEqual(held_rows[0]["override_type"], "keep_lock")

                    # No current mapping owns this hub, so the normal poll drops
                    # tracking, restores native behavior, and clears ownership.
                    await mgr.poll_once()
                    self.assertEqual(access.lock.await_count, 2)
                    self.assertEqual(await db.get_hub_sync_holds(), [])
                finally:
                    await db.close()
        _run(go())

    def test_opt_out_releases_while_ha_offline(self) -> None:
        async def go():
            states = {"lock.front": "unlocked"}
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            ha = _make_ha(states)
            access = _make_access()
            mgr = _make_mgr(db, ha, access)
            await mgr.poll_once()

            ha.connected = False
            db.get_all_locks = AsyncMock(
                return_value=[dict(HA_LOCK, sync_hub_state=0), HUB]
            )
            await mgr.poll_once()
            access.lock.assert_awaited_once_with("dev-hub-1")
            ha.get_entity_state.assert_awaited_once()  # only initial converge
            db.clear_hub_sync_hold.assert_awaited_once_with(
                "lock.front", "dev-hub-1"
            )
        _run(go())

    def test_shutdown_resets_all_held_hubs(self) -> None:
        async def go():
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            access = _make_access()
            mgr = _make_mgr(
                db, _make_ha({"lock.front": "unlocked"}), access
            )
            await mgr.poll_once()
            self.assertEqual(await mgr.shutdown(), 1)
            access.lock.assert_awaited_once_with("dev-hub-1")
            db.clear_hub_sync_hold.assert_awaited_once_with(
                "lock.front", "dev-hub-1"
            )
            self.assertEqual(mgr._pending_release, {})
        _run(go())

    def test_failed_shutdown_retains_release_for_next_start(self) -> None:
        async def go():
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            access = _make_access()
            mgr = _make_mgr(
                db, _make_ha({"lock.front": "unlocked"}), access
            )
            await mgr.poll_once()
            access.lock = AsyncMock(side_effect=RuntimeError("offline"))
            old_delay = hs_module._APPLY_RETRY_DELAY
            hs_module._APPLY_RETRY_DELAY = 0.0
            try:
                self.assertEqual(await mgr.shutdown(), 0)
            finally:
                hs_module._APPLY_RETRY_DELAY = old_delay
            self.assertIn("lock.front", mgr._pending_release)
            # Only the physical reset may authorize deleting ownership.
            db.clear_hub_sync_hold.assert_not_awaited()
        _run(go())

    def test_partial_multi_hub_apply_releases_held_union(self) -> None:
        async def go():
            db = _make_db(
                [HA_LOCK, HUB, HUB_2],
                location_map={"loc-1": [HUB, HUB_2]},
            )
            ha = _make_ha({"lock.front": "unlocked"})
            access = _make_access()

            async def partial(device_id: str) -> None:
                if device_id == "dev-hub-2":
                    raise RuntimeError("second hub unavailable")

            access.unlock_persistent = AsyncMock(side_effect=partial)
            mgr = _make_mgr(db, ha, access)
            old_delay = hs_module._APPLY_RETRY_DELAY
            hs_module._APPLY_RETRY_DELAY = 0.0
            try:
                self.assertEqual(await mgr.poll_once(), 0)
            finally:
                hs_module._APPLY_RETRY_DELAY = old_delay
            # Write-ahead rows conservatively own both the successful hub and
            # the hub whose remote outcome was uncertain.
            self.assertEqual(
                {hub["device_id"] for hub in mgr._held_open["lock.front"]},
                {"dev-hub-1", "dev-hub-2"},
            )

            ha.connected = False
            db.get_all_locks = AsyncMock(return_value=[HUB, HUB_2])
            await mgr.poll_once()
            self.assertEqual(
                {call.args[0] for call in access.lock.await_args_list},
                {"dev-hub-1", "dev-hub-2"},
            )
            self.assertEqual(mgr._pending_release, {})
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

            old_delay = hs_module._APPLY_RETRY_DELAY
            hs_module._APPLY_RETRY_DELAY = 0.0
            try:
                self.assertEqual(await mgr.poll_once(), 0)
            finally:
                hs_module._APPLY_RETRY_DELAY = old_delay
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

    def test_waiter_uses_client_published_inside_command_barrier(self) -> None:
        async def go():
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            old_access = _make_access()
            new_access = _make_access()
            current = {"client": old_access}
            command_lock = asyncio.Lock()
            await command_lock.acquire()
            mgr = _make_mgr(
                db,
                _make_ha({"lock.front": "unlocked"}),
                old_access,
                access_getter=lambda: current["client"],
                command_lock=command_lock,
            )
            poll = asyncio.create_task(mgr.poll_once())
            await asyncio.sleep(0)  # let the poll queue behind the barrier

            current["client"] = new_access
            old_access.connected = False
            command_lock.release()
            self.assertEqual(await poll, 1)

            old_access.unlock_persistent.assert_not_awaited()
            new_access.unlock_persistent.assert_awaited_once_with("dev-hub-1")
        _run(go())

    def test_retry_refreshes_current_access_client(self) -> None:
        async def go():
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            first = _make_access()
            second = _make_access()
            current = {"client": first}

            async def fail_and_swap(_device_id: str) -> None:
                current["client"] = second
                raise RuntimeError("retired client")

            first.unlock_persistent = AsyncMock(side_effect=fail_and_swap)
            mgr = _make_mgr(
                db,
                _make_ha({"lock.front": "unlocked"}),
                first,
                access_getter=lambda: current["client"],
            )
            old_delay = hs_module._APPLY_RETRY_DELAY
            hs_module._APPLY_RETRY_DELAY = 0.0
            try:
                self.assertEqual(await mgr.poll_once(), 1)
            finally:
                hs_module._APPLY_RETRY_DELAY = old_delay

            first.unlock_persistent.assert_awaited_once_with("dev-hub-1")
            second.unlock_persistent.assert_awaited_once_with("dev-hub-1")
        _run(go())

    def test_ha_disconnected_is_a_noop(self) -> None:
        async def go():
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            ha = _make_ha({"lock.front": "locked"})
            ha.connected = False
            mgr = _make_mgr(db, ha, _make_access())
            self.assertEqual(await mgr.poll_once(), 0)
            # Topology/drop detection intentionally runs before the HA
            # connectivity gate so opt-out/delete can release a durable hold
            # even while Home Assistant is offline.
            db.get_all_locks.assert_awaited_once_with(include_hidden=True)
            ha.get_entity_state.assert_not_awaited()
        _run(go())


class TestBidirectionalConvergence(unittest.TestCase):
    def _fixture(self, *, ha_state="locked", rule="reset", door_state="locked"):
        ha_states = {"lock.front": ha_state}
        access_rules = {"dev-hub-1": {"type": rule}}
        access_states = {"dev-hub-1": door_state}
        db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
        ha = _make_bidirectional_ha(ha_states)
        access = _make_bidirectional_access(access_rules, access_states)
        mgr = _make_mgr(db, ha, access)
        return mgr, ha, access, ha_states, access_rules, access_states

    def test_active_schedule_is_the_only_open_startup_mismatch(self) -> None:
        async def go():
            mgr, ha, access, states, _rules, _access_states = self._fixture(
                ha_state="locked", rule="schedule", door_state="unlocked"
            )
            self.assertEqual(await mgr.poll_once(), 1)
            self.assertEqual(states["lock.front"], "unlocked")
            ha.unlock.assert_awaited_once_with("lock.front")
            access.hold_unlocked.assert_not_awaited()
        _run(go())

    def test_schedule_rule_with_locked_relay_is_preserved(self) -> None:
        async def go():
            mgr, ha, access, states, rules, _access_states = self._fixture(
                ha_state="unlocked", rule="schedule", door_state="locked"
            )
            with patch(
                "access_control.hub_sync.asyncio.sleep", new=AsyncMock()
            ):
                self.assertEqual(await mgr.poll_once(), 1)

            self.assertEqual(states["lock.front"], "locked")
            self.assertEqual(rules["dev-hub-1"]["type"], "schedule")
            ha.lock.assert_awaited_once_with("lock.front")
            access.hold_locked.assert_not_awaited()
            access.force_lock.assert_not_awaited()
        _run(go())

    def test_non_settling_observation_reads_once_without_sleeping(self) -> None:
        """The write-ahead guard observes with ``settle=False`` while holding
        the global command barrier; even the schedule+locked relay-lag case
        must classify on a single read with no progressive-window sleeps."""
        async def go():
            mgr, _ha, access, _states, _rules, _access_states = self._fixture(
                ha_state="unlocked", rule="schedule", door_state="locked"
            )
            sleep = AsyncMock()
            with patch("access_control.hub_sync.asyncio.sleep", new=sleep):
                state, rule, _active, _relay = await mgr._observe_access_hub(
                    access,
                    {"device_id": "dev-hub-1", "location_id": "loc-1"},
                    settle=False,
                )
            sleep.assert_not_awaited()
            access.get_lock_rule.assert_awaited_once()
            access.get_door_state.assert_awaited_once()
            self.assertEqual(state, "locked")
            self.assertEqual(rule["type"], "schedule")
        _run(go())

    def test_ha_unlock_is_suppressed_if_access_changes_before_write(self) -> None:
        async def go():
            mgr, _ha, access, states, rules, access_states = self._fixture()
            await mgr.poll_once()
            access.hold_unlocked.reset_mock()
            mgr._db.record_hub_sync_hold.reset_mock()

            states["lock.front"] = "unlocked"
            calls = 0

            async def changing_rule(device_id, location_id=None):
                nonlocal calls
                calls += 1
                if calls >= 2:
                    rules[device_id] = {"type": "keep_lock"}
                    access_states[device_id] = "locked"
                return dict(rules[device_id])

            access.get_lock_rule = AsyncMock(side_effect=changing_rule)

            self.assertEqual(await mgr.poll_once(), 0)
            access.hold_unlocked.assert_not_awaited()
            mgr._db.record_hub_sync_hold.assert_not_awaited()
            self.assertEqual(rules["dev-hub-1"]["type"], "keep_lock")
        _run(go())

    def test_schedule_deactivation_locks_ha(self) -> None:
        async def go():
            mgr, ha, access, states, rules, access_states = self._fixture(
                ha_state="unlocked", rule="schedule", door_state="unlocked"
            )
            await mgr.poll_once()
            rules["dev-hub-1"] = {"type": "lock_early"}
            access_states["dev-hub-1"] = "locked"

            self.assertEqual(await mgr.poll_once(), 1)
            self.assertEqual(states["lock.front"], "locked")
            ha.lock.assert_awaited_once_with("lock.front")
            access.force_lock.assert_not_awaited()
        _run(go())

    def test_missed_access_event_is_caught_by_poll(self) -> None:
        async def go():
            mgr, ha, _access, states, rules, access_states = self._fixture()
            await mgr.poll_once()  # confirmed locked baseline
            rules["dev-hub-1"] = {"type": "keep_unlock"}
            access_states["dev-hub-1"] = "unlocked"

            self.assertEqual(await mgr.poll_once(), 1)
            self.assertEqual(states["lock.front"], "unlocked")
            ha.unlock.assert_awaited_once_with("lock.front")
        _run(go())

    def test_native_rule_momentary_relay_unlock_is_not_persistent_intent(self) -> None:
        async def go():
            mgr, ha, access, _states, _rules, access_states = self._fixture()
            await mgr.poll_once()
            # A normal credential buzz changes only the relay. The persistent
            # rule remains reset/native and must not be mirrored into HA as an
            # indefinite unlock or rewritten as keep_unlock.
            access_states["dev-hub-1"] = "unlocked"

            self.assertEqual(await mgr.poll_once(), 0)
            ha.unlock.assert_not_awaited()
            access.hold_unlocked.assert_not_awaited()
            access.hold_locked.assert_not_awaited()
        _run(go())

    def test_ha_change_drives_access_and_echo_does_not_bounce(self) -> None:
        async def go():
            mgr, ha, access, states, _rules, _access_states = self._fixture()
            await mgr.poll_once()
            states["lock.front"] = "unlocked"

            self.assertEqual(await mgr.poll_once(), 1)
            access.hold_unlocked.assert_awaited_once_with(
                "dev-hub-1", location_id="loc-1"
            )
            await mgr.poll_once()
            self.assertEqual(access.hold_unlocked.await_count, 1)
            ha.lock.assert_not_awaited()
        _run(go())

    def test_simultaneous_conflict_is_locked_wins(self) -> None:
        async def go():
            mgr, ha, access, states, rules, access_states = self._fixture()
            await mgr.poll_once()
            # HA opens while Access changes rule but remains closed: both sides
            # changed to conflicting observations in the same sample.
            states["lock.front"] = "unlocked"
            rules["dev-hub-1"] = {"type": "keep_lock"}
            access_states["dev-hub-1"] = "locked"

            self.assertEqual(await mgr.poll_once(), 1)
            self.assertEqual(states["lock.front"], "locked")
            ha.lock.assert_awaited_once_with("lock.front")
            access.hold_locked.assert_not_awaited()  # it was already closed
        _run(go())

    def test_malformed_access_readback_holds_both_sides_locked(self) -> None:
        async def go():
            mgr, ha, access, states, rules, access_states = self._fixture(
                ha_state="unlocked", rule="keep_unlock", door_state="unlocked"
            )
            rules["dev-hub-1"] = {"type": "future_unknown_rule"}

            self.assertEqual(await mgr.poll_once(), 1)
            self.assertEqual(states["lock.front"], "locked")
            ha.lock.assert_awaited_once_with("lock.front")
            access.hold_locked.assert_awaited_once_with(
                "dev-hub-1", location_id="loc-1"
            )
            self.assertEqual(access_states["dev-hub-1"], "locked")
        _run(go())

    def test_lockdown_uses_persistent_hold_locked_not_rule_restore(self) -> None:
        async def go():
            mgr, _ha, access, _states, _rules, access_states = self._fixture(
                ha_state="unlocked", rule="schedule", door_state="unlocked"
            )
            mgr._lockdown_getter = lambda: True

            self.assertEqual(await mgr.poll_once(), 1)
            access.hold_locked.assert_awaited_once_with(
                "dev-hub-1", location_id="loc-1"
            )
            access.restore_native_rule.assert_not_awaited()
            self.assertEqual(access_states["dev-hub-1"], "locked")
        _run(go())

    def test_access_momentary_marker_suppresses_keep_unlock_echo(self) -> None:
        async def go():
            mgr, _ha, access, states, _rules, _access_states = self._fixture()
            await mgr.poll_once()
            mgr.mark_access_momentary("lock.front", 30)
            states["lock.front"] = "unlocked"

            self.assertEqual(await mgr.poll_once(), 0)
            access.hold_unlocked.assert_not_awaited()
        _run(go())

    def test_persisted_baseline_identifies_access_only_keep_unlock(self) -> None:
        async def go():
            mgr, ha, _access, states, _rules, _access_states = self._fixture(
                ha_state="locked", rule="keep_unlock", door_state="unlocked"
            )
            mgr._db.get_hub_sync_states = AsyncMock(return_value=[{
                "entity_id": "lock.front",
                "desired_state": "locked",
                "source": "already_converged",
                "ha_state": "locked",
                "access_state": "locked",
                "access_rule_fingerprint": "previous-locked-rule",
                "pairing_signature": '["dev-hub-1"]',
            }])
            mgr._db.set_hub_sync_state = AsyncMock()

            self.assertEqual(await mgr.poll_once(), 1)
            self.assertEqual(states["lock.front"], "unlocked")
            ha.unlock.assert_awaited_once_with("lock.front")
        _run(go())

    def test_ha_disconnect_holds_access_locked_even_for_external_schedule(self) -> None:
        async def go():
            mgr, ha, access, _states, _rules, access_states = self._fixture(
                ha_state="unlocked", rule="schedule", door_state="unlocked"
            )
            ha.connected = False

            self.assertEqual(await mgr.poll_once(), 0)
            access.hold_locked.assert_awaited_once_with(
                "dev-hub-1", location_id="loc-1"
            )
            access.restore_native_rule.assert_not_awaited()
            self.assertEqual(access_states["dev-hub-1"], "locked")
        _run(go())

    def test_open_api_token_remains_available_without_private_session(self) -> None:
        async def go():
            mgr, ha, access, states, _rules, _access_states = self._fixture(
                ha_state="locked", rule="schedule", door_state="unlocked"
            )
            access.connected = False
            access.open_api_configured = True

            self.assertEqual(await mgr.poll_once(), 1)
            self.assertEqual(states["lock.front"], "unlocked")
            ha.unlock.assert_awaited_once_with("lock.front")
        _run(go())


class TestBidirectionalDamping(unittest.TestCase):
    """Flap/backoff damping must also bound command volume on the
    bidirectional reconcile path — not only the legacy _poll_once path."""

    def _fixture(self, *, ha_state="locked", rule="reset", door_state="locked"):
        ha_states = {"lock.front": ha_state}
        access_rules = {"dev-hub-1": {"type": rule}}
        access_states = {"dev-hub-1": door_state}
        db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
        ha = _make_bidirectional_ha(ha_states)
        access = _make_bidirectional_access(access_rules, access_states)
        mgr = _make_mgr(db, ha, access)
        return mgr, ha, access, ha_states, access_rules, access_states

    def test_apply_times_stays_bounded_across_many_bidirectional_drives(self) -> None:
        """Bug 1: the flap-timestamp list is pruned at append time, so it
        cannot grow unbounded for the install's lifetime in bidirectional
        mode (where the legacy lazy prune never runs)."""
        async def go():
            mgr, _ha, _access, states, _rules, _access_states = self._fixture()
            clock = {"t": 1000.0}
            with patch(
                "access_control.hub_sync.time.monotonic",
                side_effect=lambda: clock["t"],
            ):
                await mgr.poll_once()  # confirmed locked baseline
                # Alternate the lock every poll, stepping well past the flap
                # window so each real actuation prunes every older timestamp.
                for i in range(60):
                    clock["t"] += hs_module._FLAP_WINDOW + 5
                    states["lock.front"] = "unlocked" if i % 2 == 0 else "locked"
                    await mgr.poll_once()
                # Without append-time pruning this would retain ~60 entries.
                self.assertLessEqual(
                    len(mgr._apply_times.get("lock.front", [])), 2
                )
        _run(go())

    def test_bidirectional_hold_open_respects_min_apply_interval(self) -> None:
        """Bug 2: a hold-open drive within the min-apply interval is
        deferred (never lost) — locking is never delayed by this."""
        async def go():
            mgr, ha, _access, _states, rules, access_states = self._fixture()
            await mgr.poll_once()  # confirmed locked baseline

            # A very recent prior actuation makes the min-apply clock hot.
            mgr._last_applied_at["lock.front"] = _time.monotonic()
            # An Access schedule opens the door (missed event caught by poll).
            rules["dev-hub-1"] = {"type": "keep_unlock"}
            access_states["dev-hub-1"] = "unlocked"

            self.assertEqual(await mgr.poll_once(), 0)
            ha.unlock.assert_not_awaited()

            # After the interval elapses the deferred hold-open applies.
            _clear_damping(mgr)
            self.assertEqual(await mgr.poll_once(), 1)
            ha.unlock.assert_awaited_once_with("lock.front")
        _run(go())

    def test_sustained_bidirectional_flapping_suspends_and_fails_safe(self) -> None:
        """Bug 2: enough recent hold-open drives inside the flap window
        suspends the entity before issuing yet another hold-open."""
        async def go():
            mgr, ha, access, states, _rules, _access_states = self._fixture()
            await mgr.poll_once()  # confirmed locked baseline

            now = _time.monotonic()
            mgr._apply_times["lock.front"] = [
                now - i for i in range(hs_module._FLAP_THRESHOLD)
            ]

            states["lock.front"] = "unlocked"
            self.assertEqual(await mgr.poll_once(), 0)
            self.assertGreater(
                mgr._suspended_until.get("lock.front", 0), _time.monotonic()
            )
            access.hold_unlocked.assert_not_awaited()
            ha.unlock.assert_not_awaited()
            ha.fire_event.assert_awaited_once_with(
                "access_control_hub_sync_failed",
                {"entity_id": "lock.front", "lock_name": "Front Deadbolt",
                 "reason": "flapping"},
            )

            # While suspended the hold-open is not followed at all.
            self.assertEqual(await mgr.poll_once(), 0)
            access.hold_unlocked.assert_not_awaited()
        _run(go())

    def test_lockdown_enforcement_is_not_damped_by_flap_suspension(self) -> None:
        """Bug 2 safety invariant: locking during lockdown bypasses every
        damping gate. Even a fully suspended/backed-off entity is still
        closed immediately (lockdown never reaches _reconcile_bidirectional)."""
        async def go():
            mgr, _ha, access, _states, _rules, access_states = self._fixture(
                ha_state="unlocked", rule="keep_unlock", door_state="unlocked"
            )
            future = _time.monotonic() + hs_module._FLAP_SUSPEND
            mgr._suspended_until["lock.front"] = future
            mgr._backoff_until["lock.front"] = future
            mgr._last_applied_at["lock.front"] = _time.monotonic()
            mgr._lockdown_getter = lambda: True

            self.assertEqual(await mgr.poll_once(), 1)
            access.hold_locked.assert_awaited_once_with(
                "dev-hub-1", location_id="loc-1"
            )
            self.assertEqual(access_states["dev-hub-1"], "locked")
        _run(go())


class TestLockedDirectionHardRejectionBackoff(unittest.TestCase):
    """A repeatedly hard-rejected locked drive (e.g. a UNVR Access update
    removing the legacy per-device lock_rule endpoint) must be spaced onto a
    bounded backoff — never stopped, never blocking lockdown, and only for a
    genuine permanent rejection (not a transient fault)."""

    def _fixture(self, error, *, ha_state="locked"):
        """Bidirectional pair whose readback and locked drive both raise
        ``error`` while ``broken['on']`` is True."""
        broken = {"on": True}
        ha_states = {"lock.front": ha_state}
        access_rules = {"dev-hub-1": {"type": "keep_lock"}}
        access_states = {"dev-hub-1": "locked"}
        db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
        ha = _make_bidirectional_ha(ha_states)
        access = _make_bidirectional_access(access_rules, access_states)

        async def get_rule(device_id, location_id=None):
            if broken["on"]:
                raise error
            return dict(access_rules[device_id])

        async def get_state(device_id, location_id=None):
            if broken["on"]:
                raise error
            return access_states[device_id]

        async def hold_locked(device_id, location_id=None):
            if broken["on"]:
                raise error
            access_rules[device_id] = {"type": "keep_lock"}
            access_states[device_id] = "locked"
            return {"type": "keep_lock", "state": "locked"}

        access.get_lock_rule = AsyncMock(side_effect=get_rule)
        access.get_door_state = AsyncMock(side_effect=get_state)
        access.hold_locked = AsyncMock(side_effect=hold_locked)
        mgr = _make_mgr(db, ha, access)
        return mgr, ha, access, broken

    def test_repeated_hard_rejection_backs_off_then_resumes(self) -> None:
        async def go():
            mgr, _ha, access, _broken = self._fixture(
                AccessLegacyEndpointGoneError("legacy gone")
            )
            threshold = hs_module._HARD_REJECT_BACKOFF_THRESHOLD
            retries = hs_module._APPLY_RETRIES
            old_delay = hs_module._APPLY_RETRY_DELAY
            hs_module._APPLY_RETRY_DELAY = 0.0
            try:
                # Full cadence until the consecutive hard-rejection threshold.
                for _ in range(threshold):
                    self.assertEqual(await mgr.poll_once(), 0)
                at_threshold = access.hold_locked.await_count
                self.assertEqual(at_threshold, threshold * retries)
                self.assertGreater(
                    mgr._backoff_until.get("lock.front", 0.0), _time.monotonic()
                )

                # Inside the backoff window the locked drive is SKIPPED — but
                # the durable safe intent is retained, not abandoned.
                self.assertEqual(await mgr.poll_once(), 0)
                self.assertEqual(access.hold_locked.await_count, at_threshold)
                self.assertIn("lock.front", mgr._fail_safe_reset_eids)

                # After the deadline passes the drive RESUMES — forever, spaced.
                mgr._backoff_until.clear()
                self.assertEqual(await mgr.poll_once(), 0)
                self.assertGreater(
                    access.hold_locked.await_count, at_threshold
                )
            finally:
                hs_module._APPLY_RETRY_DELAY = old_delay
        _run(go())

    def test_transient_error_never_backs_off_locked_direction(self) -> None:
        async def go():
            # A 5xx is transient: it must keep retrying at full cadence and
            # never engage the hard-rejection backoff.
            mgr, _ha, access, _broken = self._fixture(
                AccessClientError("HTTP 503 from PUT /…/lock_rule", status=503)
            )
            retries = hs_module._APPLY_RETRIES
            polls = hs_module._HARD_REJECT_BACKOFF_THRESHOLD + 3
            old_delay = hs_module._APPLY_RETRY_DELAY
            hs_module._APPLY_RETRY_DELAY = 0.0
            try:
                for _ in range(polls):
                    self.assertEqual(await mgr.poll_once(), 0)
                # Every poll drove both attempts — no skip ever happened.
                self.assertEqual(
                    access.hold_locked.await_count, polls * retries
                )
                self.assertNotIn("lock.front", mgr._backoff_until)
                self.assertNotIn("lock.front", mgr._hard_reject_state)
            finally:
                hs_module._APPLY_RETRY_DELAY = old_delay
        _run(go())

    def test_lockdown_drives_at_full_cadence_during_hard_rejection_backoff(
        self,
    ) -> None:
        """Safety invariant: an entity parked in hard-rejection backoff is
        still force-closed immediately under lockdown, because lockdown never
        reaches _reconcile_bidirectional (mirrors the flap-suspension test)."""
        async def go():
            ha_states = {"lock.front": "unlocked"}
            access_rules = {"dev-hub-1": {"type": "keep_unlock"}}
            access_states = {"dev-hub-1": "unlocked"}
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            ha = _make_bidirectional_ha(ha_states)
            access = _make_bidirectional_access(access_rules, access_states)
            mgr = _make_mgr(db, ha, access)

            # Park the entity in a fully-engaged hard-rejection backoff.
            future = _time.monotonic() + hs_module._FAILURE_BACKOFF
            mgr._backoff_until["lock.front"] = future
            mgr._hard_reject_state["lock.front"] = (
                "legacy_endpoint_gone",
                hs_module._HARD_REJECT_BACKOFF_THRESHOLD + 2,
            )
            mgr._lockdown_getter = lambda: True

            self.assertEqual(await mgr.poll_once(), 1)
            access.hold_locked.assert_awaited_once_with(
                "dev-hub-1", location_id="loc-1"
            )
            self.assertEqual(access_states["dev-hub-1"], "locked")
        _run(go())

    def test_drive_failure_logs_once_then_debug_and_rearms(self) -> None:
        async def go():
            mgr, _ha, _access, broken = self._fixture(
                AccessLegacyEndpointGoneError("legacy gone; configure token")
            )
            old_delay = hs_module._APPLY_RETRY_DELAY
            hs_module._APPLY_RETRY_DELAY = 0.0
            logger = MagicMock()

            def drive_exception_calls():
                return [
                    c for c in logger.exception.call_args_list
                    if "Hub sync attempt" in c.args[0]
                ]

            try:
                with patch.object(hs_module, "_LOGGER", logger):
                    # First failing poll: attempt 1 logs loudly (ERROR via
                    # _LOGGER.exception), attempt 2 (same signature) is debug.
                    await mgr.poll_once()
                    self.assertEqual(len(drive_exception_calls()), 1)
                    # The actionable message rides along on that first log.
                    self.assertIn(
                        "configure token",
                        str(drive_exception_calls()[0].args[-1]),
                    )

                    # A second failing poll adds no new loud log (debug only).
                    await mgr.poll_once()
                    self.assertEqual(len(drive_exception_calls()), 1)

                    # Convergence clears the signature and re-arms loud logging;
                    # a fresh incident then logs at ERROR again.
                    broken["on"] = False
                    await mgr.poll_once()  # converges (release to locked)
                    broken["on"] = True
                    await mgr.poll_once()  # new incident
                    self.assertEqual(len(drive_exception_calls()), 2)
            finally:
                hs_module._APPLY_RETRY_DELAY = old_delay
        _run(go())


class TestPersistentOverrideLifecycleRegressions(unittest.TestCase):
    def test_lockdown_rechecks_and_relocks_later_external_unlocks(self) -> None:
        async def go():
            ha_states = {"lock.front": "unlocked"}
            rules = {"dev-hub-1": {"type": "schedule"}}
            access_states = {"dev-hub-1": "unlocked"}
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            access = _make_bidirectional_access(rules, access_states)
            ha = _make_bidirectional_ha(ha_states)
            mgr = _make_mgr(db, ha, access, lockdown=lambda: True)

            self.assertEqual(await mgr.poll_once(), 1)
            self.assertEqual(rules["dev-hub-1"]["type"], "keep_lock")
            self.assertEqual(ha_states["lock.front"], "locked")

            # A later direct Access schedule activation and HA unlock must not
            # be hidden by the prior one-shot acknowledgement.
            rules["dev-hub-1"] = {"type": "schedule"}
            access_states["dev-hub-1"] = "unlocked"
            ha_states["lock.front"] = "unlocked"

            self.assertEqual(await mgr.poll_once(), 1)
            self.assertEqual(access.hold_locked.await_count, 2)
            self.assertEqual(ha.lock.await_count, 2)
            self.assertEqual(rules["dev-hub-1"]["type"], "keep_lock")
            self.assertEqual(ha_states["lock.front"], "locked")

            # Confirmed-safe state is read back on subsequent polls without
            # duplicate writes.
            self.assertEqual(await mgr.poll_once(), 0)
            self.assertEqual(access.hold_locked.await_count, 2)
            self.assertEqual(ha.lock.await_count, 2)
        _run(go())

    def test_poll_without_explicit_recover_first_holds_persisted_open_locked(self) -> None:
        async def go():
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            db.get_hub_sync_holds = AsyncMock(return_value=[{
                "entity_id": "lock.front",
                "hub_device_id": "dev-hub-1",
                "hub_lock_id": 1,
                "hub_location_id": "loc-1",
                "hub_name": "Front Door Hub",
                "override_type": "keep_unlock",
            }])
            ha = _make_ha({})
            ha.connected = False
            access = _make_access()
            access.hold_locked = AsyncMock(
                return_value={"type": "keep_lock", "state": "locked"}
            )
            access.restore_native_rule = AsyncMock(
                return_value={"type": "reset", "state": "unlocked"}
            )
            mgr = _make_mgr(db, ha, access)

            await mgr.poll_once()

            access.hold_locked.assert_awaited_once_with(
                "dev-hub-1", location_id="loc-1"
            )
            access.restore_native_rule.assert_not_awaited()
            db.record_hub_sync_hold.assert_awaited_with(
                "lock.front",
                "dev-hub-1",
                1,
                "Front Door Hub",
                hub_location_id="loc-1",
                override_type="keep_lock",
            )
        _run(go())

    def test_crash_recovered_keep_lock_is_released_once_ha_is_trustworthy(self) -> None:
        async def go():
            rules = {"dev-hub-1": {"type": "keep_lock"}}
            access_states = {"dev-hub-1": "locked"}
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            db.get_hub_sync_holds = AsyncMock(return_value=[{
                "entity_id": "lock.front",
                "hub_device_id": "dev-hub-1",
                "hub_lock_id": 1,
                "hub_location_id": "loc-1",
                "hub_name": "Front Door Hub",
                "override_type": "keep_lock",
            }])
            ha = _make_bidirectional_ha({"lock.front": "locked"})
            access = _make_bidirectional_access(rules, access_states)

            async def release(device_id, location_id=None):
                rules[device_id] = {"type": "lock_early"}
                access_states[device_id] = "locked"
                return {"type": "lock_early", "state": "locked"}

            access.release_persistent_lock = AsyncMock(side_effect=release)
            mgr = _make_mgr(db, ha, access)

            self.assertEqual(await mgr.recover(), 1)
            access.hold_locked.assert_awaited_once_with(
                "dev-hub-1", location_id="loc-1"
            )

            self.assertEqual(await mgr.poll_once(), 1)
            access.release_persistent_lock.assert_awaited_once_with(
                "dev-hub-1", location_id="loc-1"
            )
            db.clear_hub_sync_hold.assert_any_await(
                "lock.front", "dev-hub-1"
            )
            self.assertFalse(mgr._held_locked.get("lock.front"))

            await mgr.poll_once()
            self.assertEqual(access.release_persistent_lock.await_count, 1)
        _run(go())

    def test_shared_hub_conflict_override_is_released_when_owner_is_removed(self) -> None:
        async def go():
            other = dict(
                HA_LOCK,
                id=4,
                entity_id="lock.back",
                name="Back Deadbolt",
            )
            states = {"lock.front": "locked", "lock.back": "locked"}
            db = _make_db(
                [HA_LOCK, other, HUB],
                location_map={"loc-1": [HUB]},
            )
            access = _make_access()
            access.hold_locked = AsyncMock(
                return_value={"type": "keep_lock", "state": "locked"}
            )
            access.release_persistent_lock = AsyncMock(
                return_value={"type": "lock_early", "state": "locked"}
            )
            access.restore_native_rule = AsyncMock(
                return_value={"type": "reset", "state": "locked"}
            )
            mgr = _make_mgr(db, _make_ha(states), access)

            await mgr.poll_once()
            access.hold_locked.assert_awaited_once_with(
                "dev-hub-1", location_id="loc-1"
            )

            db.get_all_locks = AsyncMock(return_value=[HA_LOCK, HUB])
            await mgr.poll_once()

            cleared = {call.args for call in db.clear_hub_sync_hold.await_args_list}
            self.assertIn(("lock.front", "dev-hub-1"), cleared)
            self.assertIn(("lock.back", "dev-hub-1"), cleared)
            self.assertFalse(mgr._held_locked.get("lock.front"))
            self.assertFalse(mgr._held_locked.get("lock.back"))
        _run(go())

    def test_external_schedule_supersedes_owned_keep_unlock(self) -> None:
        async def go():
            ha_states = {"lock.front": "locked"}
            rules = {"dev-hub-1": {"type": "reset"}}
            access_states = {"dev-hub-1": "locked"}
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            access = _make_bidirectional_access(rules, access_states)
            mgr = _make_mgr(db, _make_bidirectional_ha(ha_states), access)

            await mgr.poll_once()
            ha_states["lock.front"] = "unlocked"
            await mgr.poll_once()
            self.assertTrue(mgr._held_open.get("lock.front"))

            # A UI or Access-console action restores the native active schedule.
            rules["dev-hub-1"] = {"type": "schedule", "ended_time": 123}
            access_states["dev-hub-1"] = "unlocked"
            await mgr.poll_once()

            db.clear_hub_sync_hold.assert_awaited_once_with(
                "lock.front", "dev-hub-1"
            )
            self.assertFalse(mgr._held_open.get("lock.front"))
            self.assertNotIn("lock.front", mgr._fail_safe_reset_eids)
        _run(go())

    def test_graceful_restore_reports_schedule_relay_state_to_cache(self) -> None:
        async def go():
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            access = _make_access()
            access.open_api_configured = True
            access.hold_unlocked = AsyncMock(
                return_value={"type": "keep_unlock", "state": "unlocked"}
            )
            access.restore_native_rule = AsyncMock(
                return_value={"type": "schedule", "state": "unlocked"}
            )
            observed: list[tuple[str, str]] = []
            mgr = _make_mgr(
                db,
                _make_ha({"lock.front": "unlocked"}),
                access,
                on_hub_state=lambda device_id, state: observed.append(
                    (device_id, state)
                ),
            )

            await mgr.poll_once()
            self.assertEqual(await mgr.shutdown(), 1)

            access.restore_native_rule.assert_awaited_once_with(
                "dev-hub-1", location_id="loc-1"
            )
            self.assertEqual(observed[-1], ("dev-hub-1", "unlocked"))
        _run(go())

    def test_lockdown_still_physically_closes_when_ownership_write_fails(self) -> None:
        async def go():
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            db.record_hub_sync_hold = AsyncMock(
                side_effect=RuntimeError("sqlite unavailable")
            )
            access = _make_access()
            access.hold_locked = AsyncMock(
                return_value={"type": "keep_lock", "state": "locked"}
            )
            mgr = _make_mgr(
                db,
                _make_ha({"lock.front": "unlocked"}),
                access,
                lockdown=lambda: True,
            )

            with self.assertRaisesRegex(RuntimeError, "unresolved"):
                await mgr.enforce_lockdown()

            access.hold_locked.assert_awaited_once_with(
                "dev-hub-1", location_id="loc-1"
            )
            db.clear_hub_sync_hold.assert_not_awaited()
        _run(go())

    def test_removed_hub_keep_lock_is_released_after_current_hub_converges(self) -> None:
        async def go():
            location_map = {"loc-1": [HUB, HUB_2]}
            rules = {
                "dev-hub-1": {"type": "keep_lock"},
                "dev-hub-2": {"type": "keep_lock"},
            }
            access_states = {
                "dev-hub-1": "locked",
                "dev-hub-2": "locked",
            }
            db = _make_db(
                [HA_LOCK, HUB, HUB_2],
                location_map=location_map,
            )
            db.get_hub_sync_holds = AsyncMock(return_value=[
                {
                    "entity_id": "lock.front",
                    "hub_device_id": hub["device_id"],
                    "hub_lock_id": hub["id"],
                    "hub_location_id": hub["location_id"],
                    "hub_name": hub["name"],
                    "override_type": "keep_lock",
                }
                for hub in (HUB, HUB_2)
            ])
            access = _make_bidirectional_access(rules, access_states)

            async def release(device_id, location_id=None):
                rules[device_id] = {"type": "lock_early"}
                access_states[device_id] = "locked"
                return {"type": "lock_early", "state": "locked"}

            access.release_persistent_lock = AsyncMock(side_effect=release)
            mgr = _make_mgr(
                db,
                _make_bidirectional_ha({"lock.front": "locked"}),
                access,
            )

            self.assertEqual(await mgr.recover(), 2)
            location_map["loc-1"] = [HUB]
            await mgr.poll_once()
            await mgr.poll_once()

            db.clear_hub_sync_hold.assert_any_await(
                "lock.front", "dev-hub-1"
            )
            db.clear_hub_sync_hold.assert_any_await(
                "lock.front", "dev-hub-2"
            )
            self.assertNotEqual(rules["dev-hub-2"]["type"], "keep_lock")
            self.assertFalse(mgr._held_locked.get("lock.front"))
        _run(go())


class TestFailSafeObservationRelease(unittest.TestCase):
    """1.5.12 change 3: the locked-wins fail-safe latch is released when a poll
    observes both sides locked, even if the cosmetic keep_lock→lock_now release
    confirm fails forever (the ``reset`` self-clear wedge). It must NOT release
    on a partial/invalid observation, and lockdown is on a separate path."""

    def _fixture(
        self,
        *,
        ha_state="locked",
        rule="keep_lock",
        door_state="locked",
        authoritative_relay=True,
    ):
        ha_states = {"lock.front": ha_state}
        access_rules = {"dev-hub-1": {"type": rule}}
        access_states = {"dev-hub-1": door_state}
        db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
        ha = _make_bidirectional_ha(ha_states)
        access = _make_bidirectional_access(
            access_rules,
            access_states,
            authoritative_relay=authoritative_relay,
        )
        mgr = _make_mgr(db, ha, access)
        return mgr, ha, access, ha_states, access_rules, access_states

    def test_wedge_release_on_observed_both_locked_then_unlock_mirrored(
        self,
    ) -> None:
        """(v) THE WEDGE: latched entity whose lock_now release confirm fails
        forever; a poll observing both sides locked releases the latch, and a
        following HA-origin unlock is mirrored (not reverted)."""
        async def go():
            mgr, ha, access, ha_states, rules, access_states = self._fixture()
            await mgr.poll_once()  # both-locked baseline; recovery complete

            # The pair is latched closed and the app owns a durable keep_lock,
            # but the lock_now release confirm fails forever on this firmware
            # (rule self-clears to `reset` mid-actuation).
            mgr._fail_safe_reset_eids.add("lock.front")
            mgr._held_locked["lock.front"] = [
                {
                    "device_id": "dev-hub-1",
                    "hub_lock_id": 1,
                    "hub_location_id": "loc-1",
                    "hub_name": "Front Door Hub",
                }
            ]

            async def failing_release(device_id, location_id=None, on_written=None):
                if on_written is not None:
                    on_written()
                raise AccessClientError(
                    "lock_now command was not confirmed "
                    "(observed rule=reset, state=None)"
                )

            access.release_persistent_lock = AsyncMock(side_effect=failing_release)

            with patch(
                "access_control.hub_sync.asyncio.sleep", new=AsyncMock()
            ):
                await mgr.poll_once()

            # The cosmetic release drive was attempted and permanently failed,
            # yet the latch is released on the both-locked observation so it can
            # no longer revert unlocks indefinitely.
            self.assertGreaterEqual(
                access.release_persistent_lock.await_count, 1
            )
            self.assertNotIn("lock.front", mgr._fail_safe_reset_eids)

            # A following genuine HA-origin unlock is now mirrored, not reverted.
            ha_states["lock.front"] = "unlocked"
            _clear_damping(mgr)
            with patch(
                "access_control.hub_sync.asyncio.sleep", new=AsyncMock()
            ):
                self.assertEqual(await mgr.poll_once(), 1)
            access.hold_unlocked.assert_awaited_once_with(
                "dev-hub-1", location_id="loc-1"
            )
            self.assertEqual(ha_states["lock.front"], "unlocked")
        _run(go())

    def test_latch_not_released_when_a_side_is_not_locked(self) -> None:
        """(vi) A partial observation (Access still unlocked) must keep the
        latch even when the fail-safe lock drive fails; only both-sides-locked
        releases it."""
        async def go():
            mgr, ha, access, ha_states, rules, access_states = self._fixture(
                ha_state="locked", rule="keep_unlock", door_state="unlocked"
            )
            # Non-fresh baseline so the mismatch is source-classified, then latch.
            mgr._last_ha_observed["lock.front"] = "locked"
            mgr._last_access_observed["lock.front"] = "locked"
            mgr._last_access_rule["lock.front"] = "prev-locked"
            mgr._fail_safe_reset_eids.add("lock.front")

            async def failing_lock(device_id, location_id=None, on_written=None):
                raise AccessClientError("keep_lock was not confirmed")

            access.hold_locked = AsyncMock(side_effect=failing_lock)

            with patch(
                "access_control.hub_sync.asyncio.sleep", new=AsyncMock()
            ):
                await mgr.poll_once()

            # Access was observed unlocked (partial), so the latch is retained.
            self.assertIn("lock.front", mgr._fail_safe_reset_eids)
        _run(go())

    def test_closed_rule_with_unlocked_relay_keeps_latch(self) -> None:
        """Closed intent still suppresses credential-pulse mirroring, but an
        authoritative unlocked relay cannot release the safety latch."""
        async def go():
            mgr, _ha, access, _ha_states, _rules, _access_states = self._fixture(
                rule="keep_lock",
                door_state="unlocked",
            )
            mgr._fail_safe_reset_eids.add("lock.front")

            async def failing_lock(device_id, location_id=None, on_written=None):
                raise AccessClientError("keep_lock was not confirmed")

            access.hold_locked = AsyncMock(side_effect=failing_lock)

            with patch(
                "access_control.hub_sync.asyncio.sleep", new=AsyncMock()
            ):
                await mgr.poll_once()

            self.assertGreaterEqual(access.hold_locked.await_count, 1)
            self.assertIn("lock.front", mgr._fail_safe_reset_eids)
        _run(go())

    def test_legacy_rule_derived_locked_state_cannot_release_latch(self) -> None:
        """Without Open API relay readback, a keep_lock rule is intent only."""
        async def go():
            mgr, _ha, access, _ha_states, _rules, _access_states = self._fixture(
                authoritative_relay=False,
            )
            mgr._fail_safe_reset_eids.add("lock.front")

            async def failing_lock(device_id, location_id=None, on_written=None):
                raise AccessClientError("keep_lock was not confirmed")

            access.hold_locked = AsyncMock(side_effect=failing_lock)

            with patch(
                "access_control.hub_sync.asyncio.sleep", new=AsyncMock()
            ):
                await mgr.poll_once()

            self.assertGreaterEqual(access.hold_locked.await_count, 1)
            self.assertIn("lock.front", mgr._fail_safe_reset_eids)
        _run(go())

    def test_successful_legacy_keep_lock_still_cannot_release_latch(self) -> None:
        """A confirmed private rule write is not physical relay evidence."""
        async def go():
            mgr, _ha, access, _ha_states, _rules, _access_states = self._fixture(
                authoritative_relay=False,
            )
            mgr._fail_safe_reset_eids.add("lock.front")

            with patch(
                "access_control.hub_sync.asyncio.sleep", new=AsyncMock()
            ):
                await mgr.poll_once()

            access.hold_locked.assert_awaited()
            self.assertIn("lock.front", mgr._fail_safe_reset_eids)
        _run(go())

    def test_client_swap_cannot_promote_legacy_confirmation(self) -> None:
        """Relay authority follows the writer, not a later published client."""
        async def go():
            mgr, _ha, legacy, _ha_states, _rules, _access_states = self._fixture(
                authoritative_relay=False,
            )
            current = {"client": legacy}
            mgr._get_access = lambda: current["client"]
            mgr._fail_safe_reset_eids.add("lock.front")

            replacement = _make_bidirectional_access(
                {"dev-hub-1": {"type": "keep_unlock"}},
                {"dev-hub-1": "unlocked"},
                authoritative_relay=True,
            )

            async def legacy_hold_locked(
                device_id,
                location_id=None,
                on_written=None,
            ):
                # Settings can publish a replacement client as soon as the
                # command's write hook releases the shared barrier. The
                # private client then returns only its rule-derived result.
                if on_written is not None:
                    on_written()
                current["client"] = replacement
                return {"type": "keep_lock", "state": "locked"}

            legacy.hold_locked = legacy_hold_locked

            with patch(
                "access_control.hub_sync.asyncio.sleep", new=AsyncMock()
            ):
                await mgr.poll_once()

            self.assertIs(current["client"], replacement)
            self.assertEqual(
                await replacement.get_door_state(
                    "dev-hub-1", location_id="loc-1"
                ),
                "unlocked",
            )
            self.assertIn("lock.front", mgr._fail_safe_reset_eids)
        _run(go())

    def test_external_rule_supersession_cannot_bypass_latch(self) -> None:
        """Losing keep_lock ownership is not proof that the relay is safe."""
        async def go():
            mgr, ha, access, ha_states, rules, access_states = self._fixture()
            mgr._held_locked["lock.front"] = [
                {
                    "device_id": "dev-hub-1",
                    "hub_lock_id": 1,
                    "hub_location_id": "loc-1",
                    "hub_name": "Front Door Hub",
                }
            ]
            mgr._fail_safe_reset_eids.add("lock.front")

            # An external Access action replaces the app's keep_lock with an
            # active schedule and the authoritative relay opens.
            rules["dev-hub-1"] = {"type": "schedule"}
            access_states["dev-hub-1"] = "unlocked"
            access.hold_locked = AsyncMock(
                side_effect=AccessClientError("keep_lock did not confirm")
            )

            with patch(
                "access_control.hub_sync.asyncio.sleep", new=AsyncMock()
            ):
                self.assertEqual(await mgr.poll_once(), 0)

            self.assertIn("lock.front", mgr._fail_safe_reset_eids)
            self.assertEqual(ha_states["lock.front"], "locked")
            ha.unlock.assert_not_awaited()
            access.hold_locked.assert_awaited()
            self.assertEqual(access_states["dev-hub-1"], "unlocked")
        _run(go())

    def test_latch_not_released_when_access_is_unreadable(self) -> None:
        """(vi) An unreadable Access side (observation invalid → None) keeps the
        latch even though HA reads locked."""
        async def go():
            mgr, ha, access, ha_states, rules, access_states = self._fixture()
            await mgr.poll_once()
            mgr._fail_safe_reset_eids.add("lock.front")
            # Unknown rule → _observe_access_hub raises → access side is None.
            rules["dev-hub-1"] = {"type": "future_unknown_rule"}

            async def failing_lock(device_id, location_id=None, on_written=None):
                raise AccessClientError("keep_lock was not confirmed")

            access.hold_locked = AsyncMock(side_effect=failing_lock)

            with patch(
                "access_control.hub_sync.asyncio.sleep", new=AsyncMock()
            ):
                await mgr.poll_once()

            self.assertIn("lock.front", mgr._fail_safe_reset_eids)
        _run(go())

    def test_lockdown_reasserts_keep_lock_when_raw_relay_is_unlocked(self) -> None:
        async def go():
            mgr, _ha, access, _ha_states, _rules, access_states = self._fixture(
                rule="keep_lock",
                door_state="unlocked",
            )
            mgr._lockdown_getter = lambda: True
            mgr._lockdown_reset.add("lock.front")

            self.assertEqual(await mgr.poll_once(), 1)

            access.hold_locked.assert_awaited_once_with(
                "dev-hub-1", location_id="loc-1"
            )
            self.assertEqual(access_states["dev-hub-1"], "locked")
            self.assertIn("lock.front", mgr._lockdown_reset)
        _run(go())

    def test_legacy_keep_lock_cannot_acknowledge_lockdown_safety(self) -> None:
        async def go():
            mgr, _ha, access, _ha_states, _rules, _access_states = self._fixture(
                authoritative_relay=False,
            )
            mgr._lockdown_getter = lambda: True

            self.assertEqual(await mgr.poll_once(), 0)

            access.hold_locked.assert_awaited_once_with(
                "dev-hub-1", location_id="loc-1"
            )
            self.assertNotIn("lock.front", mgr._lockdown_reset)
            self.assertEqual(mgr.lockdown_unresolved, ("lock.front",))
        _run(go())

    def test_lockdown_enforcement_unaffected(self) -> None:
        """(vii) Lockdown enforcement drives keep_lock through its own branch,
        unaffected by the extended confirm window or the fail-safe release
        path (it converges and does not use rule restore)."""
        async def go():
            mgr, ha, access, ha_states, rules, access_states = self._fixture(
                ha_state="unlocked", rule="schedule", door_state="unlocked"
            )
            mgr._lockdown_getter = lambda: True

            with patch(
                "access_control.hub_sync.asyncio.sleep", new=AsyncMock()
            ):
                self.assertEqual(await mgr.poll_once(), 1)

            access.hold_locked.assert_awaited_once_with(
                "dev-hub-1", location_id="loc-1"
            )
            access.restore_native_rule.assert_not_awaited()
            self.assertEqual(access_states["dev-hub-1"], "locked")
        _run(go())

    def test_fail_safe_pending_property_reflects_latched_entities(self) -> None:
        """(viii) The health property exposes latched entity IDs (sorted),
        matching lockdown_unresolved's scope handling."""
        async def go():
            mgr, *_ = self._fixture()
            self.assertEqual(mgr.fail_safe_pending, ())
            mgr._fail_safe_reset_eids.update({"lock.back", "lock.front"})
            self.assertEqual(
                mgr.fail_safe_pending, ("lock.back", "lock.front")
            )
        _run(go())


class TestRelockOnHaOrigin(unittest.TestCase):
    """Change 4: opt-in relock_on_ha_origin time-bounds a genuine external
    (thumb-turn / HA-automation) unlock, while excluding every app-initiated
    unlock."""

    def _fixture(self, *, ha_origin=True):
        lock = dict(HA_LOCK)
        lock["relock_on_ha_origin"] = 1 if ha_origin else 0
        ha_states = {"lock.front": "locked"}
        access_rules = {"dev-hub-1": {"type": "reset"}}
        access_states = {"dev-hub-1": "locked"}
        db = _make_db([lock, HUB], location_map={"loc-1": [HUB]})
        db.get_pending_relock = AsyncMock(return_value=None)
        ha = _make_bidirectional_ha(ha_states)
        access = _make_bidirectional_access(access_rules, access_states)
        relock = MagicMock()
        relock.schedule = AsyncMock()
        mgr = HubSyncManager(
            db=db,
            ha_client_getter=lambda: ha,
            access_client_getter=lambda: access,
            relock_manager_getter=lambda: relock,
        )
        return mgr, ha, access, relock, db, ha_states

    def test_ha_origin_unlock_schedules_relock_once_per_edge(self) -> None:
        async def go():
            mgr, ha, access, relock, db, ha_states = self._fixture()
            await mgr.poll_once()  # confirmed locked baseline
            ha_states["lock.front"] = "unlocked"  # external thumb-turn
            _clear_damping(mgr)
            order: list[str] = []

            async def schedule(**kwargs):
                order.append("schedule")

            relock.schedule.side_effect = schedule
            original_hold_unlocked = access.hold_unlocked.side_effect

            async def ordered_hold_unlocked(device_id, location_id=None):
                order.append("hold_unlocked")
                return await original_hold_unlocked(
                    device_id, location_id=location_id
                )

            access.hold_unlocked.side_effect = ordered_hold_unlocked

            self.assertEqual(await mgr.poll_once(), 1)
            self.assertEqual(order, ["schedule", "hold_unlocked"])
            # The external unlock still propagates to Access as keep_unlock ...
            access.hold_unlocked.assert_awaited_once_with(
                "dev-hub-1", location_id="loc-1"
            )
            # ... and a durable ha_origin re-lock is scheduled exactly once.
            relock.schedule.assert_awaited_once()
            kwargs = relock.schedule.await_args.kwargs
            self.assertEqual(kwargs["entity_id"], "lock.front")
            self.assertEqual(kwargs["source"], "ha_origin")
            self.assertEqual(kwargs["duration"], 30.0)

            # The next converged poll observes both sides unlocked and does not
            # re-schedule for the same edge.
            await mgr.poll_once()
            relock.schedule.assert_awaited_once()
        _run(go())

    def test_schedule_failure_refuses_hold_open_and_compensates_locked(self) -> None:
        async def go():
            mgr, ha, access, relock, db, ha_states = self._fixture()
            await mgr.poll_once()
            ha_states["lock.front"] = "unlocked"
            _clear_damping(mgr)
            relock.schedule.side_effect = OSError("database unavailable")
            mgr._hard_reject_state["lock.front"] = ("legacy_rule_rejected", 3)
            mgr._backoff_until["lock.front"] = _time.monotonic() + 30

            self.assertEqual(await mgr.poll_once(), 1)

            access.hold_unlocked.assert_not_awaited()
            ha.lock.assert_awaited_once_with("lock.front")
            self.assertEqual(ha_states["lock.front"], "locked")
            self.assertEqual(mgr._last_converged["lock.front"], "locked")
        _run(go())

    def test_schedule_failure_retains_latch_when_compensation_fails(self) -> None:
        async def go():
            mgr, ha, access, relock, db, ha_states = self._fixture()
            await mgr.poll_once()
            ha_states["lock.front"] = "unlocked"
            _clear_damping(mgr)
            relock.schedule.side_effect = OSError("database unavailable")
            ha.lock = AsyncMock(return_value=False)

            self.assertEqual(await mgr.poll_once(), 0)

            access.hold_unlocked.assert_not_awaited()
            self.assertEqual(ha_states["lock.front"], "unlocked")
            self.assertIn("lock.front", mgr._fail_safe_reset_eids)
            self.assertNotEqual(
                mgr._last_converged.get("lock.front"), "unlocked"
            )
        _run(go())

    def test_manual_app_initiated_unlock_is_not_relocked(self) -> None:
        async def go():
            mgr, ha, access, relock, db, ha_states = self._fixture()
            await mgr.poll_once()
            # A manual dashboard Unlock marks the imminent edge app-initiated.
            mgr.mark_app_initiated_unlock("lock.front")
            ha_states["lock.front"] = "unlocked"
            _clear_damping(mgr)

            self.assertEqual(await mgr.poll_once(), 1)
            # Hold-open is preserved; no time-bound is imposed on the operator.
            access.hold_unlocked.assert_awaited_once()
            relock.schedule.assert_not_awaited()
        _run(go())

    def test_momentary_lease_suppresses_ha_origin_schedule(self) -> None:
        async def go():
            mgr, ha, access, relock, db, ha_states = self._fixture()
            await mgr.poll_once()
            # A buzz / device-auth / remote unlock leases the momentary hold.
            mgr.mark_access_momentary("lock.front", 30)
            ha_states["lock.front"] = "unlocked"
            _clear_damping(mgr)

            self.assertEqual(await mgr.poll_once(), 0)
            relock.schedule.assert_not_awaited()
        _run(go())

    def test_existing_pending_relock_is_not_double_scheduled(self) -> None:
        async def go():
            mgr, ha, access, relock, db, ha_states = self._fixture()
            # A buzz already owns a durable pending row for this entity.
            db.get_pending_relock = AsyncMock(
                return_value={"entity_id": "lock.front", "deadline": 123.0}
            )
            await mgr.poll_once()
            ha_states["lock.front"] = "unlocked"
            _clear_damping(mgr)

            self.assertEqual(await mgr.poll_once(), 1)
            relock.schedule.assert_not_awaited()
        _run(go())

    def test_toggle_off_preserves_todays_behavior(self) -> None:
        async def go():
            mgr, ha, access, relock, db, ha_states = self._fixture(
                ha_origin=False
            )
            await mgr.poll_once()
            ha_states["lock.front"] = "unlocked"
            _clear_damping(mgr)

            self.assertEqual(await mgr.poll_once(), 1)
            # Byte-for-byte today's behavior: keep_unlock, no re-lock timer.
            access.hold_unlocked.assert_awaited_once_with(
                "dev-hub-1", location_id="loc-1"
            )
            relock.schedule.assert_not_awaited()
        _run(go())


if __name__ == "__main__":
    unittest.main()
