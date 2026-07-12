"""Unit tests for HubSyncManager — opt-in mirroring of HA lock state to Access hubs."""
from __future__ import annotations

import asyncio
import importlib
import importlib.util
import sys
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
        side_effect=lambda loc: (location_map or {}).get(loc, [])
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


def _make_mgr(db, ha, access, on_hub_state=None) -> HubSyncManager:
    return HubSyncManager(
        db=db,
        ha_client_getter=lambda: ha,
        access_client_getter=lambda: access,
        on_hub_state=on_hub_state,
    )


def _run(coro):
    return asyncio.run(coro)


class TestBaselineAdoption(unittest.TestCase):
    def test_first_poll_adopts_state_without_driving_hub(self) -> None:
        async def go():
            states = {"lock.front": "locked"}
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            access = _make_access()
            mgr = _make_mgr(db, _make_ha(states), access)
            applied = await mgr.poll_once()
            self.assertEqual(applied, 0)
            access.lock.assert_not_awaited()
            access.unlock_persistent.assert_not_awaited()
        _run(go())

    def test_non_actionable_state_never_adopted_or_acted_on(self) -> None:
        async def go():
            states = {"lock.front": "unavailable"}
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            access = _make_access()
            mgr = _make_mgr(db, _make_ha(states), access)
            await mgr.poll_once()
            # Entity recovers directly into "unlocked" — that becomes the
            # baseline (first actionable observation), not a transition.
            states["lock.front"] = "unlocked"
            applied = await mgr.poll_once()
            self.assertEqual(applied, 0)
            access.unlock_persistent.assert_not_awaited()
        _run(go())


class TestTransitions(unittest.TestCase):
    def test_unlock_transition_holds_hub_open(self) -> None:
        async def go():
            states = {"lock.front": "locked"}
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            access = _make_access()
            cache: dict[str, str] = {}
            mgr = _make_mgr(
                db, _make_ha(states), access,
                on_hub_state=lambda dev, st: cache.__setitem__(dev, st),
            )
            await mgr.poll_once()  # adopt baseline: locked
            states["lock.front"] = "unlocked"
            applied = await mgr.poll_once()
            self.assertEqual(applied, 1)
            access.unlock_persistent.assert_awaited_once_with("dev-hub-1")
            access.lock.assert_not_awaited()
            self.assertEqual(cache, {"dev-hub-1": "unlocked"})
            db.log_access.assert_awaited_once()
        _run(go())

    def test_lock_transition_resets_hub(self) -> None:
        async def go():
            states = {"lock.front": "unlocked"}
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            access = _make_access()
            mgr = _make_mgr(db, _make_ha(states), access)
            await mgr.poll_once()  # adopt baseline: unlocked
            states["lock.front"] = "locked"
            applied = await mgr.poll_once()
            self.assertEqual(applied, 1)
            access.lock.assert_awaited_once_with("dev-hub-1")
            access.unlock_persistent.assert_not_awaited()
        _run(go())

    def test_steady_state_does_nothing(self) -> None:
        async def go():
            states = {"lock.front": "locked"}
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            access = _make_access()
            mgr = _make_mgr(db, _make_ha(states), access)
            await mgr.poll_once()
            await mgr.poll_once()
            await mgr.poll_once()
            access.lock.assert_not_awaited()
            access.unlock_persistent.assert_not_awaited()
        _run(go())

    def test_unavailable_blip_between_polls_does_not_trigger(self) -> None:
        async def go():
            states = {"lock.front": "locked"}
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            access = _make_access()
            mgr = _make_mgr(db, _make_ha(states), access)
            await mgr.poll_once()  # baseline: locked
            states["lock.front"] = "unavailable"
            await mgr.poll_once()  # ignored, baseline stays locked
            states["lock.front"] = "locked"
            applied = await mgr.poll_once()
            self.assertEqual(applied, 0)
            access.lock.assert_not_awaited()
        _run(go())


class TestOptIn(unittest.TestCase):
    def test_lock_without_option_is_ignored(self) -> None:
        async def go():
            plain = dict(HA_LOCK, sync_hub_state=0)
            states = {"lock.front": "locked"}
            ha = _make_ha(states)
            db = _make_db([plain, HUB], location_map={"loc-1": [HUB]})
            access = _make_access()
            mgr = _make_mgr(db, ha, access)
            await mgr.poll_once()
            states["lock.front"] = "unlocked"
            await mgr.poll_once()
            ha.get_entity_state.assert_not_awaited()
            access.unlock_persistent.assert_not_awaited()
        _run(go())

    def test_disabling_option_resets_baseline(self) -> None:
        async def go():
            states = {"lock.front": "locked"}
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            access = _make_access()
            mgr = _make_mgr(db, _make_ha(states), access)
            await mgr.poll_once()  # baseline: locked

            # Option turned off; state flips while sync is disabled
            db.get_all_locks = AsyncMock(
                return_value=[dict(HA_LOCK, sync_hub_state=0), HUB]
            )
            states["lock.front"] = "unlocked"
            await mgr.poll_once()

            # Option turned back on — the flip must NOT be replayed as a
            # transition; the current state is re-adopted as the baseline.
            db.get_all_locks = AsyncMock(return_value=[HA_LOCK, HUB])
            applied = await mgr.poll_once()
            self.assertEqual(applied, 0)
            access.unlock_persistent.assert_not_awaited()
        _run(go())


class TestPairing(unittest.TestCase):
    def test_pairing_via_entry_device_access_reader(self) -> None:
        async def go():
            ha_lock = dict(HA_LOCK, access_location_id=None)
            entry_devices = {
                2: [{"id": 9, "lock_id": 2, "type": "access_reader",
                     "device_id": "loc-1", "name": "Front Reader"}],
            }
            states = {"lock.front": "locked"}
            db = _make_db(
                [ha_lock, HUB],
                location_map={"loc-1": [HUB]},
                entry_devices=entry_devices,
            )
            access = _make_access()
            mgr = _make_mgr(db, _make_ha(states), access)
            await mgr.poll_once()
            states["lock.front"] = "unlocked"
            applied = await mgr.poll_once()
            self.assertEqual(applied, 1)
            access.unlock_persistent.assert_awaited_once_with("dev-hub-1")
        _run(go())

    def test_no_paired_hub_warns_but_advances_baseline(self) -> None:
        async def go():
            ha_lock = dict(HA_LOCK, access_location_id=None)
            states = {"lock.front": "locked"}
            db = _make_db([ha_lock], location_map={})
            access = _make_access()
            mgr = _make_mgr(db, _make_ha(states), access)
            await mgr.poll_once()
            states["lock.front"] = "unlocked"
            await mgr.poll_once()
            # Baseline advanced despite no hub — flipping back must not
            # queue up a phantom transition either.
            states["lock.front"] = "locked"
            await mgr.poll_once()
            access.lock.assert_not_awaited()
            access.unlock_persistent.assert_not_awaited()
        _run(go())


class TestFailureHandling(unittest.TestCase):
    def test_failed_drive_keeps_baseline_backs_off_and_notifies_once(self) -> None:
        async def go():
            states = {"lock.front": "locked"}
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            ha = _make_ha(states)
            access = _make_access()
            access.unlock_persistent = AsyncMock(side_effect=RuntimeError("boom"))
            mgr = _make_mgr(db, ha, access)
            await mgr.poll_once()  # baseline: locked
            states["lock.front"] = "unlocked"

            hs_module._APPLY_RETRY_DELAY = 0.0
            applied = await mgr.poll_once()
            self.assertEqual(applied, 0)
            # Both bounded retries were spent on the one transition
            self.assertEqual(access.unlock_persistent.await_count, 2)
            ha.fire_event.assert_awaited_once_with(
                "access_control_hub_sync_failed",
                {"entity_id": "lock.front", "lock_name": "Front Deadbolt"},
            )
            db.log_access.assert_not_awaited()

            # Within the backoff window nothing is retried
            await mgr.poll_once()
            self.assertEqual(access.unlock_persistent.await_count, 2)

            # After the backoff expires the transition is retried (baseline
            # was not advanced) and succeeds; no second failure event.
            mgr._backoff_until.clear()
            access.unlock_persistent = AsyncMock()
            applied = await mgr.poll_once()
            self.assertEqual(applied, 1)
            access.unlock_persistent.assert_awaited_once_with("dev-hub-1")
            self.assertEqual(ha.fire_event.await_count, 1)
        _run(go())

    def test_access_client_down_defers_transition(self) -> None:
        async def go():
            states = {"lock.front": "locked"}
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            access = _make_access(connected=False)
            mgr = _make_mgr(db, _make_ha(states), access)
            await mgr.poll_once()  # baseline: locked
            states["lock.front"] = "unlocked"
            applied = await mgr.poll_once()
            self.assertEqual(applied, 0)
            access.unlock_persistent.assert_not_awaited()

            # Access comes back — transition still pending, applied now
            access.connected = True
            mgr._backoff_until.clear()
            applied = await mgr.poll_once()
            self.assertEqual(applied, 1)
            access.unlock_persistent.assert_awaited_once_with("dev-hub-1")
        _run(go())

    def test_ha_disconnected_is_a_noop(self) -> None:
        async def go():
            db = _make_db([HA_LOCK, HUB], location_map={"loc-1": [HUB]})
            ha = _make_ha({"lock.front": "locked"})
            ha.connected = False
            mgr = _make_mgr(db, ha, _make_access())
            applied = await mgr.poll_once()
            self.assertEqual(applied, 0)
            db.get_all_locks.assert_not_awaited()
        _run(go())


if __name__ == "__main__":
    unittest.main()
