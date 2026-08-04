"""Regression tests for sync write-churn fixes (e2e review 2026-07-12).

upsert_user must no-op when nothing changed (the 15-minute topology
resync previously rewrote every user row — with synced_at freshly
stamped — in its own committed transaction, forever), and both upserts
must support commit=False batching.

Also (review 2026-08-04): the hub-sync steady-state pass must not issue a
durable set_hub_sync_state write per entity per 5s poll when nothing the
row records has changed.
"""
from __future__ import annotations

import asyncio
import importlib
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))


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
db_module = importlib.import_module("access_control.database")
Database = db_module.Database
# Reuse the hub-sync test fixtures (mock DB / bidirectional HA + Access).
hub_fixtures = importlib.import_module("test_hub_sync")


def _run(coro):
    return asyncio.run(coro)


class TestUpsertUserSkipsUnchanged(unittest.TestCase):
    def test_unchanged_upsert_is_a_noop(self) -> None:
        async def go():
            db = Database(path=Path(tempfile.mkdtemp()) / "t.db")
            await db.connect()
            try:
                uid = await db.upsert_user(
                    ulp_id="u-1", name="Nick", email="n@x.com", status="active",
                )
                first = await db.get_user(uid)

                # Re-sync with identical data — synced_at must NOT move
                # (proves the row wasn't rewritten).
                uid2 = await db.upsert_user(
                    ulp_id="u-1", name="Nick", email="n@x.com", status="active",
                    synced_at="2099-01-01 00:00:00",
                )
                self.assertEqual(uid2, uid)
                unchanged = await db.get_user(uid)
                self.assertEqual(unchanged["synced_at"], first["synced_at"])

                # A real change still writes (and bumps synced_at).
                await db.upsert_user(
                    ulp_id="u-1", name="Nick S", email="n@x.com", status="active",
                    synced_at="2099-01-01 00:00:00",
                )
                changed = await db.get_user(uid)
                self.assertEqual(changed["name"], "Nick S")
                self.assertEqual(changed["synced_at"], "2099-01-01 00:00:00")
            finally:
                await db.close()
        _run(go())

    def test_batched_upserts_land_on_explicit_commit(self) -> None:
        async def go():
            db = Database(path=Path(tempfile.mkdtemp()) / "t.db")
            await db.connect()
            try:
                await db.upsert_user(
                    ulp_id="u-1", name="A", email=None, status="active",
                    commit=False,
                )
                lock_id = await db.upsert_native_lock(
                    device_id="dev-1", location_id="loc-1", name="Front",
                    commit=False,
                )
                await db.commit()

                user = await db.get_user_by_ulp_id("u-1")
                self.assertIsNotNone(user)
                lock = await db.get_lock(lock_id)
                self.assertEqual(lock["device_id"], "dev-1")
            finally:
                await db.close()
        _run(go())

    def test_rollback_discards_batch(self) -> None:
        async def go():
            db = Database(path=Path(tempfile.mkdtemp()) / "t.db")
            await db.connect()
            try:
                await db.upsert_user(
                    ulp_id="u-gone", name="X", email=None, status="active",
                    commit=False,
                )
                await db.rollback()
                self.assertIsNone(await db.get_user_by_ulp_id("u-gone"))
            finally:
                await db.close()
        _run(go())


class TestHubSyncConvergencePersistChurn(unittest.TestCase):
    """_persist_convergence must skip the durable write when desired state,
    access-rule fingerprint, and pairing signature are unchanged from the
    last successful persist — a converged pair previously cost one new
    SQLite connection + BEGIN IMMEDIATE + fsync per entity per 5s poll."""

    def test_steady_state_persists_once_until_something_changes(self) -> None:
        async def go():
            ha_states = {"lock.front": "locked"}
            rules = {"dev-hub-1": {"type": "reset"}}
            door_states = {"dev-hub-1": "locked"}
            db = hub_fixtures._make_db(
                [hub_fixtures.HA_LOCK, hub_fixtures.HUB],
                location_map={"loc-1": [hub_fixtures.HUB]},
            )
            db.get_hub_sync_states = AsyncMock(return_value=[])
            db.set_hub_sync_state = AsyncMock()
            ha = hub_fixtures._make_bidirectional_ha(ha_states)
            access = hub_fixtures._make_bidirectional_access(
                rules, door_states
            )
            mgr = hub_fixtures._make_mgr(db, ha, access)

            # Ten converged steady-state polls → exactly one durable write
            # (the first pass after startup).
            for _ in range(10):
                await mgr.poll_once()
            self.assertEqual(db.set_hub_sync_state.await_count, 1)

            # A genuine change still persists immediately...
            ha_states["lock.front"] = "unlocked"
            hub_fixtures._clear_damping(mgr)
            self.assertEqual(await mgr.poll_once(), 1)
            self.assertEqual(db.set_hub_sync_state.await_count, 2)

            # ...the next pass upgrades the self-command marker to the real
            # observed fingerprint (one more write), then the new steady
            # state is quiet again.
            for _ in range(5):
                await mgr.poll_once()
            self.assertEqual(db.set_hub_sync_state.await_count, 3)
        _run(go())

    def test_failed_persist_is_retried_on_the_next_pass(self) -> None:
        async def go():
            ha_states = {"lock.front": "locked"}
            rules = {"dev-hub-1": {"type": "reset"}}
            door_states = {"dev-hub-1": "locked"}
            db = hub_fixtures._make_db(
                [hub_fixtures.HA_LOCK, hub_fixtures.HUB],
                location_map={"loc-1": [hub_fixtures.HUB]},
            )
            db.get_hub_sync_states = AsyncMock(return_value=[])
            db.set_hub_sync_state = AsyncMock(
                side_effect=RuntimeError("db degraded")
            )
            ha = hub_fixtures._make_bidirectional_ha(ha_states)
            access = hub_fixtures._make_bidirectional_access(
                rules, door_states
            )
            mgr = hub_fixtures._make_mgr(db, ha, access)

            # The failed write must not be recorded as persisted...
            await mgr.poll_once()
            self.assertEqual(db.set_hub_sync_state.await_count, 1)
            self.assertEqual(mgr._last_persisted_convergence, {})

            # ...so the next pass retries it; once it lands, steady state is
            # deduplicated as usual.
            db.set_hub_sync_state = AsyncMock()
            await mgr.poll_once()
            self.assertEqual(db.set_hub_sync_state.await_count, 1)
            await mgr.poll_once()
            self.assertEqual(db.set_hub_sync_state.await_count, 1)
        _run(go())


if __name__ == "__main__":
    unittest.main()
