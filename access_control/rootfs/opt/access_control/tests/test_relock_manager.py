"""Unit tests for RelockManager — scheduling, cancellation, persistence, rehydration."""
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
rm_module = importlib.import_module("access_control.relock_manager")
RelockManager = rm_module.RelockManager


def _make_db() -> MagicMock:
    """Build a MagicMock DB with the methods RelockManager uses."""
    db = MagicMock()
    db.add_pending_relock = AsyncMock()
    db.remove_pending_relock = AsyncMock()
    db.remove_pending_relock_at_deadline = AsyncMock(return_value=1)
    db.get_pending_relocks = AsyncMock(return_value=[])
    return db


def _make_ha(ok: bool = True) -> MagicMock:
    ha = MagicMock()
    ha.lock = AsyncMock(return_value=ok)
    return ha


def _run(coro):
    return asyncio.run(coro)


class TestRelockManagerSchedule(unittest.TestCase):
    def test_schedule_persists_and_creates_task(self) -> None:
        async def go():
            db = _make_db()
            ha = _make_ha()
            mgr = RelockManager(db=db, ha_client_getter=lambda: ha)
            await mgr.schedule(
                entity_id="lock.foo", duration=10,
                lock_id=1, lock_name="Foo", source="buzz",
            )
            self.assertIn("lock.foo", mgr.tasks)
            self.assertEqual(db.add_pending_relock.await_count, 1)
            # Cancel before sleeping so the test exits quickly
            await mgr.cancel("lock.foo")
            self.assertNotIn("lock.foo", mgr.tasks)
            self.assertEqual(db.remove_pending_relock.await_count, 1)
        _run(go())

    def test_schedule_cancels_previous_task_for_same_entity(self) -> None:
        async def go():
            db = _make_db()
            ha = _make_ha()
            mgr = RelockManager(db=db, ha_client_getter=lambda: ha)
            await mgr.schedule(
                entity_id="lock.foo", duration=60,
                lock_id=1, lock_name="Foo", source="buzz",
            )
            first_task = mgr.tasks["lock.foo"]
            await mgr.schedule(
                entity_id="lock.foo", duration=60,
                lock_id=1, lock_name="Foo", source="device_auth",
            )
            second_task = mgr.tasks["lock.foo"]
            self.assertIsNot(first_task, second_task)
            await asyncio.sleep(0)  # let cancellation propagate
            self.assertTrue(first_task.cancelled() or first_task.done())
            await mgr.cancel("lock.foo")
        _run(go())


class TestRelockManagerFire(unittest.TestCase):
    def test_fire_calls_ha_lock_and_clears_db_and_invokes_callback(self) -> None:
        async def go():
            db = _make_db()
            ha = _make_ha(ok=True)
            seen: list[str] = []
            mgr = RelockManager(
                db=db,
                ha_client_getter=lambda: ha,
                on_locked=seen.append,
            )
            await mgr.schedule(
                entity_id="lock.foo", duration=0.05,
                lock_id=1, lock_name="Foo", source="buzz",
            )
            # Wait for the task to fire
            await asyncio.sleep(0.2)
            ha.lock.assert_awaited_with("lock.foo")
            # on_locked is fired by the post-fire cleanup (under the lock)
            # only after the "still active" check passes.
            self.assertEqual(seen, ["lock.foo"])
            self.assertGreaterEqual(db.remove_pending_relock.await_count, 1)
            self.assertNotIn("lock.foo", mgr.tasks)
        _run(go())

    def test_superseded_fire_does_not_invoke_callback(self) -> None:
        """If schedule() supersedes our task between ha.lock() and cleanup,
        on_locked must NOT fire — a concurrent manual unlock may have
        already set lock_states to unlocked."""
        async def go():
            db = _make_db()
            ha = MagicMock()
            seen: list[str] = []
            # Fake the supersession: after the first lock call, replace
            # the in-memory task slot so the post-fire "is current" check
            # fails. Achieved by having ha.lock take a small amount of
            # time and concurrently scheduling a replacement.
            async def slow_lock(entity_id):
                await asyncio.sleep(0.05)
                return True
            ha.lock = AsyncMock(side_effect=slow_lock)
            mgr = RelockManager(
                db=db,
                ha_client_getter=lambda: ha,
                on_locked=seen.append,
            )
            await mgr.schedule(
                entity_id="lock.foo", duration=0.01,
                lock_id=1, lock_name="Foo", source="device_auth",
            )
            # While the first task is inside ha.lock (50ms), supersede it
            await asyncio.sleep(0.02)
            await mgr.schedule(
                entity_id="lock.foo", duration=10,
                lock_id=1, lock_name="Foo", source="buzz",
            )
            # Wait for the original task to finish its cleanup
            await asyncio.sleep(0.1)
            # The replaced task should NOT have fired on_locked because
            # it was superseded
            self.assertEqual(seen, [])
            await mgr.cancel("lock.foo")
        _run(go())

    def test_fire_retries_then_succeeds(self) -> None:
        async def go():
            db = _make_db()
            ha = MagicMock()
            ha.lock = AsyncMock(side_effect=[False, True])
            mgr = RelockManager(db=db, ha_client_getter=lambda: ha)
            # Use 0 duration so the timer fires immediately, then patch the
            # retry delay constant to speed the test up.
            rm_module._LOCK_RETRY_DELAY = 0.01
            try:
                await mgr.schedule(
                    entity_id="lock.foo", duration=0.01,
                    lock_id=1, lock_name="Foo", source="device_auth",
                )
                await asyncio.sleep(0.2)
            finally:
                rm_module._LOCK_RETRY_DELAY = 1.5
            self.assertEqual(ha.lock.await_count, 2)
            # On success the DB row should be cleared
            self.assertGreaterEqual(db.remove_pending_relock.await_count, 1)
        _run(go())

    def test_fire_all_retries_fail_keeps_db_row(self) -> None:
        """Lock failed after all retries — DB row must stay so HA recovery can retry."""
        async def go():
            db = _make_db()
            ha = MagicMock()
            ha.lock = AsyncMock(return_value=False)
            mgr = RelockManager(db=db, ha_client_getter=lambda: ha)
            rm_module._LOCK_RETRY_DELAY = 0.01
            try:
                await mgr.schedule(
                    entity_id="lock.foo", duration=0.01,
                    lock_id=1, lock_name="Foo", source="device_auth",
                )
                await asyncio.sleep(0.2)
            finally:
                rm_module._LOCK_RETRY_DELAY = 1.5
            # Both retries failed
            self.assertEqual(ha.lock.await_count, 2)
            # Row must NOT be deleted by the failure path — preserved for recovery
            db.remove_pending_relock.assert_not_awaited()
            # Task is removed from the in-memory dict regardless
            self.assertNotIn("lock.foo", mgr.tasks)
        _run(go())


class TestRelockManagerRehydrate(unittest.TestCase):
    def test_past_due_fires_immediately_and_clears_row(self) -> None:
        async def go():
            db = _make_db()
            db.get_pending_relocks = AsyncMock(return_value=[
                {
                    "entity_id": "lock.foo",
                    "lock_id": 1,
                    "lock_name": "Foo",
                    "source": "buzz",
                    "deadline": 1.0,  # far in the past
                    "created_at": 0.0,
                },
            ])
            ha = _make_ha(ok=True)
            mgr = RelockManager(db=db, ha_client_getter=lambda: ha)
            await mgr.rehydrate()
            ha.lock.assert_awaited_with("lock.foo")
            # Deadline-conditional delete is used in the rehydrate past-due
            # path to avoid clobbering a row a concurrent schedule() may have
            # added with a different deadline while the HA call was in flight.
            db.remove_pending_relock_at_deadline.assert_awaited_with("lock.foo", 1.0)
            self.assertNotIn("lock.foo", mgr.tasks)
        _run(go())

    def test_past_due_lock_failure_keeps_row_for_retry(self) -> None:
        async def go():
            db = _make_db()
            db.get_pending_relocks = AsyncMock(return_value=[
                {
                    "entity_id": "lock.foo",
                    "lock_id": 1,
                    "lock_name": "Foo",
                    "source": "buzz",
                    "deadline": 1.0,
                    "created_at": 0.0,
                },
            ])
            ha = _make_ha(ok=False)  # HA still down
            mgr = RelockManager(db=db, ha_client_getter=lambda: ha)
            rm_module._LOCK_RETRY_DELAY = 0.01
            try:
                await mgr.rehydrate()
            finally:
                rm_module._LOCK_RETRY_DELAY = 1.5
            # Row must NOT be deleted — it's needed for the next rehydrate
            db.remove_pending_relock_at_deadline.assert_not_awaited()
            db.remove_pending_relock.assert_not_awaited()
        _run(go())

    def test_future_deadline_schedules_task(self) -> None:
        async def go():
            import time as _time
            db = _make_db()
            db.get_pending_relocks = AsyncMock(return_value=[
                {
                    "entity_id": "lock.foo",
                    "lock_id": 1,
                    "lock_name": "Foo",
                    "source": "buzz",
                    "deadline": _time.time() + 60,  # 60s in future
                    "created_at": _time.time(),
                },
            ])
            ha = _make_ha(ok=True)
            mgr = RelockManager(db=db, ha_client_getter=lambda: ha)
            await mgr.rehydrate()
            self.assertIn("lock.foo", mgr.tasks)
            self.assertFalse(ha.lock.await_count)  # not fired yet
            await mgr.cancel("lock.foo")
        _run(go())

    def test_rehydrate_cancels_existing_task_for_same_entity(self) -> None:
        async def go():
            import time as _time
            db = _make_db()
            ha = _make_ha(ok=True)
            mgr = RelockManager(db=db, ha_client_getter=lambda: ha)
            await mgr.schedule(
                entity_id="lock.foo", duration=60,
                lock_id=1, lock_name="Foo", source="buzz",
            )
            first_task = mgr.tasks["lock.foo"]
            db.get_pending_relocks = AsyncMock(return_value=[
                {
                    "entity_id": "lock.foo",
                    "lock_id": 1,
                    "lock_name": "Foo",
                    "source": "buzz",
                    "deadline": _time.time() + 60,
                    "created_at": _time.time(),
                },
            ])
            await mgr.rehydrate()
            await asyncio.sleep(0)
            self.assertTrue(first_task.cancelled() or first_task.done())
            await mgr.cancel("lock.foo")
        _run(go())


if __name__ == "__main__":
    unittest.main()
