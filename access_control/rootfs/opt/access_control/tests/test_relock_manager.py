"""Unit tests for RelockManager — scheduling, cancellation, persistence, rehydration."""
from __future__ import annotations

import asyncio
import importlib
import importlib.util
import sys
import time as _time
import time
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
rm_module = importlib.import_module("access_control.relock_manager")
RelockManager = rm_module.RelockManager


def _make_db() -> MagicMock:
    """Build a MagicMock DB with the methods RelockManager uses."""
    db = MagicMock()
    pending: dict[str, dict] = {}

    async def add_pending_relock(**values):
        row = dict(values)
        created_at = row.pop("now", None)
        row["created_at"] = (
            float(created_at) if created_at is not None else _time.time()
        )
        pending[row["entity_id"]] = row

    async def remove_pending_relock(entity_id):
        pending.pop(entity_id, None)

    async def remove_at_deadline(entity_id, deadline):
        row = pending.get(entity_id)
        if row is None or float(row["deadline"]) != float(deadline):
            return 0
        del pending[entity_id]
        return 1

    async def get_pending_relock(entity_id):
        row = pending.get(entity_id)
        return dict(row) if row is not None else None

    async def get_pending_relocks():
        return [dict(row) for row in pending.values()]

    db._pending = pending
    db.add_pending_relock = AsyncMock(side_effect=add_pending_relock)
    db.remove_pending_relock = AsyncMock(side_effect=remove_pending_relock)
    db.remove_pending_relock_at_deadline = AsyncMock(side_effect=remove_at_deadline)
    db.get_pending_relock = AsyncMock(side_effect=get_pending_relock)
    db.get_pending_relocks = AsyncMock(side_effect=get_pending_relocks)
    return db


def _set_pending_rows(db: MagicMock, rows: list[dict]) -> None:
    db._pending.clear()
    db._pending.update({row["entity_id"]: dict(row) for row in rows})


def _make_ha(ok: bool = True) -> MagicMock:
    ha = MagicMock()
    ha.lock = AsyncMock(return_value=ok)
    ha.get_entity_state = AsyncMock(return_value="locked")
    ha.fire_event = AsyncMock(return_value=True)
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


class TestRelockManagerPreUnlockIntent(unittest.TestCase):
    def test_failed_unlock_restores_exact_prior_row_and_deadline(self) -> None:
        async def go():
            db = _make_db()
            ha = _make_ha()
            mgr = RelockManager(db=db, ha_client_getter=lambda: ha)
            await mgr.schedule(
                entity_id="lock.foo", duration=120,
                lock_id=7, lock_name="Original", source="device_auth",
            )
            prior_row = dict(db._pending["lock.foo"])
            prior_task = mgr.tasks["lock.foo"]

            intent = await mgr.schedule(
                entity_id="lock.foo", duration=240,
                lock_id=8, lock_name="Replacement", source="buzz",
            )
            replacement_task = mgr.tasks["lock.foo"]
            self.assertEqual(intent.previous_row, prior_row)
            self.assertIsNot(replacement_task, prior_task)
            self.assertNotEqual(
                db._pending["lock.foo"]["deadline"], prior_row["deadline"]
            )

            self.assertTrue(await mgr.restore_after_failed_unlock(intent))
            await asyncio.sleep(0)

            self.assertEqual(db._pending["lock.foo"], prior_row)
            self.assertTrue(replacement_task.done())
            restored_task = mgr.tasks["lock.foo"]
            self.assertIsNot(restored_task, replacement_task)
            self.assertIsNot(restored_task, prior_task)
            self.assertFalse(restored_task.done())
            await mgr.cancel("lock.foo")

        _run(go())

    def test_failed_unlock_removes_new_intent_without_prior_row(self) -> None:
        async def go():
            db = _make_db()
            ha = _make_ha()
            mgr = RelockManager(db=db, ha_client_getter=lambda: ha)
            intent = await mgr.schedule(
                entity_id="lock.foo", duration=120,
                lock_id=7, lock_name="Foo", source="buzz",
            )
            intent_task = mgr.tasks["lock.foo"]
            self.assertIsNone(intent.previous_row)

            self.assertTrue(await mgr.restore_after_failed_unlock(intent))
            await asyncio.sleep(0)

            self.assertNotIn("lock.foo", db._pending)
            self.assertNotIn("lock.foo", mgr.tasks)
            self.assertTrue(intent_task.done())
            db.remove_pending_relock_at_deadline.assert_awaited_once_with(
                "lock.foo", intent.deadline
            )

        _run(go())

    def test_schedule_db_failure_leaves_prior_live_timer(self) -> None:
        async def go():
            db = _make_db()
            ha = _make_ha()
            mgr = RelockManager(db=db, ha_client_getter=lambda: ha)
            await mgr.schedule(
                entity_id="lock.foo", duration=120,
                lock_id=7, lock_name="Foo", source="device_auth",
            )
            prior_row = dict(db._pending["lock.foo"])
            prior_task = mgr.tasks["lock.foo"]
            working_add = db.add_pending_relock.side_effect
            db.add_pending_relock = AsyncMock(
                side_effect=RuntimeError("sqlite unavailable")
            )

            with self.assertRaisesRegex(RuntimeError, "sqlite unavailable"):
                await mgr.schedule(
                    entity_id="lock.foo", duration=240,
                    lock_id=8, lock_name="Replacement", source="buzz",
                )

            self.assertEqual(db._pending["lock.foo"], prior_row)
            self.assertIs(mgr.tasks["lock.foo"], prior_task)
            self.assertFalse(prior_task.done())
            db.add_pending_relock = AsyncMock(side_effect=working_add)
            await mgr.cancel("lock.foo")

        _run(go())

    def test_late_rollback_cannot_clobber_concurrent_new_schedule(self) -> None:
        async def go():
            db = _make_db()
            ha = _make_ha()
            mgr = RelockManager(db=db, ha_client_getter=lambda: ha)
            stale_intent = await mgr.schedule(
                entity_id="lock.foo", duration=120,
                lock_id=7, lock_name="Pre-unlock", source="buzz",
            )

            base_add = db.add_pending_relock.side_effect
            replacement_started = asyncio.Event()
            release_replacement = asyncio.Event()

            async def delayed_add(**values):
                if values["source"] == "latest":
                    replacement_started.set()
                    await release_replacement.wait()
                return await base_add(**values)

            db.add_pending_relock = AsyncMock(side_effect=delayed_add)
            replacement = asyncio.create_task(
                mgr.schedule(
                    entity_id="lock.foo", duration=300,
                    lock_id=9, lock_name="Latest", source="latest",
                )
            )
            await replacement_started.wait()
            rollback = asyncio.create_task(
                mgr.restore_after_failed_unlock(stale_intent)
            )
            await asyncio.sleep(0)
            self.assertFalse(rollback.done())

            release_replacement.set()
            latest_intent = await replacement
            self.assertFalse(await rollback)
            self.assertEqual(
                db._pending["lock.foo"]["deadline"], latest_intent.deadline
            )
            self.assertIs(mgr.tasks["lock.foo"], latest_intent._task)
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
            self.assertGreaterEqual(
                db.remove_pending_relock_at_deadline.await_count, 1
            )
            self.assertNotIn("lock.foo", mgr.tasks)
        _run(go())

    def test_new_schedule_waits_for_inflight_lock_command(self) -> None:
        """A newer schedule linearizes after an in-flight physical lock."""
        async def go():
            db = _make_db()
            ha = MagicMock()
            ha.get_entity_state = AsyncMock(return_value="locked")
            seen: list[str] = []
            lock_started = asyncio.Event()

            async def slow_lock(entity_id):
                lock_started.set()
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
            await lock_started.wait()
            replacement = asyncio.create_task(
                mgr.schedule(
                    entity_id="lock.foo", duration=10,
                    lock_id=1, lock_name="Foo", source="buzz",
                )
            )
            await asyncio.sleep(0.01)
            self.assertFalse(replacement.done())
            await replacement
            # The replacement generation won before old cleanup, so the old
            # command must not overwrite the newer unlock's state cache.
            self.assertEqual(seen, [])
            self.assertIn("lock.foo", mgr.tasks)
            await mgr.cancel("lock.foo")
        _run(go())

    def test_fire_retries_then_succeeds(self) -> None:
        async def go():
            db = _make_db()
            ha = MagicMock()
            ha.lock = AsyncMock(side_effect=[False, True])
            ha.get_entity_state = AsyncMock(return_value="locked")
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
            self.assertGreaterEqual(
                db.remove_pending_relock_at_deadline.await_count, 1
            )
        _run(go())

    def test_fire_all_retries_fail_keeps_db_row(self) -> None:
        """Lock failed after all retries — DB row must stay so HA recovery can retry."""
        async def go():
            db = _make_db()
            ha = MagicMock()
            ha.lock = AsyncMock(return_value=False)
            ha.get_entity_state = AsyncMock(return_value="locked")
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


class TestRelockManagerCommandBarrier(unittest.TestCase):
    def test_timer_waits_for_shared_command_barrier(self) -> None:
        async def go():
            db = _make_db()
            ha = _make_ha(ok=True)
            barrier = asyncio.Lock()
            mgr = RelockManager(
                db=db,
                ha_client_getter=lambda: ha,
                command_lock=barrier,
            )

            await barrier.acquire()
            await mgr.schedule(
                entity_id="lock.foo", duration=0.01,
                lock_id=1, lock_name="Foo", source="buzz",
            )
            await asyncio.sleep(0.05)
            ha.lock.assert_not_awaited()
            self.assertIn("lock.foo", mgr.tasks)

            barrier.release()
            await asyncio.sleep(0.1)
            ha.lock.assert_awaited_once_with("lock.foo")

        _run(go())

    def test_rehydrate_waits_for_shared_command_barrier(self) -> None:
        async def go():
            db = _make_db()
            _set_pending_rows(db, [{
                "entity_id": "lock.foo",
                "lock_name": "Foo",
                "deadline": time.time() - 10,
            }])
            ha = _make_ha(ok=True)
            barrier = asyncio.Lock()
            mgr = RelockManager(
                db=db,
                ha_client_getter=lambda: ha,
                command_lock=barrier,
            )

            await barrier.acquire()
            recovery = asyncio.create_task(mgr.rehydrate())
            await asyncio.sleep(0.02)
            ha.lock.assert_not_awaited()
            self.assertFalse(recovery.done())

            barrier.release()
            await recovery
            ha.lock.assert_awaited_once_with("lock.foo")

        _run(go())

    def test_sweep_waits_for_shared_command_barrier(self) -> None:
        async def go():
            db = _make_db()
            _set_pending_rows(db, [{
                "entity_id": "lock.foo",
                "lock_name": "Foo",
                "deadline": time.time() - 10,
            }])
            ha = _make_ha(ok=True)
            barrier = asyncio.Lock()
            mgr = RelockManager(
                db=db,
                ha_client_getter=lambda: ha,
                command_lock=barrier,
            )

            await barrier.acquire()
            sweep = asyncio.create_task(mgr.sweep_overdue())
            await asyncio.sleep(0.02)
            ha.lock.assert_not_awaited()
            self.assertFalse(sweep.done())

            barrier.release()
            self.assertEqual(await sweep, 1)
            ha.lock.assert_awaited_once_with("lock.foo")

        _run(go())


class TestRelockManagerRehydrate(unittest.TestCase):
    def test_past_due_fires_immediately_and_clears_row(self) -> None:
        async def go():
            db = _make_db()
            _set_pending_rows(db, [
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
            _set_pending_rows(db, [
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
            db = _make_db()
            _set_pending_rows(db, [
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

    def test_rehydrate_keeps_existing_task_for_same_deadline(self) -> None:
        async def go():
            db = _make_db()
            ha = _make_ha(ok=True)
            mgr = RelockManager(db=db, ha_client_getter=lambda: ha)
            await mgr.schedule(
                entity_id="lock.foo", duration=60,
                lock_id=1, lock_name="Foo", source="buzz",
            )
            first_task = mgr.tasks["lock.foo"]
            row = dict(db._pending["lock.foo"])
            await mgr.rehydrate()
            await asyncio.sleep(0)
            self.assertIs(mgr.tasks["lock.foo"], first_task)
            self.assertFalse(first_task.done())
            self.assertEqual(float(row["deadline"]), float(db._pending["lock.foo"]["deadline"]))
            await mgr.cancel("lock.foo")
        _run(go())


class TestRelockManagerSweepOverdue(unittest.TestCase):
    """Regression (2026-07-05): a failed relock must be retried while HA stays
    connected — not only on a reconnect transition — or a door stays unlocked
    until the next restart."""

    def test_sweep_locks_past_due_row_with_no_task(self) -> None:
        async def go():
            db = _make_db()
            _set_pending_rows(db, [
                {"entity_id": "lock.foo", "lock_name": "Foo",
                 "deadline": time.time() - 100},
            ])
            ha = _make_ha(ok=True)
            seen: list[str] = []
            mgr = RelockManager(db=db, ha_client_getter=lambda: ha,
                                on_locked=seen.append)
            swept = await mgr.sweep_overdue()
            self.assertEqual(swept, 1)
            ha.lock.assert_awaited_once_with("lock.foo")
            db.remove_pending_relock_at_deadline.assert_awaited_once()
            self.assertEqual(seen, ["lock.foo"])
        _run(go())

    def test_sweep_skips_future_dated_rows(self) -> None:
        async def go():
            db = _make_db()
            _set_pending_rows(db, [
                {"entity_id": "lock.bar", "lock_name": "Bar",
                 "deadline": time.time() + 100},
            ])
            ha = _make_ha(ok=True)
            mgr = RelockManager(db=db, ha_client_getter=lambda: ha)
            swept = await mgr.sweep_overdue()
            self.assertEqual(swept, 0)
            ha.lock.assert_not_awaited()
        _run(go())

    def test_sweep_skips_entity_with_live_task(self) -> None:
        async def go():
            db = _make_db()
            ha = _make_ha(ok=True)
            mgr = RelockManager(db=db, ha_client_getter=lambda: ha)
            # A live scheduled task owns lock.foo (fires in 60s)
            await mgr.schedule(entity_id="lock.foo", duration=60,
                               lock_id=1, lock_name="Foo", source="buzz")
            # A past-due DB row for the same entity must be left to the task
            # Keep the durable row aligned with the live task. A stale
            # snapshot for the same entity must not replace/fire it.
            db.get_pending_relocks = AsyncMock(return_value=[{
                "entity_id": "lock.foo", "lock_name": "Foo",
                "deadline": time.time() - 100,
            }])
            swept = await mgr.sweep_overdue()
            self.assertEqual(swept, 0)
            ha.lock.assert_not_awaited()
            await mgr.cancel("lock.foo")
        _run(go())


class TestRelockManagerRecoveryConcurrency(unittest.TestCase):
    def test_rehydrate_snapshot_cannot_override_new_schedule(self) -> None:
        async def go():
            db = _make_db()
            old_row = {
                "entity_id": "lock.foo",
                "lock_name": "Foo",
                "deadline": time.time() - 100,
            }
            _set_pending_rows(db, [old_row])
            snapshot_taken = asyncio.Event()
            release_snapshot = asyncio.Event()

            async def delayed_snapshot():
                snapshot_taken.set()
                await release_snapshot.wait()
                return [dict(old_row)]

            db.get_pending_relocks = AsyncMock(side_effect=delayed_snapshot)
            ha = _make_ha(ok=True)
            mgr = RelockManager(db=db, ha_client_getter=lambda: ha)

            recovery = asyncio.create_task(mgr.rehydrate())
            await snapshot_taken.wait()
            await mgr.schedule(
                entity_id="lock.foo",
                duration=60,
                lock_id=1,
                lock_name="Foo",
                source="buzz",
            )
            fresh_task = mgr.tasks["lock.foo"]
            fresh_deadline = db._pending["lock.foo"]["deadline"]
            release_snapshot.set()
            await recovery

            ha.lock.assert_not_awaited()
            self.assertIs(mgr.tasks["lock.foo"], fresh_task)
            self.assertEqual(db._pending["lock.foo"]["deadline"], fresh_deadline)
            await mgr.cancel("lock.foo")

        _run(go())

    def test_sweep_snapshot_cannot_lock_after_new_schedule(self) -> None:
        async def go():
            db = _make_db()
            old_row = {
                "entity_id": "lock.foo",
                "lock_name": "Foo",
                "deadline": time.time() - 100,
            }
            _set_pending_rows(db, [old_row])
            snapshot_taken = asyncio.Event()
            release_snapshot = asyncio.Event()

            async def delayed_snapshot():
                snapshot_taken.set()
                await release_snapshot.wait()
                return [dict(old_row)]

            db.get_pending_relocks = AsyncMock(side_effect=delayed_snapshot)
            ha = _make_ha(ok=True)
            mgr = RelockManager(db=db, ha_client_getter=lambda: ha)

            sweep = asyncio.create_task(mgr.sweep_overdue())
            await snapshot_taken.wait()
            await mgr.schedule(
                entity_id="lock.foo",
                duration=60,
                lock_id=1,
                lock_name="Foo",
                source="device_auth",
            )
            release_snapshot.set()
            self.assertEqual(await sweep, 0)

            ha.lock.assert_not_awaited()
            self.assertIn("lock.foo", mgr.tasks)
            await mgr.cancel("lock.foo")

        _run(go())

    def test_pause_waits_for_inflight_recovery_before_new_unlock(self) -> None:
        async def go():
            db = _make_db()
            row = {
                "entity_id": "lock.foo",
                "lock_name": "Foo",
                "deadline": time.time() - 100,
            }
            _set_pending_rows(db, [row])
            lock_started = asyncio.Event()
            release_lock = asyncio.Event()
            ha = _make_ha()

            async def slow_lock(entity_id):
                lock_started.set()
                await release_lock.wait()
                return True

            ha.lock = AsyncMock(side_effect=slow_lock)
            mgr = RelockManager(db=db, ha_client_getter=lambda: ha)

            sweep = asyncio.create_task(mgr.sweep_overdue())
            await lock_started.wait()
            pause = asyncio.create_task(mgr.pause("lock.foo"))
            await asyncio.sleep(0.01)
            self.assertFalse(pause.done())

            release_lock.set()
            # The physical request releases its locks before confirmation and
            # retry sleeps. A queued manual operation may therefore win the
            # generation before cleanup; the durable row stays paused/safe.
            self.assertEqual(await sweep, 0)
            self.assertIsNotNone(await pause)
            ha.lock.assert_awaited_once_with("lock.foo")

        _run(go())

    def test_pause_prevents_stale_snapshot_lock_after_manual_unlock(self) -> None:
        async def go():
            db = _make_db()
            old_row = {
                "entity_id": "lock.foo",
                "lock_name": "Foo",
                "deadline": time.time() - 100,
            }
            _set_pending_rows(db, [old_row])
            snapshot_taken = asyncio.Event()
            release_snapshot = asyncio.Event()

            async def delayed_snapshot():
                snapshot_taken.set()
                await release_snapshot.wait()
                return [dict(old_row)]

            db.get_pending_relocks = AsyncMock(side_effect=delayed_snapshot)
            ha = _make_ha(ok=True)
            mgr = RelockManager(db=db, ha_client_getter=lambda: ha)

            sweep = asyncio.create_task(mgr.sweep_overdue())
            await snapshot_taken.wait()

            # A manual command reserves the entity before physically
            # unlocking it. Recovery may hold an old snapshot, but cannot
            # act while the reservation is paused.
            paused_row = await mgr.pause("lock.foo")
            self.assertIsNotNone(paused_row)
            release_snapshot.set()
            self.assertEqual(await sweep, 0)
            ha.lock.assert_not_awaited()

            # Successful unlock replaces the old deadline and releases the
            # pause in one operation.
            await mgr.schedule(
                entity_id="lock.foo",
                duration=60,
                lock_id=1,
                lock_name="Foo",
                source="buzz",
            )
            self.assertIn("lock.foo", mgr.tasks)
            await mgr.cancel("lock.foo")

        _run(go())


class TestRelockManagerShutdown(unittest.TestCase):
    def test_shutdown_cancels_timers_but_preserves_rows(self) -> None:
        async def go():
            db = _make_db()
            ha = _make_ha()
            mgr = RelockManager(db=db, ha_client_getter=lambda: ha)
            await mgr.schedule(
                entity_id="lock.one", duration=60, lock_id=1,
                lock_name="One", source="buzz",
            )
            await mgr.schedule(
                entity_id="lock.two", duration=60, lock_id=2,
                lock_name="Two", source="device_auth",
            )
            live_tasks = list(mgr.tasks.values())
            durable_deadlines = {
                entity_id: row["deadline"]
                for entity_id, row in db._pending.items()
            }

            await mgr.shutdown()
            await mgr.shutdown()  # idempotent

            self.assertEqual(mgr.tasks, {})
            self.assertTrue(all(task.done() for task in live_tasks))
            self.assertEqual(
                {
                    entity_id: row["deadline"]
                    for entity_id, row in db._pending.items()
                },
                durable_deadlines,
            )
            db.remove_pending_relock.assert_not_awaited()
            db.remove_pending_relock_at_deadline.assert_not_awaited()
            ha.lock.assert_not_awaited()
            with self.assertRaises(RuntimeError):
                await mgr.schedule(
                    entity_id="lock.three", duration=60, lock_id=3,
                    lock_name="Three", source="buzz",
                )

        _run(go())


class TestRelockManagerFailureEvent(unittest.TestCase):
    """Regression: a relock that exhausts its retries must fire an HA event so
    automations can alert on a door that failed to re-lock."""

    def test_failed_relock_fires_ha_event(self) -> None:
        async def go():
            db = _make_db()
            ha = _make_ha(ok=False)
            mgr = RelockManager(db=db, ha_client_getter=lambda: ha)
            rm_module._LOCK_RETRY_DELAY = 0.01
            try:
                await mgr.schedule(entity_id="lock.foo", duration=0.01,
                                   lock_id=1, lock_name="Foo", source="buzz")
                await asyncio.sleep(0.2)
            finally:
                rm_module._LOCK_RETRY_DELAY = 1.5
            ha.fire_event.assert_awaited_once()
            event_type = ha.fire_event.await_args.args[0]
            self.assertEqual(event_type, "access_control_relock_failed")
            # Row retained for the sweep to retry
            db.remove_pending_relock.assert_not_awaited()
        _run(go())


class TestRelockMonotonicBound(unittest.TestCase):
    """Change 2: a live timer fires at whichever of the wall-clock deadline and
    the schedule-time monotonic bound arrives first, so a backward clock jump
    can shorten but never extend an open-door window."""

    def _capture_wait(
        self, *, sched_time, sched_mono, wait_time, wait_mono, duration=100.0
    ):
        # Patching relock_manager.asyncio.sleep patches the shared asyncio
        # module globally, so yield with a real-sleep reference captured before
        # the patch — otherwise the test's own yields would pollute ``sleeps``.
        real_sleep = asyncio.sleep
        sleeps: list[float] = []

        async def fake_sleep(delay):
            sleeps.append(delay)

        async def go():
            db = _make_db()
            ha = _make_ha(ok=True)
            mgr = RelockManager(db=db, ha_client_getter=lambda: ha)
            fake_time = MagicMock()
            fake_time.time.return_value = sched_time
            fake_time.monotonic.return_value = sched_mono
            with patch("access_control.relock_manager.time", fake_time), patch(
                "access_control.relock_manager.asyncio.sleep", new=fake_sleep
            ):
                await mgr.schedule(
                    entity_id="lock.foo", duration=duration,
                    lock_id=1, lock_name="Foo", source="buzz",
                )
                fake_time.time.return_value = wait_time
                fake_time.monotonic.return_value = wait_mono
                for _ in range(5):
                    await real_sleep(0)
            await mgr.cancel("lock.foo")
        _run(go())
        return sleeps

    def test_backward_clock_jump_does_not_extend_window(self) -> None:
        # deadline=1100, monotonic bound=5100. Wall clock jumped back 500s.
        sleeps = self._capture_wait(
            sched_time=1000.0, sched_mono=5000.0,
            wait_time=500.0, wait_mono=5001.0,
        )
        # wall_remaining=600, mono_remaining=99 → bounded to 99, not 600.
        self.assertAlmostEqual(sleeps[0], 99.0, places=5)

    def test_forward_clock_jump_fires_early_via_wall_deadline(self) -> None:
        # deadline=1100, monotonic bound=5100. Wall clock jumped forward 90s.
        sleeps = self._capture_wait(
            sched_time=1000.0, sched_mono=5000.0,
            wait_time=1090.0, wait_mono=5001.0,
        )
        # wall_remaining=10, mono_remaining=99 → wall deadline wins.
        self.assertAlmostEqual(sleeps[0], 10.0, places=5)

    def test_rehydrated_row_uses_pure_wall_clock(self) -> None:
        # Rehydrate has no monotonic context; the wait is pure wall-clock even
        # though the module's monotonic clock is far from the deadline.
        real_sleep = asyncio.sleep
        sleeps: list[float] = []

        async def fake_sleep(delay):
            sleeps.append(delay)

        async def go():
            db = _make_db()
            ha = _make_ha(ok=True)
            mgr = RelockManager(db=db, ha_client_getter=lambda: ha)
            _set_pending_rows(db, [{
                "entity_id": "lock.foo", "lock_id": 1, "lock_name": "Foo",
                "source": "buzz", "deadline": 1050.0, "created_at": 900.0,
            }])
            fake_time = MagicMock()
            fake_time.time.return_value = 1000.0
            fake_time.monotonic.return_value = 5000.0
            with patch("access_control.relock_manager.time", fake_time), patch(
                "access_control.relock_manager.asyncio.sleep", new=fake_sleep
            ):
                await mgr.rehydrate()
                for _ in range(5):
                    await real_sleep(0)
            await mgr.cancel("lock.foo")
        _run(go())
        # remaining = 1050 - 1000 = 50, no monotonic bound applied.
        self.assertAlmostEqual(sleeps[0], 50.0, places=5)


class TestPendingRelockStatus(unittest.TestCase):
    """Change 3(b): status map drives health counts and the locks-page badge."""

    def test_status_maps_each_entity_to_overdue_flag(self) -> None:
        async def go():
            db = _make_db()
            ha = _make_ha()
            mgr = RelockManager(db=db, ha_client_getter=lambda: ha)
            now = _time.time()
            _set_pending_rows(db, [
                {"entity_id": "lock.a", "deadline": now - 5,
                 "lock_name": "A", "source": "buzz", "created_at": now},
                {"entity_id": "lock.b", "deadline": now + 500,
                 "lock_name": "B", "source": "buzz", "created_at": now},
            ])
            status = await mgr.pending_relock_status()
            self.assertEqual(status, {"lock.a": True, "lock.b": False})
        _run(go())


class TestRelockOverdueRenotify(unittest.TestCase):
    """Change 3(a): a stuck overdue relock re-fires its failure event on a
    bounded per-entity cadence, and clears on success."""

    def _overdue_db(self) -> MagicMock:
        db = _make_db()
        now = _time.time()
        _set_pending_rows(db, [{
            "entity_id": "lock.foo", "lock_id": 1, "lock_name": "Foo",
            "source": "buzz", "deadline": now - 100, "created_at": now - 100,
        }])
        return db

    def test_overdue_sweep_refires_on_bounded_cadence(self) -> None:
        async def go():
            db = self._overdue_db()
            ha = _make_ha(ok=False)  # HA lock keeps failing
            mgr = RelockManager(db=db, ha_client_getter=lambda: ha)
            with patch(
                "access_control.relock_manager.asyncio.sleep", new=AsyncMock()
            ):
                await mgr.sweep_overdue()
                self.assertEqual(ha.fire_event.await_count, 1)
                # Immediate re-sweep stays silent inside the cadence window.
                await mgr.sweep_overdue()
                self.assertEqual(ha.fire_event.await_count, 1)
                # Past the window it re-fires so the stuck door stays visible.
                mgr._overdue_notified_at["lock.foo"] = (
                    _time.monotonic()
                    - rm_module._RELOCK_RENOTIFY_INTERVAL
                    - 1
                )
                await mgr.sweep_overdue()
                self.assertEqual(ha.fire_event.await_count, 2)
        _run(go())

    def test_success_clears_renotify_state(self) -> None:
        async def go():
            db = self._overdue_db()
            ha = _make_ha(ok=False)
            mgr = RelockManager(db=db, ha_client_getter=lambda: ha)
            with patch(
                "access_control.relock_manager.asyncio.sleep", new=AsyncMock()
            ):
                await mgr.sweep_overdue()
                self.assertIn("lock.foo", mgr._overdue_notified_at)
                # HA recovers; the overdue row locks and the cadence resets.
                ha.lock = AsyncMock(return_value=True)
                await mgr.sweep_overdue()
            self.assertNotIn("lock.foo", mgr._overdue_notified_at)
        _run(go())


if __name__ == "__main__":
    unittest.main()
