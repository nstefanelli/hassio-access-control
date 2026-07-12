"""
Relock manager — centralises auto-relock scheduling across all three sources
(buzz button, remote unlock, device-auth unlock) and persists pending relocks
to the database so they survive a service restart.

Used by main.py to rehydrate pending relocks on startup, by web_routes.py
for buzz unlocks, by main.py for remote-unlock relocks, and by auth_engine.py
for device-auth relocks.

Concurrency model
-----------------
The manager lock serialises mutation of ``_tasks`` and durable rows.  A
per-entity operation lock additionally orders physical HA commands against
schedule/cancel/pause/recovery for that same lock without making an offline
door stall unrelated doors.  Every recovery re-reads the durable row after
acquiring that operation lock; a stale snapshot can therefore neither
overwrite a newer timer nor issue a lock command after a newer schedule.
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Optional

from .database import Database

_LOGGER = logging.getLogger(__name__)

# Retry attempts for the actual HA lock call when relock fires
_LOCK_RETRIES = 2
_LOCK_RETRY_DELAY = 1.5
_CONFIRM_ATTEMPTS = 3
_CONFIRM_DELAY = 0.25


@dataclass(frozen=True)
class RelockIntent:
    """Opaque rollback token returned when a relock is scheduled.

    Callers that durably schedule a relock *before* issuing an HA unlock keep
    this token until the command succeeds. Ambiguous network failure uses
    :meth:`RelockManager.retain_after_uncertain_unlock` so the earliest safety
    deadline survives. The exact-restore method remains available only when a
    caller can prove the physical unlock did not execute. The owning task is a
    generation token that prevents late recovery from clobbering a newer row.
    """

    entity_id: str
    deadline: float
    previous_row: dict | None
    _task: asyncio.Task = field(repr=False, compare=False)


class RelockManager:
    """
    Schedules auto-relock tasks for HA-external locks, persisting each
    pending relock so it survives a service restart.

    All three relock sources (buzz, remote_unlock, device_auth) flow
    through :meth:`schedule`. The manager keeps an in-memory dict of
    active asyncio.Tasks keyed by entity_id, and a parallel row in the
    ``pending_relocks`` table keyed by the same.
    """

    def __init__(
        self,
        db: Database,
        ha_client_getter,
        on_locked=None,
        command_lock: asyncio.Lock | None = None,
    ) -> None:
        # ha_client_getter is a zero-arg callable returning the *current*
        # HAClient — needed because the client can be replaced via Settings.
        # on_locked is an optional callback(entity_id) invoked after the
        # lock command succeeds — used to refresh the in-memory state cache.
        self._db = db
        self._get_ha = ha_client_getter
        self._on_locked = on_locked
        # Shared with manual unlocks and lockdown transitions. Physical HA
        # lock calls take this barrier before their per-entity lock so a
        # command already in flight has a single, deadlock-free ordering.
        self._command_lock = command_lock
        self._tasks: dict[str, asyncio.Task] = {}
        self._lock: asyncio.Lock = asyncio.Lock()
        self._entity_locks: dict[str, asyncio.Lock] = {}
        # A paused entity is inside a manual HA command. Recovery skips it
        # until the caller resolves the pause via schedule/cancel/resume.
        self._paused: set[str] = set()
        self._shutting_down = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def tasks(self) -> dict[str, asyncio.Task]:
        """Expose the live task dict for read-only inspection (do not mutate)."""
        return self._tasks

    async def schedule(
        self,
        *,
        entity_id: str,
        duration: float,
        lock_id: Optional[int],
        lock_name: str,
        source: str,
    ) -> RelockIntent:
        """
        Schedule a relock for ``entity_id`` after ``duration`` seconds.

        Cancels any pending relock for the same entity, persists the new
        deadline, and starts a background task that calls ``ha_client.lock()``
        when the timer fires (with bounded retries on failure).

        The returned :class:`RelockIntent` is normally ignored. A caller that
        is scheduling before an HA unlock keeps it and calls
        :meth:`retain_after_uncertain_unlock` if that physical command has an
        ambiguous failure.
        Persistence happens before the prior task is cancelled, so a database
        failure leaves the previous safety timer live.
        """
        operation_lock = self._entity_lock(entity_id)
        async with operation_lock:
            async with self._lock:
                if self._shutting_down:
                    raise RuntimeError("RelockManager is shutting down")
                deadline = time.time() + duration
                previous_row = await self._db.get_pending_relock(entity_id)
                # Persist first. If SQLite fails, the existing safety timer
                # remains live instead of being cancelled with no replacement.
                await self._db.add_pending_relock(
                    entity_id=entity_id,
                    lock_id=lock_id,
                    lock_name=lock_name,
                    source=source,
                    deadline=deadline,
                )
                self._cancel_locked(entity_id)
                self._paused.discard(entity_id)
                _LOGGER.info(
                    "Re-lock scheduled (%s): %s in %.0fs",
                    source,
                    lock_name,
                    duration,
                )
                task = asyncio.create_task(
                    self._wait_and_lock(entity_id, lock_name, deadline),
                    name=f"relock-{source}-{entity_id}",
                )
                self._tasks[entity_id] = task
                return RelockIntent(
                    entity_id=entity_id,
                    deadline=deadline,
                    previous_row=(
                        dict(previous_row) if previous_row is not None else None
                    ),
                    _task=task,
                )

    async def restore_after_failed_unlock(self, intent: RelockIntent) -> bool:
        """Roll back a pre-unlock relock schedule atomically.

        ``intent`` must be the value returned by the schedule performed before
        the failed HA unlock. If that intent still owns the entity, this method
        first restores its exact predecessor row (including the original
        deadline and creation timestamp), or conditionally deletes the new row
        when no predecessor existed. Only after that durable mutation succeeds
        is the new task cancelled. A restored predecessor is then re-armed at
        its original deadline, unless shutdown is in progress.

        Returns ``True`` when the rollback was applied. Returns ``False`` when
        a newer schedule already superseded the token, so the newer timer wins.
        A database exception is propagated while the current intent remains
        live and durable.
        """
        entity_id = intent.entity_id
        operation_lock = self._entity_lock(entity_id)
        async with operation_lock:
            async with self._lock:
                current = await self._db.get_pending_relock(entity_id)
                if (
                    current is None
                    or float(current["deadline"]) != float(intent.deadline)
                ):
                    return False

                live_task = self._tasks.get(entity_id)
                if live_task is not intent._task:
                    # During shutdown the task map is intentionally empty but
                    # schedules are frozen, so the matching durable deadline
                    # is still sufficient to complete the rollback safely.
                    if not (self._shutting_down and live_task is None):
                        return False

                previous = intent.previous_row
                if previous is None:
                    removed = await self._db.remove_pending_relock_at_deadline(
                        entity_id, intent.deadline
                    )
                    if not removed:
                        return False
                else:
                    # add_pending_relock is an upsert. Supplying created_at via
                    # ``now`` restores the prior row byte-for-field rather than
                    # silently making an old intent look newly created.
                    await self._db.add_pending_relock(
                        entity_id=previous["entity_id"],
                        lock_id=previous.get("lock_id"),
                        lock_name=previous.get("lock_name"),
                        source=previous["source"],
                        deadline=float(previous["deadline"]),
                        now=previous.get("created_at"),
                    )

                self._cancel_locked(entity_id)
                self._paused.discard(entity_id)

                if previous is not None and not self._shutting_down:
                    old_deadline = float(previous["deadline"])
                    old_name = previous.get("lock_name") or entity_id
                    task = asyncio.create_task(
                        self._wait_and_lock(entity_id, old_name, old_deadline),
                        name=f"relock-restore-{entity_id}",
                    )
                    self._tasks[entity_id] = task
                    _LOGGER.warning(
                        "Restored prior pending re-lock for %s after unlock failed",
                        old_name,
                    )
                return True

    async def retain_after_uncertain_unlock(self, intent: RelockIntent) -> bool:
        """Keep the earliest durable relock after an ambiguous unlock result.

        A timeout, transport error, or generic ``False`` cannot prove that HA
        rejected the service call; the request may have reached HA before the
        response was lost. Never delete the new write-ahead intent in that
        window. If it replaced an even earlier predecessor, restore that
        predecessor instead. The extra future lock call is harmless when HA
        definitively did not unlock and essential when it did.
        """
        previous = intent.previous_row
        if previous is None:
            current = await self._db.get_pending_relock(intent.entity_id)
            return bool(
                current is not None
                and float(current["deadline"]) == float(intent.deadline)
            )
        if float(previous["deadline"]) <= float(intent.deadline):
            return await self.restore_after_failed_unlock(intent)
        current = await self._db.get_pending_relock(intent.entity_id)
        return bool(
            current is not None
            and float(current["deadline"]) == float(intent.deadline)
        )

    async def extend_after_success(
        self, intent: RelockIntent, duration: float
    ) -> bool:
        """Move an owned intent to ``success time + duration`` with CAS.

        The early write-ahead deadline remains live until the database update
        commits. If persistence or ownership validation fails, it is retained
        as the safer fallback rather than cancelling the only timer.
        """
        entity_id = intent.entity_id
        operation_lock = self._entity_lock(entity_id)
        async with operation_lock:
            async with self._lock:
                if self._shutting_down:
                    return False
                current = await self._db.get_pending_relock(entity_id)
                if (
                    current is None
                    or float(current["deadline"]) != float(intent.deadline)
                    or self._tasks.get(entity_id) is not intent._task
                ):
                    return False
                new_deadline = time.time() + duration
                changed = await self._db.replace_pending_relock_deadline(
                    entity_id, intent.deadline, new_deadline
                )
                if not changed:
                    return False
                self._cancel_locked(entity_id)
                task = asyncio.create_task(
                    self._wait_and_lock(
                        entity_id,
                        current.get("lock_name") or entity_id,
                        new_deadline,
                    ),
                    name=f"relock-extended-{entity_id}",
                )
                self._tasks[entity_id] = task
                return True

    async def cancel(self, entity_id: str) -> None:
        """Cancel any pending relock for ``entity_id`` and clear DB row."""
        operation_lock = self._entity_lock(entity_id)
        async with operation_lock:
            async with self._lock:
                # Delete first for the same reason schedule persists first: a
                # transient DB failure must not silently destroy the only live
                # safety timer.
                await self._db.remove_pending_relock(entity_id)
                self._cancel_locked(entity_id)
                self._paused.discard(entity_id)

    async def pause(self, entity_id: str) -> dict | None:
        """Pause a pending relock without deleting its durable row.

        Manual lock actions use this while an HA command is in flight. If
        the command fails, :meth:`resume` re-arms the original deadline;
        if it succeeds, the caller replaces or cancels the row. This avoids
        losing the only safety timer merely because HA returned an error.
        """
        operation_lock = self._entity_lock(entity_id)
        async with operation_lock:
            async with self._lock:
                row = await self._db.get_pending_relock(entity_id)
                self._cancel_locked(entity_id)
                if row is not None:
                    self._paused.add(entity_id)
                return row

    async def resume(self, row: dict | None) -> bool:
        """Re-arm a row returned by :meth:`pause` if it was not superseded.

        Returns True when a task was restored. A concurrent schedule may
        have replaced the database row while the HA command was running;
        in that case its newer task/deadline wins and this is a no-op.
        """
        if not row:
            return False
        entity_id = row["entity_id"]
        deadline = float(row["deadline"])
        lock_name = row.get("lock_name") or entity_id
        operation_lock = self._entity_lock(entity_id)
        async with operation_lock:
            async with self._lock:
                current = await self._db.get_pending_relock(entity_id)
                if (
                    self._shutting_down
                    or current is None
                    or float(current["deadline"]) != deadline
                ):
                    self._paused.discard(entity_id)
                    return False
                existing = self._tasks.get(entity_id)
                if existing and not existing.done():
                    self._paused.discard(entity_id)
                    return False
                task = asyncio.create_task(
                    self._wait_and_lock(entity_id, lock_name, deadline),
                    name=f"relock-resume-{entity_id}",
                )
                self._tasks[entity_id] = task
                self._paused.discard(entity_id)
                _LOGGER.warning(
                    "Restored pending re-lock for %s after manual command failed",
                    lock_name,
                )
                return True

    async def shutdown(self) -> None:
        """Cancel and await live timers without deleting durable rows.

        Pending rows are intentionally retained so the next process can
        rehydrate them. The method is idempotent and prevents new schedules
        from being accepted once shutdown begins.
        """
        async with self._lock:
            if self._shutting_down and not self._tasks:
                return
            self._shutting_down = True
            current = asyncio.current_task()
            tasks = [task for task in self._tasks.values() if task is not current]
            self._tasks.clear()
            self._paused.clear()
            for task in tasks:
                if not task.done():
                    task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def rehydrate(self) -> None:
        """
        Reschedule pending relocks loaded from the database.

        Called on startup and after HA recovery. For each row:

        - If the deadline has passed → call ``ha_client.lock()`` immediately.
          On success, clear the DB row. On failure, leave the row so a
          later rehydrate (next HA recovery, next restart) can retry.
        - Else ensure one live task owns the durable deadline, preserving an
          already-running task for that same deadline.

        Each snapshot row is revalidated under its per-entity operation lock.
        A schedule that landed after ``get_pending_relocks()`` therefore wins
        without the stale row issuing a physical command or replacing its
        timer.
        """
        rows = await self._db.get_pending_relocks()
        if not rows:
            return
        _LOGGER.info("Rehydrating %d pending relock(s)", len(rows))
        for row in rows:
            await self._recover_or_schedule(row, schedule_future=True)

    async def sweep_overdue(self) -> int:
        """
        Retry past-due pending relocks that have no live task.

        Called periodically by the HA health loop while HA is connected.
        This closes the gap where a relock that exhausted its retries (DB
        row retained) would otherwise only be retried on the next HA
        disconnected→connected transition or restart — leaving a door
        physically unlocked indefinitely if HA never drops.

        Only rows whose deadline has passed AND that have no live in-memory
        task are swept: a future-dated row is owned by its scheduled task,
        and a live task is already handling that entity. Returns the number
        of relocks successfully fired.
        """
        rows = await self._db.get_pending_relocks()
        if not rows:
            return 0
        swept = 0
        for row in rows:
            if await self._recover_or_schedule(row, schedule_future=False):
                swept += 1
        return swept

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _entity_lock(self, entity_id: str) -> asyncio.Lock:
        """Return the stable physical-command lock for one HA entity."""
        lock = self._entity_locks.get(entity_id)
        if lock is None:
            lock = asyncio.Lock()
            self._entity_locks[entity_id] = lock
        return lock

    @asynccontextmanager
    async def _physical_command_barrier(self) -> AsyncIterator[None]:
        """Take the optional app-wide barrier around a physical HA command."""
        if self._command_lock is None:
            yield
            return
        async with self._command_lock:
            yield

    async def _recover_or_schedule(
        self, row: dict, *, schedule_future: bool
    ) -> bool:
        """Revalidate one snapshot row, then schedule or fire it safely.

        Returns True only when an overdue row was successfully locked and
        removed. The per-entity lock is held through the physical command, so
        a newer pause/schedule/cancel linearizes after that command; if the
        newer operation wins first, the deadline revalidation below skips the
        stale command entirely.
        """
        entity_id = row["entity_id"]
        deadline = float(row["deadline"])
        lock_name = row.get("lock_name") or entity_id
        operation_lock = self._entity_lock(entity_id)

        # First perform the cheap future/live-task check without taking the
        # app-wide physical-command barrier. Most sweep rows exit here. An
        # overdue row is revalidated after acquiring the barrier and the
        # per-entity lock in that fixed order.
        async with operation_lock:
            async with self._lock:
                if self._shutting_down or entity_id in self._paused:
                    return False
                current = await self._db.get_pending_relock(entity_id)
                if current is None or float(current["deadline"]) != deadline:
                    return False

                existing = self._tasks.get(entity_id)
                if existing is not None:
                    if not existing.done():
                        return False
                    self._tasks.pop(entity_id, None)

                remaining = deadline - time.time()
                if remaining > 0:
                    if schedule_future:
                        task = asyncio.create_task(
                            self._wait_and_lock(entity_id, lock_name, deadline),
                            name=f"relock-rehydrate-{entity_id}",
                        )
                        self._tasks[entity_id] = task
                    return False

        _LOGGER.warning(
            "Recovering overdue re-lock for %s (deadline %.0fs ago)",
            lock_name,
            max(0.0, time.time() - deadline),
        )
        ok = await self._call_ha_lock(
            entity_id, lock_name, deadline=deadline
        )
        if not ok:
            # Retain the durable row for the next recovery sweep.
            return False

        async with operation_lock:
            async with self._lock:
                if self._shutting_down or entity_id in self._paused:
                    return False
                current = await self._db.get_pending_relock(entity_id)
                if (
                    current is None
                    or float(current["deadline"]) != deadline
                ):
                    return False
                removed = await self._db.remove_pending_relock_at_deadline(
                    entity_id, deadline
                )
                if removed and self._on_locked is not None:
                    try:
                        self._on_locked(entity_id)
                    except Exception:
                        _LOGGER.exception(
                            "on_locked callback raised for %s", entity_id
                        )
                return bool(removed)

    async def _notify_relock_failed(self, entity_id: str, lock_name: str) -> None:
        """
        Fire an ``access_control_relock_failed`` HA event so automations can
        alert on a door that failed to re-lock. Best-effort — a failure to
        fire the event must not raise into the relock task.
        """
        ha = self._get_ha()
        if not ha:
            return
        try:
            await ha.fire_event(
                "access_control_relock_failed",
                {"entity_id": entity_id, "lock_name": lock_name},
            )
        except Exception:
            _LOGGER.exception("Failed to fire relock-failed event for %s", entity_id)

    def _cancel_locked(self, entity_id: str) -> None:
        """
        Cancel any in-memory task for ``entity_id`` without touching the DB.

        MUST be called with ``self._lock`` held — pure sync, no awaits.
        """
        existing = self._tasks.pop(entity_id, None)
        if existing and not existing.done():
            existing.cancel()

    async def _wait_and_lock(
        self, entity_id: str, lock_name: str, deadline: float
    ) -> None:
        current_task = asyncio.current_task()
        try:
            remaining = max(0.0, deadline - time.time())
            await asyncio.sleep(remaining)
        except asyncio.CancelledError:
            return

        notify_failed = False
        operation_lock = self._entity_lock(entity_id)
        try:
            ok = await self._call_ha_lock(
                entity_id,
                lock_name,
                deadline=deadline,
                owner_task=current_task,
            )

            async with operation_lock:
                async with self._lock:
                    if self._tasks.get(entity_id) is not current_task:
                        return
                    del self._tasks[entity_id]
                    if ok:
                        try:
                            removed = await self._db.remove_pending_relock_at_deadline(
                                entity_id, deadline
                            )
                        except Exception:
                            _LOGGER.exception(
                                "Failed to clear pending_relock row for %s",
                                entity_id,
                            )
                            removed = 0
                        if removed and self._on_locked is not None:
                            try:
                                self._on_locked(entity_id)
                            except Exception:
                                _LOGGER.exception(
                                    "on_locked callback raised for %s", entity_id
                                )
                    else:
                        # All retries exhausted. Leave the DB row so the
                        # periodic sweep can retry while HA stays connected.
                        _LOGGER.error(
                            "Re-lock FAILED for %s after %d retries — DB row "
                            "retained; sweep will retry and an HA event has "
                            "been fired",
                            lock_name,
                            _LOCK_RETRIES,
                        )
                        notify_failed = True
        except asyncio.CancelledError:
            return
        except Exception:
            _LOGGER.exception("Re-lock task crashed for %s; durable row retained", entity_id)
            async with self._lock:
                if self._tasks.get(entity_id) is current_task:
                    del self._tasks[entity_id]
            return

        if notify_failed:
            await self._notify_relock_failed(entity_id, lock_name)

    async def _call_ha_lock(
        self,
        entity_id: str,
        lock_name: str,
        *,
        deadline: float,
        owner_task: asyncio.Task | None = None,
    ) -> bool:
        """
        Call ha_client.lock() with bounded retries. Returns True on success.

        Each individual physical request takes the app barrier and entity lock
        only for that request. Retry/confirmation sleeps release both, and the
        durable generation is revalidated before every attempt. This prevents
        one degraded lock from blocking lockdown or unrelated doors.

        Does NOT invoke the on_locked callback — that fires from the caller
        only after the "still active" check passes, so a superseded relock
        can't overwrite the lock_states cache after a concurrent unlock.
        """
        for attempt in range(1, _LOCK_RETRIES + 1):
            operation_lock = self._entity_lock(entity_id)
            async with self._physical_command_barrier():
                async with operation_lock:
                    async with self._lock:
                        if self._shutting_down or entity_id in self._paused:
                            return False
                        if (
                            owner_task is not None
                            and self._tasks.get(entity_id) is not owner_task
                        ):
                            return False
                        current = await self._db.get_pending_relock(entity_id)
                        if (
                            current is None
                            or float(current["deadline"]) != float(deadline)
                        ):
                            return False
                        if owner_task is None:
                            live = self._tasks.get(entity_id)
                            if live is not None and not live.done():
                                return False

                    ha = self._get_ha()
                    if not ha:
                        _LOGGER.error(
                            "Re-lock skipped for %s — HA client unavailable",
                            lock_name,
                        )
                        ok = False
                    else:
                        try:
                            ok = await ha.lock(entity_id)
                        except Exception:
                            _LOGGER.exception(
                                "Re-lock attempt %d/%d raised for %s",
                                attempt,
                                _LOCK_RETRIES,
                                lock_name,
                            )
                            ok = False
            if ok:
                for confirmation in range(1, _CONFIRM_ATTEMPTS + 1):
                    try:
                        state = (
                            await ha.get_entity_state(entity_id)
                            if ha is not None
                            else None
                        )
                    except Exception:
                        _LOGGER.exception(
                            "Re-lock confirmation %d/%d raised for %s",
                            confirmation,
                            _CONFIRM_ATTEMPTS,
                            lock_name,
                        )
                        state = None
                    if state == "locked":
                        _LOGGER.info(
                            "Re-lock confirmed for %s%s",
                            lock_name,
                            f" on retry {attempt}" if attempt > 1 else "",
                        )
                        return True
                    if confirmation < _CONFIRM_ATTEMPTS:
                        await asyncio.sleep(_CONFIRM_DELAY)
                _LOGGER.warning(
                    "HA accepted re-lock for %s but state was not confirmed locked",
                    lock_name,
                )
            if attempt < _LOCK_RETRIES:
                await asyncio.sleep(_LOCK_RETRY_DELAY)
        return False
