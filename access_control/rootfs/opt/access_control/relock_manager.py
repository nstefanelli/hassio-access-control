"""
Relock manager — centralises auto-relock scheduling across all three sources
(buzz button, remote unlock, device-auth unlock) and persists pending relocks
to the database so they survive a service restart.

Used by main.py to rehydrate pending relocks on startup, by web_routes.py
for buzz unlocks, by main.py for remote-unlock relocks, and by auth_engine.py
for device-auth relocks.

Concurrency model
-----------------
A single ``asyncio.Lock`` serialises mutation of the in-memory ``_tasks``
dict and the corresponding ``pending_relocks`` rows. The actual HA lock
call (which may take seconds with retries) runs *outside* the lock so it
never blocks new buzz/cancel commands. Cleanup after a successful lock
re-acquires the lock and is a no-op if a newer ``schedule()`` has already
replaced this entry — preventing the row-clobber race where a fired timer
would delete the row for a freshly-scheduled relock.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional

from .database import Database

_LOGGER = logging.getLogger(__name__)

# Retry attempts for the actual HA lock call when relock fires
_LOCK_RETRIES = 2
_LOCK_RETRY_DELAY = 1.5


class RelockManager:
    """
    Schedules auto-relock tasks for HA-external locks, persisting each
    pending relock so it survives a service restart.

    All three relock sources (buzz, remote_unlock, device_auth) flow
    through :meth:`schedule`. The manager keeps an in-memory dict of
    active asyncio.Tasks keyed by entity_id, and a parallel row in the
    ``pending_relocks`` table keyed by the same.
    """

    def __init__(self, db: Database, ha_client_getter, on_locked=None) -> None:
        # ha_client_getter is a zero-arg callable returning the *current*
        # HAClient — needed because the client can be replaced via Settings.
        # on_locked is an optional callback(entity_id) invoked after the
        # lock command succeeds — used to refresh the in-memory state cache.
        self._db = db
        self._get_ha = ha_client_getter
        self._on_locked = on_locked
        self._tasks: dict[str, asyncio.Task] = {}
        self._lock: asyncio.Lock = asyncio.Lock()

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
    ) -> None:
        """
        Schedule a relock for ``entity_id`` after ``duration`` seconds.

        Cancels any pending relock for the same entity, persists the new
        deadline, and starts a background task that calls ``ha_client.lock()``
        when the timer fires (with bounded retries on failure).
        """
        async with self._lock:
            self._cancel_locked(entity_id)
            deadline = time.time() + duration
            await self._db.add_pending_relock(
                entity_id=entity_id,
                lock_id=lock_id,
                lock_name=lock_name,
                source=source,
                deadline=deadline,
            )
            _LOGGER.info(
                "Re-lock scheduled (%s): %s in %.0fs", source, lock_name, duration
            )
            task = asyncio.create_task(
                self._wait_and_lock(entity_id, lock_name, deadline),
                name=f"relock-{source}-{entity_id}",
            )
            self._tasks[entity_id] = task

    async def cancel(self, entity_id: str) -> None:
        """Cancel any pending relock for ``entity_id`` and clear DB row."""
        async with self._lock:
            self._cancel_locked(entity_id)
            await self._db.remove_pending_relock(entity_id)

    async def rehydrate(self) -> None:
        """
        Reschedule pending relocks loaded from the database.

        Called on startup and after HA recovery. For each row:

        - If the deadline has passed → call ``ha_client.lock()`` immediately.
          On success, clear the DB row. On failure, leave the row so a
          later rehydrate (next HA recovery, next restart) can retry.
        - Else cancel any live task for the entity and schedule a fresh
          task for the remaining time.

        The HA lock call for past-due rows happens *outside* the lock so
        it doesn't block concurrent schedule/cancel calls.
        """
        rows = await self._db.get_pending_relocks()
        if not rows:
            return
        now = time.time()
        _LOGGER.info("Rehydrating %d pending relock(s)", len(rows))
        for row in rows:
            entity_id = row["entity_id"]
            lock_name = row.get("lock_name") or entity_id
            deadline = float(row["deadline"])
            remaining = deadline - now

            # Cancel any live task for this entity under the lock — rehydrate
            # is called by the HA recovery loop while normal operation
            # continues, so a live task may exist for the same entity.
            async with self._lock:
                self._cancel_locked(entity_id)

            if remaining <= 0:
                _LOGGER.warning(
                    "Pending re-lock for %s expired %.0fs ago — locking now",
                    lock_name, -remaining,
                )
                ok = await self._call_ha_lock(entity_id, lock_name)
                if ok:
                    # Deadline-conditional delete: between releasing the
                    # cancel lock and now, a concurrent schedule() may have
                    # written a *new* row with a different deadline. Only
                    # remove our row. Same reasoning for on_locked — fire
                    # it only if a concurrent operation didn't supersede us.
                    async with self._lock:
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
                # If failed, leave the row for a future rehydrate to retry.
                continue

            async with self._lock:
                task = asyncio.create_task(
                    self._wait_and_lock(entity_id, lock_name, deadline),
                    name=f"relock-rehydrate-{entity_id}",
                )
                self._tasks[entity_id] = task

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

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
        try:
            remaining = max(0.0, deadline - time.time())
            await asyncio.sleep(remaining)
            ok = await self._call_ha_lock(entity_id, lock_name)
        except asyncio.CancelledError:
            # Cancellation paths (cancel() / schedule() replacement / rehydrate)
            # own all _tasks + DB cleanup. We just exit.
            return

        # Re-acquire the lock for the post-fire cleanup. A concurrent
        # schedule() / cancel() may have replaced or removed our slot
        # while we were inside _call_ha_lock — in that case we must NOT
        # touch _tasks, the DB row, or the on_locked cache.
        async with self._lock:
            current = asyncio.current_task()
            if self._tasks.get(entity_id) is not current:
                # Superseded — newer schedule() already cleaned up.
                # Do NOT fire on_locked even though ha.lock returned ok:
                # a concurrent manual unlock may have just put the door
                # into an "unlocked" state that we don't want to overwrite.
                return
            del self._tasks[entity_id]
            if ok:
                # Success — fire the lock_states cache update first, then
                # clear the DB row. Both happen under the lock so concurrent
                # cancel/schedule are serialised behind us.
                if self._on_locked is not None:
                    try:
                        self._on_locked(entity_id)
                    except Exception:
                        _LOGGER.exception("on_locked callback raised for %s", entity_id)
                try:
                    await self._db.remove_pending_relock(entity_id)
                except Exception:
                    _LOGGER.exception(
                        "Failed to clear pending_relock row for %s", entity_id
                    )
            else:
                # All retries exhausted. Leave the DB row so the HA recovery
                # loop's rehydrate() will retry once HA is healthy.
                _LOGGER.error(
                    "Re-lock FAILED for %s after %d retries — DB row retained for recovery",
                    lock_name, _LOCK_RETRIES,
                )

    async def _call_ha_lock(self, entity_id: str, lock_name: str) -> bool:
        """
        Call ha_client.lock() with bounded retries. Returns True on success.

        Does NOT invoke the on_locked callback — that fires from the caller
        only after the "still active" check passes, so a superseded relock
        can't overwrite the lock_states cache after a concurrent unlock.
        """
        ha = self._get_ha()
        if not ha:
            _LOGGER.error("Re-lock skipped for %s — HA client unavailable", lock_name)
            return False
        for attempt in range(1, _LOCK_RETRIES + 1):
            try:
                ok = await ha.lock(entity_id)
            except Exception:
                _LOGGER.exception(
                    "Re-lock attempt %d/%d raised for %s",
                    attempt, _LOCK_RETRIES, lock_name,
                )
                ok = False
            if ok:
                if attempt > 1:
                    _LOGGER.info(
                        "Re-lock succeeded for %s on retry %d", lock_name, attempt
                    )
                else:
                    _LOGGER.info("Re-lock fired for %s", lock_name)
                return True
            if attempt < _LOCK_RETRIES:
                await asyncio.sleep(_LOCK_RETRY_DELAY)
        return False
