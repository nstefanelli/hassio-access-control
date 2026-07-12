"""
Hub sync manager — optionally mirrors a third-party HA lock's state onto
its associated UniFi Access hub/door.

For HA-external locks that opted in via the per-lock ``sync_hub_state``
setting (off by default), this manager polls the HA lock entity and, on a
locked/unlocked transition, drives the paired native Access hub so the
door follows the physical lock:

- HA lock ``unlocked`` → hub ``keep_unlock`` (persistent hold-open)
- HA lock ``locked``   → hub ``reset`` (normal locked behaviour)

Pairing between the HA lock and the hub reuses the existing association
model: the lock's entry_devices rows of type ``access_reader`` (device_id
holds the Access location id) plus the legacy ``access_location_id``
column. Native locks at those locations provide the hub ``device_id``.

Safety properties (all verified by tests/test_hub_sync.py):

- One-way HA → hub, so sync cannot feed back into itself.
- Transitions only: the first poll after startup (or after enabling the
  option) adopts the current state as the baseline without touching the
  hub, so a restart never slams doors.
- States other than ``locked``/``unlocked`` (``unavailable``,
  ``unknown``, ``jammed``, …) are never acted on and never move the
  baseline, so a Z-Wave/Zigbee hiccup can't trigger a spurious change.
- **Lockdown**: while app lockdown is active, unlock transitions are
  never applied — the baseline is adopted instead, so the hub stays
  closed AND the door does not pop open the moment lockdown is lifted.
  Lock-direction transitions still apply (locking during lockdown is
  always safe and desirable). HA entity state is writable by any HA
  user token or integration, so without this check a lockdown could be
  defeated by faking an "unlocked" state write.
- **Flap damping**: applied transitions per entity are spaced at least
  ``_MIN_APPLY_INTERVAL`` apart (the deferred transition still applies
  once the interval passes — sync converges to the real state). A lock
  that keeps flapping (``_FLAP_THRESHOLD`` applied transitions within
  ``_FLAP_WINDOW``) suspends sync for that entity for
  ``_FLAP_SUSPEND`` seconds, fail-safes any held-open hub back to
  ``reset``, and fires ``access_control_hub_sync_failed`` with
  ``reason: flapping`` — protecting the strike relay from a failing
  lock or a deliberate low-privilege flipper.
- **Release on drop**: when a synced lock leaves the opted-in set
  (option turned off, lock hidden, or lock deleted) while its hub is
  held open, the hub is driven back to ``reset`` rather than being
  silently stranded in ``keep_unlock``. Releases retry with backoff
  until they succeed. Hubs are resolved from the lock row when it still
  exists (works even across a restart, since the adopted baseline
  carries the unlocked status) and from the in-memory held-open record
  for deleted rows.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Callable, Optional

from .database import Database

_LOGGER = logging.getLogger(__name__)

# Retry attempts for a single hub drive when a transition fires
_APPLY_RETRIES = 2
_APPLY_RETRY_DELAY = 1.5

# After a failed transition, wait this long before retrying that entity —
# the baseline is NOT advanced on failure, so the transition is retried
# until the hub converges (desired-state semantics, like sweep_overdue).
_FAILURE_BACKOFF = 30.0

# Flap damping: minimum spacing between applied transitions per entity.
# A deferred transition is not lost — the baseline is unchanged, so it
# applies on the first poll after the interval elapses.
_MIN_APPLY_INTERVAL = 30.0

# Flap suspension: this many *applied* transitions within the window
# means the lock is cycling abnormally (failing hardware or deliberate
# flipping). Sync for the entity is suspended, held-open hubs fail-safe
# to reset, and the failure event fires with reason "flapping".
_FLAP_WINDOW = 600.0
_FLAP_THRESHOLD = 4
_FLAP_SUSPEND = 600.0


class HubSyncManager:
    """
    Polls opted-in HA lock entities and mirrors their state to paired
    Access hubs. Driven by a supervised loop in main.py calling
    :meth:`poll_once` every :data:`POLL_INTERVAL` seconds.
    """

    # Poll cadence for the main.py loop. Transitions are what matter, so
    # this only bounds reaction latency (the app has no HA websocket).
    POLL_INTERVAL = 5.0

    def __init__(
        self,
        db: Database,
        ha_client_getter: Callable[[], Any],
        access_client_getter: Callable[[], Any],
        on_hub_state: Optional[Callable[[str, str], None]] = None,
        lockdown_getter: Optional[Callable[[], bool]] = None,
    ) -> None:
        # Clients are fetched lazily via getters — same rationale as
        # RelockManager: credential updates from Settings swap the client
        # objects and the getters transparently pick up the new ones.
        # on_hub_state(device_id, state) refreshes the in-memory
        # lock_states cache after a hub is driven. lockdown_getter
        # returns the auth engine's current lockdown flag.
        self._db = db
        self._get_ha = ha_client_getter
        self._get_access = access_client_getter
        self._on_hub_state = on_hub_state
        self._lockdown_getter = lockdown_getter
        # entity_id → last state the paired hub is known to match. Absent
        # key = baseline not yet adopted.
        self._applied: dict[str, str] = {}
        # entity_id → monotonic deadline before which we skip retrying
        self._backoff_until: dict[str, float] = {}
        # entities whose current failing transition already fired the
        # failure event (avoid re-notifying every backoff cycle)
        self._failure_notified: set[str] = set()
        # Flap damping state: last applied-transition time and the recent
        # applied-transition timestamps within the flap window.
        self._last_applied_at: dict[str, float] = {}
        self._apply_times: dict[str, list[float]] = {}
        self._suspended_until: dict[str, float] = {}
        # entity_id → hub lock rows we currently hold open (keep_unlock).
        # Used to release hubs when a deleted lock leaves the synced set.
        self._held_open: dict[str, list[dict]] = {}
        # entity_id → hubs that still need to be driven back to reset
        # after their lock left the synced set; retried with backoff.
        self._pending_release: dict[str, list[dict]] = {}
        self._release_backoff: dict[str, float] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def poll_once(self) -> int:
        """
        One sync pass over all opted-in locks. Returns the number of
        transitions successfully applied to hubs.
        """
        ha = self._get_ha()
        if ha is None or not getattr(ha, "connected", False):
            return 0

        # include_hidden so a just-hidden lock's row is still available
        # for hub resolution when we release its held-open hub below.
        all_locks = await self._db.get_all_locks(include_hidden=True)
        synced = [
            lock for lock in all_locks
            if lock.get("type") == "ha_external"
            and lock.get("sync_hub_state")
            and lock.get("entity_id")
            and not lock.get("hidden")
        ]
        current_eids = {lock["entity_id"] for lock in synced}

        # Entities that left the opted-in set (option off / hidden /
        # deleted): release any hub we hold open, then drop tracking so
        # re-enabling later re-adopts a fresh baseline instead of
        # replaying a stale transition.
        for eid in list(self._applied):
            if eid not in current_eids:
                await self._queue_release(eid, all_locks)
                self._drop_tracking(eid)
        self._failure_notified &= current_eids

        await self._process_pending_releases()

        applied_count = 0
        for lock in synced:
            eid = lock["entity_id"]
            now = time.monotonic()
            if self._suspended_until.get(eid, 0.0) > now:
                continue
            if self._backoff_until.get(eid, 0.0) > now:
                continue

            try:
                state = await ha.get_entity_state(eid)
            except Exception:
                _LOGGER.exception("Hub sync: state fetch raised for %s", eid)
                continue
            if state not in ("locked", "unlocked"):
                continue

            prev = self._applied.get(eid)
            if prev is None:
                # First observation — adopt without acting so startup /
                # option-enable never moves a door by itself.
                self._applied[eid] = state
                _LOGGER.info("Hub sync baseline adopted for %s: %s", eid, state)
                continue
            if state == prev:
                # Any failing transition self-reverted — clear the notify
                # flag so the NEXT failing transition alerts again.
                self._failure_notified.discard(eid)
                continue

            # Flap damping: space applied transitions out. Deferring keeps
            # the old baseline, so the transition applies after the
            # interval if the state still differs.
            if now - self._last_applied_at.get(eid, 0.0) < _MIN_APPLY_INTERVAL:
                _LOGGER.debug(
                    "Hub sync: transition for %s deferred (min interval)", eid
                )
                continue

            # Flap suspension: an entity that keeps earning applied
            # transitions is cycling abnormally — stop following it.
            recent = [
                t for t in self._apply_times.get(eid, ())
                if now - t <= _FLAP_WINDOW
            ]
            self._apply_times[eid] = recent
            if len(recent) >= _FLAP_THRESHOLD:
                await self._suspend_flapping(lock)
                continue

            # Lockdown: never hold a hub open off an HA state write while
            # lockdown is active. Adopt the baseline instead of deferring
            # so the door also doesn't pop open when lockdown lifts.
            if state == "unlocked" and self._in_lockdown():
                _LOGGER.warning(
                    "Hub sync: %s reported unlocked during LOCKDOWN — "
                    "hub stays closed; baseline adopted",
                    lock.get("name", eid),
                )
                self._applied[eid] = state
                continue

            _LOGGER.info(
                "Hub sync: %s changed %s → %s — syncing paired hub(s)",
                lock.get("name", eid), prev, state,
            )
            if await self._apply_transition(lock, state):
                self._applied[eid] = state
                self._backoff_until.pop(eid, None)
                self._failure_notified.discard(eid)
                applied_count += 1
            else:
                # Keep the old baseline so the transition is retried after
                # the backoff — the hub must converge to the lock state.
                self._backoff_until[eid] = time.monotonic() + _FAILURE_BACKOFF

        return applied_count

    # ------------------------------------------------------------------
    # Internal — transitions
    # ------------------------------------------------------------------

    def _in_lockdown(self) -> bool:
        if self._lockdown_getter is None:
            return False
        try:
            return bool(self._lockdown_getter())
        except Exception:
            # Fail closed: if lockdown state can't be read, behave as if
            # lockdown is active — suppressing a hold-open is the safe
            # direction for a physical door.
            _LOGGER.exception("Hub sync: lockdown getter raised — failing closed")
            return True

    async def _apply_transition(self, lock: dict, state: str) -> bool:
        """Drive all hubs paired with ``lock`` to ``state``. True on success."""
        eid = lock["entity_id"]
        lock_name = lock.get("name", eid)

        access = self._get_access()
        if access is None or not getattr(access, "connected", False):
            _LOGGER.warning(
                "Hub sync for %s deferred — Access client unavailable", lock_name
            )
            return False

        hubs = await self._resolve_hub_locks(lock)
        if not hubs:
            # Misconfiguration (option on, no paired Access door). Warn and
            # treat as applied so we don't re-warn every backoff cycle; the
            # next transition will warn again if still unpaired.
            _LOGGER.warning(
                "Hub sync enabled for %s but no associated Access hub found — "
                "link an Access location via Entry Devices or lock settings",
                lock_name,
            )
            return True

        ok_all = True
        drove_any = False
        for hub in hubs:
            device_id = hub["device_id"]
            hub_name = hub.get("name", device_id)
            if not await self._drive_hub(access, device_id, state, hub_name):
                ok_all = False
                continue
            drove_any = True
            self._record_hub_state(eid, hub, state)
            if self._on_hub_state is not None:
                try:
                    self._on_hub_state(device_id, state)
                except Exception:
                    _LOGGER.exception("on_hub_state callback raised for %s", device_id)
            try:
                await self._db.log_access(
                    method="hub_sync",
                    result="info",
                    lock_id=hub.get("id"),
                    lock_name=hub_name,
                    reason=f"Synced to {lock_name} ({state})",
                )
            except Exception:
                _LOGGER.exception("Failed to log hub sync for %s", hub_name)

        if drove_any:
            # Damping bookkeeping counts only real hub actuations — a
            # no-hub misconfiguration must not trip the flap breaker.
            now = time.monotonic()
            self._last_applied_at[eid] = now
            self._apply_times.setdefault(eid, []).append(now)

        if not ok_all and eid not in self._failure_notified:
            self._failure_notified.add(eid)
            await self._notify_sync_failed(eid, lock_name, reason="apply_failed")
        return ok_all

    def _record_hub_state(self, eid: str, hub: dict, state: str) -> None:
        """Track which hubs we currently hold open for ``eid``."""
        held = self._held_open.setdefault(eid, [])
        if state == "unlocked":
            if not any(h.get("id") == hub.get("id") for h in held):
                held.append(hub)
        else:
            self._held_open[eid] = [
                h for h in held if h.get("id") != hub.get("id")
            ]

    async def _suspend_flapping(self, lock: dict) -> None:
        """
        The entity earned too many applied transitions inside the flap
        window. Suspend sync for it, fail-safe any held-open hub back to
        reset, and alert. Tracking is dropped so the first poll after the
        suspension re-adopts a fresh baseline without acting.
        """
        eid = lock["entity_id"]
        lock_name = lock.get("name", eid)
        self._suspended_until[eid] = time.monotonic() + _FLAP_SUSPEND
        _LOGGER.error(
            "Hub sync SUSPENDED for %s — %d transitions inside %.0fs "
            "(flapping lock or abuse). Hub fail-safes to reset; sync "
            "resumes in %.0fs with a fresh baseline.",
            lock_name, _FLAP_THRESHOLD, _FLAP_WINDOW, _FLAP_SUSPEND,
        )
        await self._queue_release(eid, all_locks=None, lock_row=lock)
        self._applied.pop(eid, None)
        self._last_applied_at.pop(eid, None)
        self._apply_times.pop(eid, None)
        self._backoff_until.pop(eid, None)
        await self._notify_sync_failed(eid, lock_name, reason="flapping")

    # ------------------------------------------------------------------
    # Internal — release of held-open hubs
    # ------------------------------------------------------------------

    async def _queue_release(
        self,
        eid: str,
        all_locks: Optional[list[dict]],
        lock_row: Optional[dict] = None,
    ) -> None:
        """
        If ``eid`` may have hubs in keep_unlock, queue them to be driven
        back to reset. Hubs are resolved from the lock row when available
        (covers opt-out/hide, and survives restarts because the adopted
        baseline carries the unlocked status); the in-memory held-open
        record covers deleted rows.
        """
        held = self._held_open.get(eid, [])
        baseline_unlocked = self._applied.get(eid) == "unlocked"
        if not held and not baseline_unlocked:
            return

        if lock_row is None and all_locks is not None:
            lock_row = next(
                (l for l in all_locks if l.get("entity_id") == eid), None
            )
        hubs: list[dict] = []
        if lock_row is not None:
            try:
                hubs = await self._resolve_hub_locks(lock_row)
            except Exception:
                _LOGGER.exception("Hub sync: release resolution failed for %s", eid)
        if not hubs:
            hubs = list(held)
        if not hubs:
            _LOGGER.warning(
                "Hub sync disabled for %s while unlocked, but no paired hub "
                "could be resolved — check the hub state manually", eid,
            )
            return

        _LOGGER.warning(
            "Hub sync no longer follows %s — driving %d paired hub(s) back "
            "to reset so no door is left held open",
            eid, len(hubs),
        )
        pending = self._pending_release.setdefault(eid, [])
        for hub in hubs:
            if not any(h.get("id") == hub.get("id") for h in pending):
                pending.append(hub)
        self._release_backoff.pop(eid, None)

    async def _process_pending_releases(self) -> None:
        """Drive queued hubs back to reset; keep failures for retry."""
        if not self._pending_release:
            return
        access = self._get_access()
        now = time.monotonic()
        for eid in list(self._pending_release):
            if self._release_backoff.get(eid, 0.0) > now:
                continue
            if access is None or not getattr(access, "connected", False):
                self._release_backoff[eid] = now + _FAILURE_BACKOFF
                continue
            remaining: list[dict] = []
            for hub in self._pending_release[eid]:
                device_id = hub["device_id"]
                hub_name = hub.get("name", device_id)
                if not await self._drive_hub(access, device_id, "locked", hub_name):
                    remaining.append(hub)
                    continue
                if self._on_hub_state is not None:
                    try:
                        self._on_hub_state(device_id, "locked")
                    except Exception:
                        _LOGGER.exception(
                            "on_hub_state callback raised for %s", device_id
                        )
                try:
                    await self._db.log_access(
                        method="hub_sync",
                        result="info",
                        lock_id=hub.get("id"),
                        lock_name=hub_name,
                        reason=f"Reset after sync stopped following {eid}",
                    )
                except Exception:
                    _LOGGER.exception("Failed to log hub release for %s", hub_name)
            if remaining:
                self._pending_release[eid] = remaining
                self._release_backoff[eid] = time.monotonic() + _FAILURE_BACKOFF
            else:
                del self._pending_release[eid]
                self._release_backoff.pop(eid, None)

    def _drop_tracking(self, eid: str) -> None:
        self._applied.pop(eid, None)
        self._backoff_until.pop(eid, None)
        self._last_applied_at.pop(eid, None)
        self._apply_times.pop(eid, None)
        self._suspended_until.pop(eid, None)
        self._held_open.pop(eid, None)

    # ------------------------------------------------------------------
    # Internal — resolution / actuation / alerting
    # ------------------------------------------------------------------

    async def _resolve_hub_locks(self, lock: dict) -> list[dict]:
        """
        Return native Access locks paired with an HA-external lock via its
        entry_devices access_reader rows and/or legacy access_location_id.
        """
        location_ids: set[str] = set()
        if lock.get("access_location_id"):
            location_ids.add(lock["access_location_id"])
        try:
            devices_by_lock = await self._db.get_entry_devices_for_locks([lock["id"]])
        except Exception:
            _LOGGER.exception("Hub sync: entry-device lookup failed for lock %s", lock.get("id"))
            devices_by_lock = {}
        for device in devices_by_lock.get(lock["id"], []):
            if device.get("type") == "access_reader" and device.get("device_id"):
                location_ids.add(device["device_id"])

        hubs: list[dict] = []
        seen_ids: set[int] = set()
        for location_id in location_ids:
            for candidate in await self._db.get_locks_for_location(location_id):
                if (
                    candidate.get("type") == "access_native"
                    and candidate.get("device_id")
                    and candidate["id"] not in seen_ids
                ):
                    hubs.append(candidate)
                    seen_ids.add(candidate["id"])
        return hubs

    async def _drive_hub(
        self, access: Any, device_id: str, state: str, hub_name: str
    ) -> bool:
        """Call the Access API with bounded retries. True on success."""
        for attempt in range(1, _APPLY_RETRIES + 1):
            try:
                if state == "unlocked":
                    await access.unlock_persistent(device_id)
                else:
                    await access.lock(device_id)
                _LOGGER.info("Hub sync: %s driven to %s", hub_name, state)
                return True
            except Exception:
                _LOGGER.exception(
                    "Hub sync attempt %d/%d failed for %s (→ %s)",
                    attempt, _APPLY_RETRIES, hub_name, state,
                )
                if attempt < _APPLY_RETRIES:
                    await asyncio.sleep(_APPLY_RETRY_DELAY)
        return False

    async def _notify_sync_failed(
        self, entity_id: str, lock_name: str, reason: str = "apply_failed"
    ) -> None:
        """
        Fire an ``access_control_hub_sync_failed`` HA event so automations
        can alert on a hub that failed to follow its lock (or was
        suspended for flapping). Best-effort — fired once per failing
        transition, not on every backoff retry.
        """
        ha = self._get_ha()
        if not ha:
            return
        try:
            await ha.fire_event(
                "access_control_hub_sync_failed",
                {"entity_id": entity_id, "lock_name": lock_name, "reason": reason},
            )
        except Exception:
            _LOGGER.exception("Failed to fire hub-sync-failed event for %s", entity_id)
