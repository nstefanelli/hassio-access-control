"""
Hub sync manager — optionally mirrors a third-party HA lock's state onto
its associated UniFi Access hub/door.

For HA-external locks that opted in via the per-lock ``sync_hub_state``
setting (off by default), this manager polls the HA lock entity and, on a
locked/unlocked transition, drives the paired native Access hub so the
door follows the physical lock:

- HA lock ``unlocked`` → hub ``keep_unlock`` (persistent hold-open)
- HA lock ``locked``   → hub ``reset`` (normal locked behaviour)

Pairing reuses the existing association model between an HA lock and an
Access door: ``entry_devices`` rows of type ``access_reader`` (whose
``device_id`` holds the Access location id) plus the legacy
``access_location_id`` column. Native locks at those locations provide
the hub ``device_id`` to drive.

Sync direction is one-way (HA → hub) so it cannot feed back into itself,
and it acts on observed *transitions* only — the first poll after startup
(or after enabling the option) adopts the current state as the baseline
without touching the hub, so a restart never slams doors.

States other than ``locked``/``unlocked`` (``unavailable``, ``unknown``,
``jammed``, …) are never acted on and never move the baseline, so a
Z-Wave/Zigbee hiccup can't trigger a spurious hub change.
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
    ) -> None:
        # Clients are fetched lazily via getters — same rationale as
        # RelockManager: credential updates from Settings swap the client
        # objects and the getters transparently pick up the new ones.
        # on_hub_state(device_id, state) refreshes the in-memory
        # lock_states cache after a hub is driven.
        self._db = db
        self._get_ha = ha_client_getter
        self._get_access = access_client_getter
        self._on_hub_state = on_hub_state
        # entity_id → last state the paired hub is known to match. Absent
        # key = baseline not yet adopted.
        self._applied: dict[str, str] = {}
        # entity_id → monotonic deadline before which we skip retrying
        self._backoff_until: dict[str, float] = {}
        # entities whose current failing transition already fired the
        # failure event (avoid re-notifying every backoff cycle)
        self._failure_notified: set[str] = set()

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

        locks = await self._db.get_all_locks()
        synced = [
            lock for lock in locks
            if lock.get("type") == "ha_external"
            and lock.get("sync_hub_state")
            and lock.get("entity_id")
        ]

        # Drop tracking for entities no longer opted in, so re-enabling
        # later re-adopts a fresh baseline instead of replaying a stale
        # transition from before the option was turned off.
        current_eids = {lock["entity_id"] for lock in synced}
        for eid in list(self._applied):
            if eid not in current_eids:
                del self._applied[eid]
        for eid in list(self._backoff_until):
            if eid not in current_eids:
                del self._backoff_until[eid]
        self._failure_notified &= current_eids

        applied_count = 0
        for lock in synced:
            eid = lock["entity_id"]
            if self._backoff_until.get(eid, 0.0) > time.monotonic():
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
    # Internal
    # ------------------------------------------------------------------

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
        for hub in hubs:
            device_id = hub["device_id"]
            hub_name = hub.get("name", device_id)
            if not await self._drive_hub(access, device_id, state, hub_name):
                ok_all = False
                continue
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

        if not ok_all and eid not in self._failure_notified:
            self._failure_notified.add(eid)
            await self._notify_sync_failed(eid, lock_name)
        return ok_all

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

    async def _notify_sync_failed(self, entity_id: str, lock_name: str) -> None:
        """
        Fire an ``access_control_hub_sync_failed`` HA event so automations
        can alert on a hub that failed to follow its lock. Best-effort —
        fired once per failing transition, not on every backoff retry.
        """
        ha = self._get_ha()
        if not ha:
            return
        try:
            await ha.fire_event(
                "access_control_hub_sync_failed",
                {"entity_id": entity_id, "lock_name": lock_name},
            )
        except Exception:
            _LOGGER.exception("Failed to fire hub-sync-failed event for %s", entity_id)
