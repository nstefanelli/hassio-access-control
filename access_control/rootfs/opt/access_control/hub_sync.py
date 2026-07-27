"""Bidirectional Home Assistant lock ↔ UniFi Access door convergence.

Opted-in ``ha_external`` locks and their paired native Access doors are
observed every poll. Authenticated Access schedule/temporary-rule events wake
the same reconciliation early; event payloads are never accepted as physical
proof. With rule and relay readback available, a change on either side drives
the other. Older compatibility clients retain safe HA→Access behavior.

Command semantics are explicit:

- HA-origin unlock → ``keep_unlock`` (persistent app-owned override)
- HA-origin lock → ``lock_now`` (close now; later schedules remain eligible)
- lockdown, conflict, or untrusted state → ``keep_lock`` until safe release
- deliberate opt-out/shutdown → ``reset`` to return native schedule ownership

Startup mismatches and concurrent changes are locked-wins, except for an
authenticated active Access schedule whose relay is also confirmed unlocked.

Pairing between the HA lock and the hub reuses the existing association
model, resolved in this order:

- ``entry_devices`` rows of type ``access_reader`` — device_id holds the
  Access location id directly;
- ``entry_devices`` rows of type ``protect_doorbell`` — device_id is a
  Protect camera id, mapped to its door location via the app's
  camera→location map (covers G6 Entry-paired doors);
- the legacy ``access_location_id`` column.

Native locks at those locations provide the hub ``device_id`` to drive —
including locks the user hid from the dashboard (hiding is cosmetic and
must not silently break sync).

Persistent ``keep_unlock`` and ``keep_lock`` ownership is written to SQLite,
including the official Access door id, before the physical command. Recovery
first closes uncertain doors, then replaces app-owned ``keep_lock`` only after
readback proves HA and Access are safe. A failed release retains ownership for
retry, preventing both stranded-open doors and silently suppressed schedules.
"""
from __future__ import annotations

import asyncio
import inspect
import json
import logging
import time
from contextlib import AsyncExitStack
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional

from .access_client import AccessClientError, AccessLegacyEndpointGoneError
from .database import Database
from .ha_client import ha_client_operation

_LOGGER = logging.getLogger(__name__)

# Retry attempts for a single hub drive
_APPLY_RETRIES = 2
_APPLY_RETRY_DELAY = 1.5

# After a failed drive, wait this long before retrying that entity —
# the applied state is NOT advanced on failure, so the change is retried
# until the hub converges (desired-state semantics, like sweep_overdue).
_FAILURE_BACKOFF = 30.0

# Consecutive identical hard-rejection failures before the locked direction is
# placed on _FAILURE_BACKOFF spacing. The retry NEVER stops — it is only spaced
# so a permanently removed endpoint cannot spam a drive+log every poll.
_HARD_REJECT_BACKOFF_THRESHOLD = 3

# Exact AccessClientError messages that denote a permanent, operator-actionable
# rejection of a legacy lock write. Kept as a tiny exact-match allowlist so
# ordinary transient faults (timeouts, 5xx, connection resets) never engage the
# hard-rejection backoff — they keep retrying at full cadence.
_HARD_REJECTION_MARKERS = frozenset(
    {"UniFi Access rejected the legacy lock rule"}
)

# Flap damping: minimum spacing between hub drives per entity. A
# deferred change is not lost — it applies on the first poll after the
# interval elapses. Short enough that "converge on enable, then the user
# immediately toggles the lock" still feels responsive.
_MIN_APPLY_INTERVAL = 10.0

# Flap suspension: this many drives inside the window means the lock is
# cycling pathologically (failing hardware or deliberate flipping) —
# NOT normal use: leaving+returning twice in 5 minutes is 4 drives, and
# hand-testing the feature is similar. 8 in 5 minutes is well past both.
_FLAP_WINDOW = 300.0
_FLAP_THRESHOLD = 8
_FLAP_SUSPEND = 600.0

_HA_CONFIRM_ATTEMPTS = 3
_HA_CONFIRM_DELAY = 0.25
# Access relay observation runs on a bounded progressive window (~5s total),
# matching the access_client confirm window. Current Access firmware can echo a
# freshly written rule while the relay reports the previous state for several
# seconds, and a momentary lock_now transiently returns no relay state at all.
# A short fixed loop classified that normal actuation latency as an
# inconsistent/unreadable side and latched locked-wins. Reads at
# t≈0,0.25,0.75,1.75,3.25,5.25s; a missing/invalid read mid-window is retried,
# and only the final read is classified. Settling observations run under the
# poll lock, never the physical-command barrier: the one observation taken
# while the barrier is held (the write-ahead freshness guard) uses a single
# non-settling read bounded by _GUARD_OBSERVE_TIMEOUT and fails safe on
# ambiguity, so it cannot stall unrelated door commands.
_ACCESS_OBSERVE_DELAYS = (0.25, 0.5, 1.0, 1.5, 2.0)
_ACCESS_OBSERVE_WINDOW = round(sum(_ACCESS_OBSERVE_DELAYS), 1)
_GUARD_OBSERVE_TIMEOUT = 6.0

# Graceful-restart hold preservation (opt-in per lock via
# ``preserve_hold_on_restart``). shutdown() records a single-use
# clean-shutdown marker in the config table naming the keep_unlock holds it
# deliberately left physically in place; recover() consumes the marker and
# re-adopts a named hold only after readback proves HA still reports the
# deadbolt unlocked (and a readback-capable Access client still reports
# keep_unlock). Everything else keeps the fail-closed recovery path.
_CLEAN_SHUTDOWN_KEY = "hub_sync_clean_shutdown"
# A marker older than this is treated as unclean (fail closed). Generous
# enough for a full-backup stop/start window while bounding how long a stray
# marker could vouch for an open door. Wall-clock, because monotonic time
# does not survive the restart the marker exists to bridge.
_CLEAN_SHUTDOWN_MAX_AGE = 1800.0
# Small tolerance for wall-clock steps (NTP) between write and read; a
# marker further in the future than this is suspicious and fails closed.
_CLEAN_SHUTDOWN_FUTURE_SKEW = 60.0

_ACCESS_OPEN_RULES = {"schedule", "keep_unlock", "custom"}
_ACCESS_CLOSED_RULES = {
    "keep_lock",
    "lock_early",
    "lock_now",
}
_ACCESS_NATIVE_RULES = {"reset", "normal", "native"}
_ACCESS_STATE_EVENTS = {
    "access.unlock_schedule.activate",
    "access.unlock_schedule.deactivate",
    "access.temporary_unlock.start",
    "access.temporary_unlock.end",
}

# _persist_convergence writes this prefix into _last_access_rule after our
# own successful drive, instead of a real Access rule-fingerprint JSON blob —
# there is no fresh observation to record at that point, only the state we
# just commanded. A "command:<state>" marker can never equal a JSON
# fingerprint, so comparing it against the next poll's real observation is
# always spuriously unequal even when nothing external changed. Detecting
# the marker lets _reconcile_bidirectional fall back to a state-only
# comparison for that one baseline instead of misreading it as an
# Access-origin change (and, via concurrent_conflict, reverting a legitimate
# unlock that immediately follows our own lock drive).
_SELF_COMMAND_RULE_PREFIX = "command:"

# HA-reported states while a Z-Wave/Zigbee deadbolt's motor is mid-throw.
# These are neither "locked" nor "unlocked" but are NOT the same as an
# untrusted/unknown state: the bolt is actively completing a command we (or
# the user) just issued. Field data for lock.back_door: unlock transitions
# normally complete in 0.5-2.0s, but one observed transition took 7.69s —
# long enough for a 5s poll to land mid-throw and, without this exemption,
# be classified untrusted_state and drive the just-completed unlock back
# closed on both sides.
#
# Deliberately EXCLUDED: "jammed", "opening", "open". These are not
# in-flight completions of a command this app or the user just issued —
# "jammed" in particular is a genuine mechanical fault and MUST continue to
# fail closed via the untrusted_state path. Do not "complete" this set to
# include them.
_HA_TRANSITIONAL_STATES = frozenset({"unlocking", "locking"})

# Bound on how long a transitional HA reading is treated as merely
# in-flight rather than untrusted. An entity still transitional after this
# many seconds is no longer "mid-throw" — it falls through to the existing
# untrusted_state fail-closed path exactly as before this exemption existed.
_HA_TRANSITION_GRACE = 30.0


@dataclass(frozen=True)
class _HubDriveResult:
    """Outcome tied to the exact Access client that accepted the write."""

    state: str
    authoritative_relay: bool


class HubSyncManager:
    """
    Polls opted-in HA lock entities and converges their paired Access
    hubs to the lock state. Driven by a supervised loop in main.py
    calling :meth:`poll_once` every :data:`POLL_INTERVAL` seconds.
    """

    # Poll cadence for the main.py loop — bounds reaction latency (the
    # app has no HA websocket).
    POLL_INTERVAL = 5.0

    def __init__(
        self,
        db: Database,
        ha_client_getter: Callable[[], Any],
        access_client_getter: Callable[[], Any],
        on_hub_state: Optional[Callable[[str, str], None]] = None,
        lockdown_getter: Optional[Callable[[], bool]] = None,
        camera_map_getter: Optional[Callable[[], dict]] = None,
        command_lock: Optional[asyncio.Lock] = None,
        relock_manager_getter: Optional[Callable[[], Any]] = None,
        entity_command_locks: dict[str, asyncio.Lock] | None = None,
    ) -> None:
        # Clients are fetched lazily via getters — same rationale as
        # RelockManager: credential updates from Settings swap the client
        # objects and the getters transparently pick up the new ones.
        # on_hub_state(device_id, state) refreshes the in-memory
        # lock_states cache after a hub is driven. lockdown_getter
        # returns the auth engine's current lockdown flag.
        # camera_map_getter returns the live camera_id→location_id map
        # (app.state.camera_to_location) for protect_doorbell pairings.
        self._db = db
        self._get_ha = ha_client_getter
        self._get_access = access_client_getter
        self._on_hub_state = on_hub_state
        self._lockdown_getter = lockdown_getter
        self._get_camera_map = camera_map_getter
        # Lazily fetched RelockManager. Used only by the opt-in
        # ``relock_on_ha_origin`` feature: a genuine HA-origin unlock edge on a
        # synced lock schedules a durable time-bounded re-lock through it.
        self._get_relock_manager = relock_manager_getter
        self._command_lock = command_lock or asyncio.Lock()
        self._entity_command_locks = (
            entity_command_locks
            if entity_command_locks is not None
            else {}
        )
        self._poll_lock = asyncio.Lock()
        # ``enforce_lockdown`` sets this before waiting for ``_poll_lock``.
        # A normal pass that already owns the lock observes it between remote
        # operations and during retry waits, then yields promptly so incident
        # enforcement is not queued behind minutes of unrelated retries.
        self._urgent_lockdown = asyncio.Event()
        self._urgent_lockdown_waiters = 0
        # entity_id → last state the paired hub is known to match. Absent
        # key = not yet converged (fresh enable / restart / post-suspend).
        self._applied: dict[str, str] = {}
        # Pairing is part of desired state. Remember both its stable device-id
        # signature and the full rows used for the last successful convergence
        # so a topology/settings change can reset removed hubs before opening
        # newly paired ones, even when the HA state itself did not change.
        self._pairing_signature: dict[str, tuple[str, ...]] = {}
        self._paired_hubs: dict[str, list[dict]] = {}
        # entity_id → monotonic deadline before which we skip retrying
        self._backoff_until: dict[str, float] = {}
        # entities whose current failing change already fired the
        # failure event (avoid re-notifying every backoff cycle)
        self._failure_notified: set[str] = set()
        # Hard-rejection tracking for the locked direction. ``_last_drive_hard``
        # carries the classification of the most recent _drive_hub failure for
        # an eid (reset before each bidirectional drive); ``_hard_reject_state``
        # holds (signature, consecutive_count) so a *repeated* permanent
        # rejection can be spaced onto _FAILURE_BACKOFF without ever stopping.
        self._last_drive_hard: dict[str, str] = {}
        self._hard_reject_state: dict[str, tuple[str, int]] = {}
        # eid → last logged failure signature so a persistent fault logs once at
        # its natural level (exception/warning) then drops to debug until a
        # convergence re-arms it. Keeps a removed endpoint from flooding logs.
        self._drive_log_signature: dict[str, str] = {}
        self._observe_log_signature: dict[str, str] = {}
        # Flap damping state: last drive time and the recent drive
        # timestamps within the flap window.
        self._last_applied_at: dict[str, float] = {}
        self._apply_times: dict[str, list[float]] = {}
        self._suspended_until: dict[str, float] = {}
        # Entities whose paired hub has been explicitly reset during the
        # current lockdown. This prevents repeated reset traffic on every
        # poll while still forcing a one-time fail-safe reset when lockdown
        # begins, including when the hub had previously been held open.
        self._lockdown_reset: set[str] = set()
        # entity_id → hub rows under app-owned persistent Access rules. Open
        # and closed overrides are tracked separately: keep_unlock must first
        # fail safe to keep_lock after an uncertain restart, while keep_lock
        # must later be replaced so it cannot suppress future schedules.
        self._held_open: dict[str, list[dict]] = {}
        self._held_locked: dict[str, list[dict]] = {}
        # entity_id → hubs that still need to be driven back to reset
        # after their lock left the synced set; retried with backoff.
        self._pending_release: dict[str, list[dict]] = {}
        self._release_backoff: dict[str, float] = {}
        self._recovery_complete = False
        # True once THIS process resolved prior-run ownership (recover(), or
        # the _poll_once fallback that fail-safes it). shutdown() may only
        # preserve holds afterwards: a shutdown on the failed-startup path
        # must not launder an unclean exit's holds into a clean marker.
        self._lifecycle_recovered = False
        self._lockdown_unresolved: set[str] = set()
        self._fail_safe_reset_eids: set[str] = set()
        # entity_id → monotonic time first observed reporting a transitional
        # HA state (unlocking/locking — bolt mid-throw). Bounds
        # _HA_TRANSITION_GRACE; cleared as soon as a valid locked/unlocked
        # state is observed for that entity. Never consulted for an entity
        # already in _fail_safe_reset_eids — an active incident is never
        # paused by a transitional reading.
        self._ha_transition_started: dict[str, float] = {}
        # Bidirectional origin tracking. These observations are persisted only
        # after both sides are confirmed, allowing a restart to distinguish a
        # new HA-only change from a new Access-only change without confusing an
        # Access-origin schedule with an app-owned keep-unlock override.
        self._last_ha_observed: dict[str, str] = {}
        self._last_access_observed: dict[str, str] = {}
        self._last_access_rule: dict[str, str] = {}
        self._last_converged: dict[str, str] = {}
        self._sync_state_loaded = False
        # A remote Access unlock is momentary. While its durable HA relock is
        # live, do not echo HA's temporary unlocked state back as keep_unlock.
        self._access_momentary_until: dict[str, float] = {}
        # entity_id → monotonic deadline before which an observed HA unlock edge
        # is known to be app-initiated (manual dashboard Unlock, buzz,
        # device-auth, or remote). ``relock_on_ha_origin`` skips scheduling a
        # durable re-lock while this is live so it only fires for genuinely
        # external (thumb-turn / HA-automation) unlocks.
        self._app_initiated_until: dict[str, float] = {}
        # Event hints reduce latency. They are never trusted as proof of an
        # unsafe open; reconciliation still performs authenticated readback.
        self._dirty_locations: set[str] = set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def poll_once(self) -> int:
        """Serialize and execute one desired-state convergence pass."""
        async with self._poll_lock:
            return await self._poll_once()

    @property
    def lockdown_unresolved(self) -> tuple[str, ...]:
        """Entity ids whose hubs are not yet confirmed reset in lockdown."""
        return tuple(sorted(self._lockdown_unresolved))

    @property
    def fail_safe_pending(self) -> tuple[str, ...]:
        """Entity ids currently held by the locked-wins fail-safe latch.

        A non-empty tuple means bidirectional sync is forcing that pair locked
        (reverting any unlock) until both sides are confirmed/observed locked.
        Surfaced in ``/api/health`` so a stuck latch is visible rather than
        silently reverting unlocks. Matches ``lockdown_unresolved`` scope
        handling: it already exposes entity IDs to every health scope.
        """
        return tuple(sorted(self._fail_safe_reset_eids))

    @staticmethod
    def is_access_state_event(event_type: str) -> bool:
        """Return whether an Access event can change a persistent door rule."""
        return event_type in _ACCESS_STATE_EVENTS

    def mark_access_momentary(self, entity_id: str, duration: float) -> None:
        """Suppress HA→Access echo for an Access-origin momentary unlock.

        The caller must first persist the matching HA relock. This marker is
        intentionally in memory: after a crash the durable relock is restored,
        while startup conflict handling remains locked-wins.

        A momentary lease is also app-initiated for the same window, so the
        opt-in ``relock_on_ha_origin`` feature never double-schedules a re-lock
        for a buzz / device-auth / remote unlock that already owns its timer.
        """
        window = time.monotonic() + max(0.0, float(duration))
        self._access_momentary_until[entity_id] = window
        self._app_initiated_until[entity_id] = max(
            self._app_initiated_until.get(entity_id, 0.0), window
        )

    def mark_app_initiated_unlock(
        self, entity_id: str, ttl: float = 15.0
    ) -> None:
        """Mark an imminent HA unlock as app-initiated for ``ttl`` seconds.

        Used by the manual dashboard Unlock (a deliberate hold-open that cancels
        pending re-locks) so ``relock_on_ha_origin`` does not observe that HA
        edge as an external thumb-turn. The short TTL covers the 5s poll edge
        without leaving a genuine later external unlock uncovered.
        """
        self._app_initiated_until[entity_id] = (
            time.monotonic() + max(0.0, float(ttl))
        )

    async def reconcile_location(
        self, location_id: str, event_type: str | None = None
    ) -> int:
        """Immediately reconcile a location after an Access rule event.

        Event payloads are only wake-up hints. In particular, an activate/start
        event cannot unlock HA until the current rule and door state have been
        read back from the authenticated, site-bound Access client.
        """
        if not location_id:
            return 0
        if event_type and event_type not in _ACCESS_STATE_EVENTS:
            return 0
        if location_id in self._dirty_locations:
            return 0
        self._dirty_locations.add(location_id)
        try:
            return await self.poll_once()
        finally:
            self._dirty_locations.discard(location_id)

    async def recover(self) -> int:
        """Fail-safe durable persistent-rule ownership after startup.

        This deliberately needs only the Access client.  Persisted rows are
        merged into the in-memory release queue, then every hub is held locked.
        A failed or unavailable close leaves both the database row and queue in
        place for the normal poll loop to retry.  During a persisted lockdown
        the same pass also closes every currently synced pairing without
        consulting Home Assistant.

        The one exception is a hold named by a clean-shutdown marker: a
        graceful shutdown deliberately left that keep_unlock in place, and it
        is re-adopted instead of closed — but only outside lockdown, only for
        a lock still opted into ``preserve_hold_on_restart``, and only after
        readback proves HA still reports the deadbolt unlocked. HA being
        unavailable at this point simply fails closed.

        Returns the number of confirmed close commands.
        """
        async with self._poll_lock:
            await self._load_persisted_sync_state()
            await self._load_persisted_holds()
            self._recovery_complete = True
            self._lifecycle_recovered = True
            lockdown_active = self._in_lockdown()
            # Always consumed (single-use), even when lockdown ignores it.
            marker_eids = await self._consume_clean_shutdown_marker()
            recovered_eids = (
                set(self._held_open)
                | set(self._held_locked)
                | set(self._pending_release)
            )
            all_locks: Optional[list[dict]] = None
            if recovered_eids:
                # Resolve the current pairing too: a topology change may have
                # added location data or another hub after the durable row was
                # written. The held+resolved union must all be safe before this
                # entity is considered reset for the current incident. A failed
                # lookup must not abort the fail-safe close below (the held
                # rows are already in memory) — and with no rows to prove the
                # opt-in, nothing is preservable either.
                try:
                    all_locks = await self._db.get_all_locks(
                        include_hidden=True
                    )
                except Exception:
                    _LOGGER.exception(
                        "Hub sync: lock lookup failed during recovery"
                    )
            preserved: set[str] = set()
            if marker_eids and not lockdown_active and all_locks is not None:
                preserved = await self._preserve_clean_holds(
                    marker_eids & recovered_eids, all_locks
                )
            for eid in preserved:
                # The physical keep_unlock never went away; re-adopt it as the
                # converged open state so the poll loop keeps following.
                self._pending_release.pop(eid, None)
                self._applied[eid] = "unlocked"
                self._last_ha_observed[eid] = "unlocked"
                self._last_access_observed[eid] = "unlocked"
            recovered_eids -= preserved
            # An unclean exit left an app-owned open override behind. Closing it
            # must use persistent keep_lock until HA is trustworthy again; a
            # plain reset could immediately resume an active unlock schedule.
            self._fail_safe_reset_eids.update(recovered_eids)
            for eid in recovered_eids:
                await self._queue_release(eid, all_locks)
            self._release_backoff.clear()
            reset_count = await self._process_pending_releases(
                force=True, enforcing_lockdown=lockdown_active
            )
            if lockdown_active:
                for eid in recovered_eids:
                    if eid not in self._pending_release:
                        self._lockdown_reset.add(eid)
                        self._applied[eid] = "unlocked"
                reset_count += await self._poll_once(enforcing_lockdown=True)
            return reset_count

    async def shutdown(self) -> int:
        """Best-effort release of every app-owned rule before shutdown.

        Non-lockdown shutdown restores native schedules. During lockdown it
        retains keep_lock. Failed commands remain durable for :meth:`recover`.

        Holds on locks opted into ``preserve_hold_on_restart`` are the
        exception: a graceful, non-incident stop leaves their keep_unlock
        physically in place and names them in a single-use clean-shutdown
        marker, so a Supervisor stop/start pair (every backup, with
        ``backup: cold``) does not re-lock a door deliberately held open.
        :meth:`recover` validates the marker with readback before re-adopting.
        """
        async with self._poll_lock:
            await self._load_persisted_sync_state()
            # A release already pending at shutdown entry means something is
            # actively being reset — never preservable. Snapshot before the
            # durable-row merge below adds the healthy holds to the queue.
            pending_before = set(self._pending_release)
            await self._load_persisted_holds()
            self._recovery_complete = True
            try:
                all_locks = await self._db.get_all_locks(include_hidden=True)
            except Exception:
                _LOGGER.exception("Hub sync: lock lookup failed during shutdown")
                all_locks = None
            lockdown_active = self._in_lockdown()
            candidates = (
                set(self._applied)
                | set(self._held_open)
                | set(self._held_locked)
                | set(self._pending_release)
            )
            preserved = self._preservable_holds(
                candidates - pending_before,
                all_locks,
                lockdown_active=lockdown_active,
            )
            # The marker is what recover() trusts. If it cannot be written,
            # the holds are released like any other shutdown (fail closed).
            preserved = await self._write_clean_shutdown_marker(preserved)
            for eid in candidates - preserved:
                await self._queue_release(eid, all_locks)
            for eid in preserved:
                # Drop the durable rows the merge queued: a preserved hold
                # deliberately keeps both its physical rule and its
                # hub_sync_holds ownership row.
                self._pending_release.pop(eid, None)
                _LOGGER.info(
                    "Hub sync: preserving keep_unlock hold for %s across "
                    "graceful shutdown",
                    eid,
                )
            self._release_backoff.clear()
            if not lockdown_active:
                # A graceful, non-incident stop deliberately returns native
                # schedule ownership instead of carrying keep_lock forward.
                self._fail_safe_reset_eids.difference_update(
                    self._pending_release
                )
            return await self._process_pending_releases(
                force=True,
                enforcing_lockdown=lockdown_active,
            )

    async def enforce_lockdown(self) -> int:
        """Immediately fail-safe synced hubs when lockdown is enabled."""
        self._urgent_lockdown_waiters += 1
        self._urgent_lockdown.set()
        try:
            async with self._poll_lock:
                # A lockdown callback may run before startup recovery has had an
                # opportunity to rebuild in-memory ownership.
                await self._load_persisted_holds()
                self._recovery_complete = True
                # A new incident must earn a fresh physical reset even if lockdown
                # toggled off/on between scheduled polls.
                self._lockdown_reset.clear()
                held_eids = list(
                    set(self._held_open)
                    | set(self._held_locked)
                    | set(self._pending_release)
                )
                all_locks = await self._db.get_all_locks(include_hidden=True)
                for eid in held_eids:
                    await self._queue_release(eid, all_locks=all_locks)
                reset_count = await self._process_pending_releases(
                    force=True, enforcing_lockdown=True
                )
                for eid in held_eids:
                    if eid not in self._pending_release:
                        self._lockdown_reset.add(eid)
                        self._applied[eid] = "unlocked"
                # Also reset every opted-in pairing, including after a cold start
                # where in-memory held-open tracking is empty. HA state is not
                # needed for the safe (reset) direction.
                reset_count += await self._poll_once(enforcing_lockdown=True)
                if self._lockdown_unresolved:
                    raise RuntimeError(
                        "Lockdown hub reset remains unresolved for: "
                        + ", ".join(sorted(self._lockdown_unresolved))
                    )
                return reset_count
        finally:
            self._urgent_lockdown_waiters -= 1
            if self._urgent_lockdown_waiters == 0:
                self._urgent_lockdown.clear()

    async def _poll_once(self, *, enforcing_lockdown: bool = False) -> int:
        """
        One sync pass over all opted-in locks. Returns the number of
        state changes successfully applied to hubs.
        """
        if self._urgent_lockdown.is_set() and not enforcing_lockdown:
            return 0

        if not self._sync_state_loaded:
            await self._load_persisted_sync_state()

        # A failed one-shot startup recovery must not permanently lose durable
        # ownership. Retry the read on every poll until it succeeds; loaded
        # rows enter the normal pending-release retry path immediately.
        if not self._recovery_complete:
            await self._load_persisted_sync_state()
            await self._load_persisted_holds()
            self._recovery_complete = True
            # This fallback fail-safes prior-run ownership just like
            # recover(), so holds established after it are preservable.
            self._lifecycle_recovered = True
            recovered_eids = (
                set(self._held_open)
                | set(self._held_locked)
                | set(self._pending_release)
            )
            # This fallback is used when explicit startup recovery was skipped
            # or interrupted. Never restore a possibly active schedule before
            # first replacing an untrusted keep_unlock with keep_lock.
            self._fail_safe_reset_eids.update(recovered_eids)
            await self._process_pending_releases(
                force=True, enforcing_lockdown=enforcing_lockdown
            )

        # include_hidden so a just-hidden lock's row is still available
        # for hub resolution when we release its held-open hub below.
        all_locks = await self._db.get_all_locks(include_hidden=True)
        synced_rows = [
            lock for lock in all_locks
            if lock.get("type") == "ha_external"
            and lock.get("sync_hub_state")
            and lock.get("entity_id")
            and not lock.get("hidden")
        ]
        # Multiple legacy rows can name the same HA entity. Treat them as one
        # desired-state owner whose pairing is the union of every row, so HA is
        # sampled once and no second row is hidden by the state fast-path.
        synced = self._group_synced_locks(synced_rows)
        current_eids = {lock["entity_id"] for lock in synced}
        lifecycle_lockdown = enforcing_lockdown or self._in_lockdown()

        # Entities that left the opted-in set (option off / hidden /
        # deleted): release any hub we hold open, then drop tracking so
        # re-enabling later re-converges from scratch.
        for eid in (
            set(self._applied)
            | set(self._held_open)
            | set(self._held_locked)
            | set(self._pairing_signature)
            | set(self._paired_hubs)
            | set(self._last_converged)
        ):
            if eid not in current_eids:
                if lifecycle_lockdown:
                    # Ownership for a removed/disabled pairing remains closed
                    # for the incident. Releasing or dropping it here could
                    # resume a schedule during lockdown; the first post-
                    # lockdown poll performs the deliberate release instead.
                    continue
                await self._queue_release(eid, all_locks)
                await self._clear_persisted_convergence(eid)
                self._drop_tracking(eid)
        self._failure_notified &= current_eids

        await self._process_pending_releases(
            enforcing_lockdown=enforcing_lockdown
        )

        if self._urgent_lockdown.is_set() and not enforcing_lockdown:
            return 0

        # Resolve every logical pairing once per pass. The same snapshot feeds
        # pairing-change cleanup, shared-hub conflict detection, and actuation;
        # otherwise a concurrent topology refresh could make those stages
        # disagree about which physical hub they own.
        resolved_results = await asyncio.gather(
            *(self._resolve_hub_locks(lock) for lock in synced),
            return_exceptions=True,
        )
        resolved_by_eid: dict[str, list[dict]] = {}
        for lock, resolved in zip(synced, resolved_results):
            eid = lock["entity_id"]
            if isinstance(resolved, BaseException):
                _LOGGER.error(
                    "Hub sync: pairing resolution failed for %s: %s", eid, resolved
                )
                if self._held_open.get(eid) or self._held_locked.get(eid):
                    await self._queue_release(eid, all_locks=None)
                continue
            resolved_by_eid[eid] = resolved
            self._prepare_pairing_change(eid, resolved)

        # A removed pairing must be reset before a newly paired hub can be
        # held open. Failures stay in ``_pending_release`` and the unsafe
        # direction below is suppressed until a later retry succeeds.
        await self._process_pending_releases(
            enforcing_lockdown=enforcing_lockdown
        )

        if self._urgent_lockdown.is_set() and not enforcing_lockdown:
            return 0

        lockdown_active = lifecycle_lockdown
        if not lockdown_active:
            # Lockdown uses persistent keep_lock so a schedule cannot reopen the
            # door during an incident. Retain a release marker after the mode is
            # lifted; normal reconciliation first confirms both sides locked,
            # then replaces keep_lock with schedule-aware lock_now. That leaves
            # this interval closed while allowing future schedules to run.
            self._fail_safe_reset_eids.update(self._lockdown_reset)
            self._lockdown_reset.clear()

        # During lockdown, continuously verify the authenticated Access
        # rule/relay and HA state. A direct HA command or Access schedule event
        # can occur after initial enforcement; a one-shot marker must never
        # become a bypass. Unreadable state is reasserted fail-closed.
        if lockdown_active:
            applied_count = 0
            for lock in synced:
                eid = lock["entity_id"]
                hubs = resolved_by_eid.get(eid)
                if hubs is None:
                    continue
                if (
                    eid in self._lockdown_reset
                    and await self._lockdown_pair_confirmed(lock, hubs)
                ):
                    continue
                self._lockdown_reset.discard(eid)
                _LOGGER.warning(
                    "Hub sync: LOCKDOWN forcing paired hub(s) for %s closed",
                    lock.get("name", eid),
                )
                access_safe = await self._apply_state(
                    lock,
                    "locked",
                    hubs=hubs,
                    enforcing_lockdown=True,
                    fail_safe=True,
                )
                ha_safe = True
                ha = self._get_ha()
                if self._method(ha, "lock") is not None:
                    ha_safe = await self._drive_ha_state(
                        lock, "locked", fail_safe=True
                    )
                access = self._get_access()
                pair_confirmed = bool(
                    access_safe
                    and ha_safe
                    and (
                        # Compatibility-only injected clients do not expose
                        # readback at all; preserve their acknowledgement
                        # contract. Production AccessClient always exposes the
                        # bidirectional methods and must pass the authoritative
                        # rule/relay re-read below.
                        not self._supports_bidirectional_access(access)
                        or await self._lockdown_pair_confirmed(lock, hubs)
                    )
                )
                if pair_confirmed:
                    self._lockdown_reset.add(eid)
                    # Conservative observed baseline: after lockdown lifts, an
                    # HA entity still reporting unlocked must not reopen the
                    # hub. A later locked observation re-arms normal following.
                    self._applied[eid] = "unlocked"
                    self._backoff_until.pop(eid, None)
                    self._failure_notified.discard(eid)
                    self._clear_incident_signatures(eid)
                    applied_count += 1
            self._lockdown_unresolved = (
                current_eids.difference(self._lockdown_reset)
                | set(self._pending_release)
            )
            return applied_count
        self._lockdown_unresolved.clear()

        conflict_eids = await self._fail_safe_shared_hub_owners(
            synced, resolved_by_eid=resolved_by_eid
        )
        if self._urgent_lockdown.is_set() and not enforcing_lockdown:
            return 0
        if conflict_eids:
            # A hub with multiple independent desired-state owners is
            # ambiguous. Never follow any of them open; keep retrying reset
            # until the configuration is made one-to-one.
            synced = [
                lock for lock in synced
                if lock["entity_id"] not in conflict_eids
            ]

        # Drop detection/releases above need only Access and must run while HA
        # is offline. Live desired-state convergence below does require HA.
        ha = self._get_ha()
        if ha is None or not getattr(ha, "connected", False):
            # A persistent hold-open is a lease on HA's desired state. Once HA
            # is unavailable, that lease has no trustworthy owner: reset every
            # hub we may hold instead of leaving a door open indefinitely.
            access_for_fail_safe = self._get_access()
            bidirectional_fail_safe = self._supports_bidirectional_access(
                access_for_fail_safe
            )
            for lock in synced:
                eid = lock["entity_id"]
                if bidirectional_fail_safe:
                    self._fail_safe_reset_eids.add(eid)
                    hubs = resolved_by_eid.get(eid)
                    if hubs is not None:
                        await self._apply_state(
                            lock, "locked", hubs=hubs, fail_safe=True
                        )
                elif (
                    self._held_open.get(eid)
                    or self._applied.get(eid) == "unlocked"
                ):
                    self._fail_safe_reset_eids.add(eid)
                    await self._queue_release(eid, all_locks, lock)
            await self._process_pending_releases(
                force=True, enforcing_lockdown=enforcing_lockdown
            )
            return 0

        poll_time = time.monotonic()
        # Always observe HA state. Backoff, flap suspension, and damping are
        # protections against repeated unsafe hold-open commands; they must
        # never delay a safe reset after an ambiguous/partial apply.
        candidates = list(synced)
        fetched_states = await asyncio.gather(
            *(ha.get_entity_state(lock["entity_id"]) for lock in candidates),
            return_exceptions=True,
        )
        access = self._get_access()
        bidirectional = self._supports_bidirectional_access(access)
        if bidirectional:
            fetched_access = await asyncio.gather(
                *(
                    self._observe_access_side(
                        access,
                        resolved_by_eid.get(lock["entity_id"], []),
                        entity_id=lock["entity_id"],
                    )
                    for lock in candidates
                ),
                return_exceptions=True,
            )
        else:
            fetched_access = [None] * len(candidates)

        if self._urgent_lockdown.is_set() and not enforcing_lockdown:
            return 0

        applied_count = 0
        for lock, state, access_observation in zip(
            candidates, fetched_states, fetched_access
        ):
            eid = lock["entity_id"]
            if self._urgent_lockdown.is_set() and not enforcing_lockdown:
                return applied_count
            now = time.monotonic()
            if bidirectional:
                hubs = resolved_by_eid.get(eid, [])
                if isinstance(access_observation, BaseException):
                    _LOGGER.error(
                        "Hub sync: Access observation raised for %s: %s",
                        eid,
                        access_observation,
                    )
                    access_state, access_rule, schedule_active, access_relay_state = (
                        None,
                        f"error:{type(access_observation).__name__}",
                        False,
                        None,
                    )
                else:
                    (
                        access_state,
                        access_rule,
                        schedule_active,
                        access_relay_state,
                    ) = access_observation
                safe_ha_state = None if isinstance(state, BaseException) else state
                applied_count += await self._reconcile_bidirectional(
                    lock,
                    safe_ha_state,
                    access_state,
                    access_rule,
                    schedule_active,
                    access_relay_state,
                    hubs,
                )
                continue
            if isinstance(state, BaseException):
                _LOGGER.error(
                    "Hub sync: state fetch raised for %s: %s", eid, state
                )
                if self._held_open.get(eid) or self._applied.get(eid) == "unlocked":
                    self._fail_safe_reset_eids.add(eid)
                    await self._queue_release(eid, all_locks, lock)
                continue
            if state not in ("locked", "unlocked"):
                if self._held_open.get(eid) or self._applied.get(eid) == "unlocked":
                    _LOGGER.warning(
                        "Hub sync: HA state %r for %s is not trustworthy; "
                        "resetting owned hold(s)",
                        state,
                        eid,
                    )
                    self._fail_safe_reset_eids.add(eid)
                    await self._queue_release(eid, all_locks, lock)
                continue

            prev = self._applied.get(eid)
            needs_safe_reset = bool(
                state == "locked"
                and (
                    self._held_open.get(eid)
                    or self._held_locked.get(eid)
                    or eid in self._fail_safe_reset_eids
                )
            )

            if state == prev and not needs_safe_reset:
                # Converged. Any failing change self-reverted — clear the
                # notify flag so the NEXT failure alerts again.
                self._failure_notified.discard(eid)
                continue

            if state == "unlocked":
                # A pending safe release owns this entity; never reopen until
                # that reset is confirmed. Backoff/suspension/damping apply
                # only to the unsafe direction.
                if eid in self._pending_release:
                    continue
                if self._suspended_until.get(eid, 0.0) > poll_time:
                    continue
                if self._backoff_until.get(eid, 0.0) > poll_time:
                    continue
                last_applied_at = self._last_applied_at.get(eid)
                if (
                    last_applied_at is not None
                    and now - last_applied_at < _MIN_APPLY_INTERVAL
                ):
                    _LOGGER.debug(
                        "Hub sync: hold-open for %s deferred (min interval)", eid
                    )
                    continue

                recent = [
                    t for t in self._apply_times.get(eid, ())
                    if now - t <= _FLAP_WINDOW
                ]
                self._apply_times[eid] = recent
                if len(recent) >= _FLAP_THRESHOLD:
                    await self._suspend_flapping(lock)
                    continue

            hubs = resolved_by_eid.get(eid)
            if hubs is None:
                self._backoff_until[eid] = time.monotonic() + _FAILURE_BACKOFF
                continue

            if prev is None:
                _LOGGER.info(
                    "Hub sync: converging %s hub(s) to current state %r",
                    lock.get("name", eid), state,
                )
            else:
                _LOGGER.info(
                    "Hub sync: %s changed %s → %s — syncing paired hub(s)",
                    lock.get("name", eid), prev, state,
                )
            if await self._apply_state(
                lock,
                state,
                hubs=hubs,
                enforcing_lockdown=enforcing_lockdown,
            ):
                self._applied[eid] = state
                if state == "locked":
                    self._fail_safe_reset_eids.discard(eid)
                self._backoff_until.pop(eid, None)
                self._failure_notified.discard(eid)
                applied_count += 1
            else:
                # Keep the old applied state so the change is retried
                # after the backoff — the hub must converge.
                self._backoff_until[eid] = time.monotonic() + _FAILURE_BACKOFF

        # Invalid/unknown states above may have queued fail-safe resets.
        await self._process_pending_releases(
            force=True, enforcing_lockdown=enforcing_lockdown
        )

        return applied_count

    # ------------------------------------------------------------------
    # Internal — state application
    # ------------------------------------------------------------------

    @staticmethod
    def _method(obj: Any, name: str) -> Any:
        """Return a real/explicit method without MagicMock auto-children.

        The production client exposes bound coroutine methods. Older unit
        fixtures use an unspecced MagicMock, where plain getattr fabricates a
        callable for every name; treating those as capabilities would silently
        enable bidirectional behavior in legacy tests and deployments using an
        older injected client.
        """
        if obj is None:
            return None
        explicit = vars(obj).get(name)
        if explicit is not None:
            return explicit
        class_attr = getattr(type(obj), name, None)
        if class_attr is None:
            return None
        method = getattr(obj, name, None)
        if inspect.iscoroutinefunction(class_attr) or callable(method):
            return method
        return None

    def _supports_bidirectional_access(self, access: Any) -> bool:
        return bool(
            self._method(access, "get_lock_rule")
            and self._method(access, "get_door_state")
        )

    @staticmethod
    async def _invoke_access_command(
        command: Callable[..., Awaitable[Any]],
        device_id: str,
        location_id: str | None,
        on_written: Callable[[], None],
    ) -> Any:
        """Call an Access lock command, passing ``on_written`` when supported.

        The production client accepts an ``on_written`` hook so the caller can
        release the physical-command barrier after the write and before the
        multi-second relay confirm. Lightweight test doubles and older injected
        clients may not; those are called without it (the barrier is then simply
        released when the whole command returns, which is harmless because they
        do not perform a long confirm).
        """
        supports = False
        try:
            # Require an *explicit* ``on_written`` parameter. A bare
            # ``AsyncMock`` reports ``(*args, **kwargs)``; a restrictive
            # side_effect behind it would then reject the unexpected kwarg, so a
            # generic VAR_KEYWORD is deliberately not treated as support.
            supports = "on_written" in inspect.signature(command).parameters
        except (TypeError, ValueError):
            supports = False
        if supports:
            return await command(
                device_id, location_id=location_id, on_written=on_written
            )
        return await command(device_id, location_id=location_id)

    @staticmethod
    def _access_available(access: Any) -> bool:
        if access is None:
            return False
        connected = bool(vars(access).get("connected", False))
        if isinstance(getattr(type(access), "connected", None), property):
            connected = bool(access.connected)
        open_api = bool(vars(access).get("open_api_configured", False))
        if isinstance(
            getattr(type(access), "open_api_configured", None), property
        ):
            open_api = bool(access.open_api_configured)
        return connected or open_api

    @staticmethod
    def _has_authoritative_relay_state(access: Any) -> bool:
        """Return whether ``get_door_state`` reads a physical Open API relay.

        The legacy/private client implements the same method by deriving state
        from the persistent rule. That remains useful for normal convergence,
        but it must never be mistaken for independent physical evidence when
        releasing a fail-safe latch or acknowledging lockdown safety.
        """
        if access is None:
            return False
        open_api = bool(vars(access).get("open_api_configured", False))
        if isinstance(
            getattr(type(access), "open_api_configured", None), property
        ):
            open_api = bool(access.open_api_configured)
        return open_api

    @staticmethod
    def _group_synced_locks(locks: list[dict]) -> list[dict]:
        """Collapse duplicate HA entity rows into one logical sync owner."""
        grouped: dict[str, dict] = {}
        for lock in locks:
            eid = lock["entity_id"]
            logical = grouped.get(eid)
            if logical is None:
                logical = dict(lock)
                logical["_sync_rows"] = [lock]
                grouped[eid] = logical
            else:
                logical["_sync_rows"].append(lock)
        return list(grouped.values())

    @staticmethod
    def _is_self_command_rule(rule: str | None) -> bool:
        """Return whether ``rule`` is our own drive marker, not an observation.

        See :data:`_SELF_COMMAND_RULE_PREFIX`. Used to recognize a
        ``_last_access_rule`` baseline that _persist_convergence wrote from
        our own successful apply rather than a real Access readback.
        """
        return rule is not None and rule.startswith(_SELF_COMMAND_RULE_PREFIX)

    @staticmethod
    def _hub_signature(hubs: list[dict]) -> tuple[str, ...]:
        """Return a stable physical-device signature for a resolved pairing."""
        return tuple(sorted({
            str(hub["device_id"])
            for hub in hubs
            if hub.get("device_id")
        }))

    def _prepare_pairing_change(self, eid: str, current_hubs: list[dict]) -> None:
        """Queue removed hubs for reset and invalidate stale convergence.

        Unsafe ownership is already durable in ``hub_sync_holds``. This method
        only moves the matching in-memory rows into the release queue; the row
        is cleared later, and only after Access confirms the reset command.
        """
        current_signature = self._hub_signature(current_hubs)
        previous_signature = self._pairing_signature.get(eid)

        known_hubs: list[dict] = []
        self._append_unique_hubs(known_hubs, self._paired_hubs.get(eid, []))
        self._append_unique_hubs(known_hubs, self._held_open.get(eid, []))
        self._append_unique_hubs(known_hubs, self._held_locked.get(eid, []))
        # Durable owned rows may include a hub removed after the last confirmed
        # pairing. Keep that device in the stale set until its override is
        # explicitly released; the prior signature alone is not exhaustive.
        known_signature = tuple(sorted(
            set(previous_signature or ())
            | set(self._hub_signature(known_hubs))
        ))
        changed = (
            previous_signature is not None
            and previous_signature != current_signature
        )
        stale_ids = set(known_signature).difference(current_signature)
        if not changed and not stale_ids:
            return

        _LOGGER.warning(
            "Hub sync pairing changed for %s: %s → %s; resetting removed hubs",
            eid,
            known_signature,
            current_signature,
        )
        stale_hubs = [
            hub for hub in known_hubs
            if str(hub.get("device_id")) in stale_ids
        ]
        if stale_hubs:
            pending = self._pending_release.setdefault(eid, [])
            self._append_unique_hubs(pending, stale_hubs)
            self._release_backoff.pop(eid, None)

        # Even an expansion with no removed hubs must re-converge so the newly
        # paired device receives the current desired state.
        self._applied.pop(eid, None)
        self._pairing_signature.pop(eid, None)
        self._paired_hubs.pop(eid, None)
        self._backoff_until.pop(eid, None)
        self._last_applied_at.pop(eid, None)
        self._failure_notified.discard(eid)
        self._last_ha_observed.pop(eid, None)
        self._last_access_observed.pop(eid, None)
        self._last_access_rule.pop(eid, None)
        self._last_converged.pop(eid, None)
        # Sibling of the pop in _drop_tracking: a stale "first seen
        # transitional" timestamp must not survive a pairing change either,
        # or a re-observed transitional reading after the swap could reuse
        # an old start time and find its grace window already expired.
        self._ha_transition_started.pop(eid, None)
        # A pairing update during an active incident must earn a reset for the
        # newly resolved hubs; the old one-time lockdown acknowledgement only
        # covered the previous physical set.
        self._lockdown_reset.discard(eid)

    def _in_lockdown(self) -> bool:
        if self._lockdown_getter is None:
            return False
        try:
            return bool(self._lockdown_getter())
        except Exception:
            # Fail closed: if lockdown state can't be read, behave as if
            # lockdown is active — suppressing a hold-open is the safe
            _LOGGER.exception("Hub sync: lockdown getter raised — failing closed")
            return True

    async def _fail_safe_shared_hub_owners(
        self,
        synced: list[dict],
        *,
        resolved_by_eid: Optional[dict[str, list[dict]]] = None,
        enforcing_lockdown: bool = False,
    ) -> set[str]:
        """Reset and suppress entities that resolve to a shared Access hub."""
        if resolved_by_eid is None:
            resolved_results = await asyncio.gather(
                *(self._resolve_hub_locks(lock) for lock in synced),
                return_exceptions=True,
            )
            resolved_by_eid = {}
            for lock, resolved in zip(synced, resolved_results):
                if isinstance(resolved, BaseException):
                    _LOGGER.error(
                        "Hub sync: conflict resolution failed for %s: %s",
                        lock.get("entity_id"),
                        resolved,
                    )
                    continue
                resolved_by_eid[lock["entity_id"]] = resolved

        by_eid: dict[str, list[dict]] = {}
        owners: dict[str, set[str]] = {}
        for lock in synced:
            eid = lock["entity_id"]
            resolved = resolved_by_eid.get(eid)
            if resolved is None:
                continue
            by_eid[eid] = resolved
            for hub in resolved:
                owners.setdefault(hub["device_id"], set()).add(eid)

        conflict_devices = {
            device_id for device_id, eids in owners.items() if len(eids) > 1
        }
        conflict_eids = {
            eid
            for device_id in conflict_devices
            for eid in owners[device_id]
        }
        if not conflict_eids:
            return set()

        reset_hubs: dict[str, dict] = {}
        for eid in conflict_eids:
            for hub in by_eid.get(eid, []):
                reset_hubs[hub["device_id"]] = hub

        for hub in reset_hubs.values():
            if self._urgent_lockdown.is_set() and not enforcing_lockdown:
                return set()
            device_id = hub["device_id"]
            hub_name = hub.get("name", device_id)
            hub_owners = [
                eid
                for eid in conflict_eids
                if any(
                    item.get("device_id") == device_id
                    for item in by_eid.get(eid, [])
                )
            ]
            ownership_recorded = True
            for eid in hub_owners:
                self._fail_safe_reset_eids.add(eid)
                try:
                    await self._record_hub_state(
                        eid,
                        hub,
                        "locked",
                        persistent_lock=True,
                    )
                except Exception:
                    ownership_recorded = False
                    _LOGGER.exception(
                        "Could not persist shared-hub keep_lock ownership for %s",
                        hub_name,
                    )
            drove = await self._drive_hub(
                device_id,
                "locked",
                hub_name,
                eid=next(iter(hub_owners), None),
                location_id=hub.get("location_id"),
                enforcing_lockdown=enforcing_lockdown,
                fail_safe=ownership_recorded,
                force_transient=not ownership_recorded,
            )
            if not drove:
                _LOGGER.error("Could not fail-safe shared Access hub %s", hub_name)

        for eid in conflict_eids:
            if self._urgent_lockdown.is_set() and not enforcing_lockdown:
                return set()
            conflict_lock = next(
                (row for row in synced if row["entity_id"] == eid),
                None,
            )
            if (
                conflict_lock is not None
                and self._supports_bidirectional_access(self._get_access())
            ):
                await self._drive_ha_state(
                    conflict_lock, "locked", fail_safe=True
                )
            self._applied[eid] = "unlocked"
            if eid not in self._failure_notified:
                self._failure_notified.add(eid)
                lock = conflict_lock or {"name": eid}
                await self._notify_sync_failed(
                    eid,
                    lock.get("name", eid),
                    reason="shared_hub_conflict",
                )
        _LOGGER.error(
            "Hub sync suppressed %d entity(s): multiple HA locks resolve to "
            "the same Access hub",
            len(conflict_eids),
        )
        return conflict_eids

    async def _lockdown_pair_confirmed(
        self,
        lock: dict,
        hubs: list[dict],
    ) -> bool:
        """Re-read both sides before honoring a lockdown-safe marker."""
        access = self._get_access()
        if not self._supports_bidirectional_access(access):
            # Compatibility mode cannot prove a schedule or temporary rule did
            # not reopen the door, so periodically reassert keep_lock.
            return False
        observations = await asyncio.gather(
            *(self._observe_access_hub(access, hub) for hub in hubs),
            return_exceptions=True,
        )
        access_safe = all(
            not isinstance(item, BaseException)
            and item[0] == "locked"
            and item[1].get("type") == "keep_lock"
            and item[3] == "locked"
            for item in observations
        )
        if not access_safe:
            return False

        ha = self._get_ha()
        if (
            ha is None
            or not getattr(ha, "connected", False)
            or self._method(ha, "lock") is None
        ):
            # Access is the fail-safe physical boundary during HA outages and
            # for legacy test/compatibility clients without command methods.
            return True
        try:
            return await ha.get_entity_state(lock["entity_id"]) == "locked"
        except Exception:
            return False

    async def _observe_access_hub(
        self, access: Any, hub: dict, *, settle: bool = True
    ) -> tuple[str | None, dict, bool, str | None]:
        """Return effective intent plus separate authoritative relay state.

        ``settle=False`` takes a single read without the progressive
        relay-lag window; callers holding the physical-command barrier must
        use it so actuation latency on one hub cannot stall other doors.
        """
        get_rule = self._method(access, "get_lock_rule")
        get_state = self._method(access, "get_door_state")
        if get_rule is None or get_state is None:
            raise RuntimeError("Access client lacks lock-rule readback")
        device_id = hub["device_id"]
        location_id = hub.get("location_id")
        attempts = (len(_ACCESS_OBSERVE_DELAYS) + 1) if settle else 1
        for attempt in range(attempts):
            final = attempt + 1 >= attempts
            rule_result, door_state = await asyncio.gather(
                get_rule(device_id, location_id=location_id),
                get_state(device_id, location_id=location_id),
            )
            if not isinstance(rule_result, dict):
                raise ValueError("Access lock-rule response is not an object")
            rule_type = str(rule_result.get("type") or "").strip().lower()
            if rule_type not in (
                _ACCESS_OPEN_RULES | _ACCESS_CLOSED_RULES | _ACCESS_NATIVE_RULES
            ):
                raise ValueError(f"unknown Access lock-rule type {rule_type!r}")
            if door_state not in {"locked", "unlocked"}:
                raise ValueError(f"unknown Access door state {door_state!r}")
            # Access can publish its new schedule/hold rule several seconds
            # before the relay catches up (observed on current firmware after a
            # keep_unlock mirror). Give that normal actuation latency the full
            # progressive window to settle before classifying it inconsistent.
            # A genuinely unreadable/invalid read (rule or relay) still raises
            # immediately above and latches locked-wins on this same pass:
            # retrying a down hub for the whole window would stall the poll loop
            # ~5s per hub, and the momentary lock_now `reset`/no-relay case is
            # confirmed authoritatively on the command path, not here.
            if (
                rule_type in _ACCESS_OPEN_RULES
                and door_state == "locked"
                and not final
            ):
                await asyncio.sleep(_ACCESS_OBSERVE_DELAYS[attempt])
                continue
            break

        if rule_type in _ACCESS_OPEN_RULES:
            if door_state == "unlocked":
                effective = "unlocked"
            elif rule_type == "schedule":
                # First-person-in and freshly activating schedules can validly
                # report schedule+locked. Preserve the schedule and mirror the
                # conservative relay state instead of replacing it with
                # keep_lock.
                effective = "locked"
            else:
                effective = None
        elif rule_type in _ACCESS_CLOSED_RULES:
            # A credential buzz can briefly open the relay while persistent
            # intent remains closed. Never turn that pulse into HA unlock.
            effective = "locked"
        elif rule_type in _ACCESS_NATIVE_RULES:
            # The relay can briefly report unlocked for an ordinary credential
            # buzz while the persistent rule remains native/reset. That is not
            # a schedule/override intent and must not become an HA keep-open.
            # Access reports `schedule` when a persistent schedule is active.
            effective = "locked"
        else:  # pragma: no cover - exhaustive sets above
            effective = None
        return (
            effective,
            dict(rule_result),
            rule_type == "schedule",
            (
                door_state
                if self._has_authoritative_relay_state(access)
                else None
            ),
        )

    async def _observe_access_side(
        self,
        access: Any,
        hubs: list[dict],
        *,
        entity_id: str,
    ) -> tuple[str | None, str, bool, str | None]:
        """Observe all hubs as one logical Access side.

        Multi-hub disagreement or one malformed/unreadable row is ambiguous
        and therefore returns no state. The caller's locked-wins path handles
        the fail-safe action. The fourth return value is the raw relay state
        only when every hub provided authoritative, agreeing relay readback.
        """
        if not hubs:
            return None, "no-hubs", False, None
        if not self._access_available(access):
            return None, "disconnected", False, None
        results = await asyncio.gather(
            *(self._observe_access_hub(access, hub) for hub in hubs),
            return_exceptions=True,
        )
        states: list[str] = []
        relay_states: list[str] = []
        fingerprint_rows: list[dict] = []
        schedules: list[bool] = []
        invalid = False
        all_relays_authoritative = True
        for hub, result in zip(hubs, results):
            if isinstance(result, BaseException):
                invalid = True
                fingerprint_rows.append(
                    {
                        "device_id": hub.get("device_id"),
                        "error": type(result).__name__,
                    }
                )
                # Log once per distinct readback failure signature (which, for a
                # removed endpoint, carries the actionable message), then drop to
                # debug so a persistent 404 does not warn on every 5s poll. The
                # signature is re-armed on convergence. This is observe-side
                # noise control only — the drive-gate backoff is what actually
                # spaces retries; invalid state still latches fail-safe locked.
                signature = f"{type(result).__name__}:{result}"
                if self._observe_log_signature.get(entity_id) == signature:
                    _LOGGER.debug(
                        "Hub sync: Access readback failed for %s: %s",
                        hub.get("name", hub.get("device_id")),
                        result,
                    )
                else:
                    self._observe_log_signature[entity_id] = signature
                    _LOGGER.warning(
                        "Hub sync: Access readback failed for %s: %s",
                        hub.get("name", hub.get("device_id")),
                        result,
                    )
                continue
            state, rule, schedule_active, relay_state = result
            rule_type = str(rule.get("type") or "")
            device_id = hub.get("device_id")
            owns_open = any(
                item.get("device_id") == device_id
                for item in self._held_open.get(entity_id, [])
            )
            owns_locked = any(
                item.get("device_id") == device_id
                for item in self._held_locked.get(entity_id, [])
            )
            if (
                (owns_open and rule_type != "keep_unlock")
                or (owns_locked and rule_type != "keep_lock")
            ):
                # An authenticated Access/UI action replaced our persistent
                # rule. Clear only the ownership proven superseded; otherwise a
                # later restart would incorrectly reassert the old override.
                try:
                    await self._record_hub_state(entity_id, hub, "locked")
                except Exception as exc:
                    invalid = True
                    _LOGGER.warning(
                        "Hub sync: could not clear superseded override for %s: %s",
                        hub.get("name", device_id),
                        exc,
                    )
            fingerprint_rows.append(
                {"device_id": hub.get("device_id"), "rule": rule, "state": state}
            )
            if state is None:
                invalid = True
            else:
                states.append(state)
            if relay_state is None:
                all_relays_authoritative = False
            else:
                relay_states.append(relay_state)
            schedules.append(schedule_active)
        # Clearing superseded durable ownership does not prove the physical
        # incident is safe. In particular, an external schedule can replace
        # our keep_lock and immediately open the relay. The fail-safe latch is
        # released only by the authoritative both-sides-locked gate in
        # _reconcile_bidirectional.
        fingerprint = json.dumps(
            sorted(fingerprint_rows, key=lambda row: str(row.get("device_id"))),
            sort_keys=True,
            separators=(",", ":"),
        )
        if invalid or len(states) != len(hubs) or len(set(states)) != 1:
            return None, fingerprint, False, None
        authoritative_relay_state = (
            relay_states[0]
            if (
                all_relays_authoritative
                and len(relay_states) == len(hubs)
                and len(set(relay_states)) == 1
            )
            else None
        )
        return (
            states[0],
            fingerprint,
            bool(schedules and all(schedules)),
            authoritative_relay_state,
        )

    async def _drive_ha_state(
        self, lock: dict, state: str, *, fail_safe: bool = False
    ) -> bool:
        eid = str(lock["entity_id"])
        entity_lock = self._entity_command_locks.setdefault(
            f"ha:{eid}", asyncio.Lock()
        )
        async with entity_lock:
            return await self._drive_ha_state_coordinated(
                lock,
                state,
                fail_safe=fail_safe,
            )

    async def _drive_ha_state_coordinated(
        self, lock: dict, state: str, *, fail_safe: bool = False
    ) -> bool:
        """Command and confirm one HA lock without holding the barrier on reads."""
        eid = lock["entity_id"]
        lock_name = lock.get("name", eid)
        accepted = False
        ha = None
        ha_lease_stack = AsyncExitStack()
        await ha_lease_stack.__aenter__()
        try:
            async with self._command_lock:
                ha = self._get_ha()
                if ha is None or not getattr(ha, "connected", False):
                    return False
                if state == "unlocked" and self._in_lockdown():
                    return False
                await ha_lease_stack.enter_async_context(
                    ha_client_operation(ha)
                )
                command = ha.unlock if state == "unlocked" else ha.lock
                accepted = bool(await command(eid))
            if not accepted:
                return False
            for attempt in range(_HA_CONFIRM_ATTEMPTS):
                if await ha.get_entity_state(eid) == state:
                    return True
                if attempt < _HA_CONFIRM_ATTEMPTS - 1:
                    await asyncio.sleep(_HA_CONFIRM_DELAY)
        except Exception:
            _LOGGER.exception(
                "Hub sync: HA command/confirmation failed for %s (→ %s)",
                lock_name,
                state,
            )
        finally:
            await ha_lease_stack.aclose()
        if accepted:
            _LOGGER.error(
                "Hub sync: HA accepted %s for %s but state was not confirmed",
                state,
                lock_name,
            )
        if fail_safe:
            await self._notify_sync_failed(eid, lock_name, reason="ha_lock_unconfirmed")
        return False

    async def _reconcile_bidirectional(
        self,
        lock: dict,
        ha_state: Any,
        access_state: str | None,
        access_rule: str,
        schedule_active: bool,
        access_relay_state: str | None,
        hubs: list[dict],
    ) -> int:
        """Reconcile one logical pair using source-change detection."""
        eid = lock["entity_id"]
        valid_ha = ha_state in {"locked", "unlocked"}
        valid_access = access_state in {"locked", "unlocked"}
        now = time.monotonic()

        if (
            ha_state in _HA_TRANSITIONAL_STATES
            and eid not in self._fail_safe_reset_eids
        ):
            # The bolt is mid-throw, not untrusted. An entity already inside
            # an active fail-safe incident is deliberately excluded above —
            # locked-wins enforcement must never be paused by a transitional
            # reading. Otherwise, make no convergence decision this pass
            # until the grace window (bounded, see _HA_TRANSITION_GRACE)
            # elapses; then fall through to the untrusted_state path below
            # exactly as if this exemption did not exist.
            #
            # The record is cleared by the ``else`` branch below on ANY
            # non-transitional reading — valid or not — not only a valid
            # one. A transitional -> invalid (unavailable/unknown/jammed)
            # -> transitional sequence with no valid reading in between
            # must start a FRESH grace window; reusing a stale start time
            # from a much earlier transition would let the window already
            # be expired on the first poll of a genuinely new transition
            # (e.g. an HA restart or a Z-Wave dropout mid-throw), which
            # reinstates the exact bug this exemption exists to fix. Once
            # expired, the record is deliberately NOT popped here — it is
            # retained across the expiry pass so a still-stuck entity keeps
            # failing closed on every subsequent poll instead of restarting
            # its grace window.
            started = self._ha_transition_started.setdefault(eid, now)
            if now - started < _HA_TRANSITION_GRACE:
                if started == now:
                    # Log once per window (the first poll to observe it),
                    # not every poll — this is the only convergence branch
                    # that writes nothing to the DB (it returns before
                    # _persist_convergence) and, before this, logged
                    # nothing either.
                    _LOGGER.debug(
                        "Hub sync: %s reports %s (bolt mid-throw) — "
                        "deferring convergence for up to %.0fs",
                        eid, ha_state, _HA_TRANSITION_GRACE,
                    )
                return 0
            _LOGGER.warning(
                "Hub sync: %s still reports %s after %.0fs — treating as "
                "untrusted and failing closed",
                eid, ha_state, now - started,
            )
        else:
            # Any non-transitional reading — a valid locked/unlocked state
            # proving the transition is over, OR a genuinely invalid one
            # (unavailable/unknown/jammed) — ends the window. See the
            # comment above: only a non-transitional reading may clear
            # this, so a stale start time is never silently reused.
            self._ha_transition_started.pop(eid, None)

        momentary_until = self._access_momentary_until.get(eid, 0.0)
        if momentary_until:
            if ha_state == "locked":
                self._access_momentary_until.pop(eid, None)
            elif now < momentary_until and ha_state == "unlocked":
                # The Access event already opened the native door. A durable
                # RelockManager intent owns HA's temporary divergence; writing
                # keep_unlock here would turn it into a persistent override.
                self._last_ha_observed[eid] = "unlocked"
                if valid_access:
                    self._last_access_observed[eid] = access_state
                    self._last_access_rule[eid] = access_rule
                return 0
            elif now >= momentary_until:
                self._access_momentary_until.pop(eid, None)
                valid_ha = False  # expired lease falls into locked-wins

        # Captured from the observation alone, before any drive mutates the
        # working copies below. Used for observation-driven fail-safe release:
        # when the latch is set but both sides are independently observed
        # locked, the incident's goal (converge locked) is visibly achieved.
        observed_both_locked = bool(
            valid_ha
            and valid_access
            and ha_state == "locked"
            and access_state == "locked"
            and access_relay_state == "locked"
        )

        previous_ha = self._last_ha_observed.get(eid)
        previous_access = self._last_access_observed.get(eid)
        previous_rule = self._last_access_rule.get(eid)
        fresh = previous_ha is None or previous_access is None

        if not valid_ha or not valid_access:
            desired = "locked"
            source = "untrusted_state"
            fail_safe = True
        elif ha_state == access_state:
            desired = ha_state
            source = "already_converged"
            fail_safe = False
        elif fresh:
            # On an unbaselined mismatch, opening either side is unsafe. The
            # sole exception is an authenticated readback of an active Access
            # schedule whose physical door state is also unlocked.
            if schedule_active and access_state == "unlocked":
                desired = "unlocked"
                source = "access_schedule_startup"
                fail_safe = False
            elif schedule_active and access_state == "locked":
                # A first-person-in or relay-transition schedule is valid
                # Access-owned intent even while physically closed. Mirror the
                # conservative state without replacing the schedule rule.
                desired = "locked"
                source = "access_schedule_startup_closed"
                fail_safe = False
            else:
                desired = "locked"
                source = "startup_conflict"
                fail_safe = True
        else:
            ha_changed = ha_state != previous_ha
            if self._is_self_command_rule(previous_rule):
                # The stored baseline is our own prior drive's marker, not a
                # real rule fingerprint — there is nothing genuine to compare
                # ``access_rule`` against. ``previous_access`` was captured
                # in the same _persist_convergence call, so a state-only
                # comparison still catches any real Access-side movement
                # since that drive; only the fingerprint-level distinction is
                # unavailable for this one baseline.
                #
                # Known, accepted limitation (documented, not fixed here):
                # this weakens change *detection* to *arbitration* on this
                # one poll. An Access rule change WITHIN the same effective
                # state (e.g. an admin's keep_lock replaced by our own
                # keep_unlock — both "locked" as far as access_state is
                # concerned) is invisible to this state-only comparison. If
                # HA also changed in that same window, ha_changed and
                # access_changed can resolve to (True, False) instead of
                # the correct concurrent_conflict, so source="ha" wins and
                # the relay is physically driven by the HA side's desired
                # state even though Access-side intent also moved. This can
                # never hide a locked<->unlocked divergence — access_state
                # itself would differ — so it cannot cause a reverted
                # unlock or mask a lockout; it only affects which side's
                # rule literally wins when both changed within the same
                # state and the app's own marker is the baseline. The
                # proper fix is threading the confirmed readback rule/state
                # back through _HubDriveResult so a real fingerprint is
                # built instead of f"command:{desired}"; that is a filed
                # follow-up, out of scope for this change.
                access_changed = access_state != previous_access
            else:
                access_changed = (
                    access_state != previous_access or access_rule != previous_rule
                )
            if ha_changed and not access_changed:
                desired = ha_state
                source = "ha"
                fail_safe = False
            elif access_changed and not ha_changed:
                desired = access_state
                source = "access"
                fail_safe = False
            elif ha_changed and access_changed and ha_state == access_state:
                desired = ha_state
                source = "both_same"
                fail_safe = False
            else:
                desired = "locked"
                source = "concurrent_conflict"
                fail_safe = True

        if fail_safe:
            # Do not reinterpret the first good read after an outage/malformed
            # sample as a fresh Access-origin request to open. The incident is
            # unresolved until both sides have actually confirmed locked.
            self._fail_safe_reset_eids.add(eid)
        if eid in self._fail_safe_reset_eids:
            desired = "locked"
            fail_safe = True

        if (
            desired == "unlocked"
            and source == "ha"
            and not await self._ensure_ha_origin_relock(lock, now)
        ):
            # The opt-in timer is part of the safety contract for a genuine
            # HA-origin unlock. Refuse the persistent Access hold-open when its
            # durable owner cannot be established, and converge both sides
            # closed through the normal locked-wins retry/latch path.
            self._fail_safe_reset_eids.add(eid)
            # This is the first and only chance to compensate the external HA
            # unlock before any durable timer exists. Do not let an older Access
            # hard-rejection delay the immediate HA-side close.
            self._backoff_until.pop(eid, None)
            desired = "locked"
            source = "ha_origin_relock_unavailable"
            fail_safe = True

        # Bounded backoff for a repeatedly hard-rejected locked drive. Once a
        # definitive rejection (legacy endpoint removed, or an explicit legacy
        # rule rejection) has recurred past the threshold, retry on a spaced
        # cadence instead of every poll. This NEVER stops: the durable locked
        # intent recorded above (_fail_safe_reset_eids / desired="locked") is
        # retained and the drive resumes the instant the deadline passes.
        # Lockdown enforcement returns from the dedicated branch in _poll_once
        # and never reaches this method, so incident closing is never delayed.
        if (
            desired == "locked"
            and self._hard_reject_state.get(eid, ("", 0))[1]
            >= _HARD_REJECT_BACKOFF_THRESHOLD
            and self._backoff_until.get(eid, 0.0) > now
        ):
            return 0

        # Flap damping — bound the command volume of a pathologically cycling
        # lock. This mirrors the legacy _poll_once contract exactly: it gates
        # ONLY the unsafe hold-open direction and only when a real drive toward
        # unlocked is pending. Locking is the fail-safe direction and is never
        # delayed; lockdown enforcement never reaches this method (it returns
        # from the dedicated ``lockdown_active`` branch in _poll_once), so
        # incident closing can never be suspended or backed off by this code.
        if desired == "unlocked" and (
            ha_state != desired or access_state != desired
        ):
            if self._suspended_until.get(eid, 0.0) > now:
                return 0
            if self._backoff_until.get(eid, 0.0) > now:
                return 0
            last_applied_at = self._last_applied_at.get(eid)
            if (
                last_applied_at is not None
                and now - last_applied_at < _MIN_APPLY_INTERVAL
            ):
                _LOGGER.debug(
                    "Hub sync: hold-open for %s deferred (min interval)", eid
                )
                return 0
            recent = [
                t for t in self._apply_times.get(eid, ())
                if now - t <= _FLAP_WINDOW
            ]
            self._apply_times[eid] = recent
            if len(recent) >= _FLAP_THRESHOLD:
                await self._suspend_flapping(lock)
                return 0

        # Clear any hard-rejection marker from a previous pass so a failed
        # drive below is judged only on this pass's own outcome. _drive_hub
        # sets it again if (and only if) this drive is permanently rejected.
        self._last_drive_hard.pop(eid, None)

        changed = False
        if ha_state != desired:
            if not await self._drive_ha_state(
                lock, desired, fail_safe=fail_safe or desired == "locked"
            ):
                self._last_ha_observed[eid] = (
                    ha_state if valid_ha else "locked"
                )
                self._last_access_observed[eid] = (
                    access_state if valid_access else "locked"
                )
                self._last_access_rule[eid] = access_rule
                # Back off retries of the unsafe direction only; a failed lock
                # must keep retrying every poll (fail-closed) — unless it is a
                # repeated hard rejection, which is spaced but never stopped.
                if desired == "unlocked":
                    self._backoff_until[eid] = (
                        time.monotonic() + _FAILURE_BACKOFF
                    )
                else:
                    self._note_locked_drive_failure(eid)
                return 0
            ha_state = desired
            changed = True

        release_fail_safe_override = bool(
            eid in self._fail_safe_reset_eids
            and desired == "locked"
            and ha_state == "locked"
            and access_state == "locked"
            and access_relay_state == "locked"
        )
        needs_authoritative_fail_safe_lock = bool(
            eid in self._fail_safe_reset_eids
            and desired == "locked"
            and access_relay_state != "locked"
        )
        if (
            access_state != desired
            or release_fail_safe_override
            or needs_authoritative_fail_safe_lock
        ):
            apply_result = await self._apply_state(
                lock,
                desired,
                hubs=hubs,
                # Once both sides are confirmed locked, use lock_now rather
                # than another keep_lock. This releases the persistent incident
                # override without resuming the currently active schedule.
                fail_safe=fail_safe and not release_fail_safe_override,
                unsafe_expected_access=(
                    access_rule
                    if source == "ha" and desired == "unlocked"
                    else None
                ),
            )
            if not apply_result:
                # Observation-driven fail-safe release (1.5.12 wedge fix). When
                # both sides were independently observed locked this pass, no
                # drive was needed to converge — the only write was the cosmetic
                # keep_lock→lock_now release, whose confirm can fail forever on
                # firmware that self-clears lock_now to `reset`. The incident's
                # goal (both sides locked) is already met, so release the latch
                # on the observation rather than leaving it wedged, reverting
                # every future unlock indefinitely. Durable keep_lock ownership
                # stays queued for a later confirmed lock_now; the door remains
                # safely locked. Only fires when release_fail_safe_override was
                # the reason we drove (both observed locked); a real failed lock
                # toward a not-yet-locked side keeps the latch (fail-closed).
                if (
                    release_fail_safe_override
                    and observed_both_locked
                    and eid in self._fail_safe_reset_eids
                ):
                    self._last_ha_observed[eid] = "locked"
                    self._last_access_observed[eid] = "locked"
                    self._last_access_rule[eid] = access_rule
                    self._release_fail_safe_latch(eid)
                    _LOGGER.info(
                        "Hub sync: fail-safe latch for %s released on "
                        "observation — both sides locked though the keep_lock "
                        "release did not confirm",
                        eid,
                    )
                    return 0
                # HA may already have moved. Keep the desired baseline absent so
                # the next pass retries rather than treating this partial apply
                # as a new external HA change.
                self._last_ha_observed[eid] = ha_state
                self._last_access_observed[eid] = (
                    access_state if valid_access else "locked"
                )
                self._last_access_rule[eid] = access_rule
                # Back off retries of the unsafe direction only; a failed lock
                # must keep retrying every poll (fail-closed) — unless it is a
                # repeated hard rejection, which is spaced but never stopped.
                if desired == "unlocked":
                    self._backoff_until[eid] = (
                        time.monotonic() + _FAILURE_BACKOFF
                    )
                else:
                    self._note_locked_drive_failure(eid)
                return 0
            access_state = desired
            # Authority belongs to the exact client that accepted and
            # confirmed the command. Settings may publish a replacement client
            # after the write barrier is released but before readback finishes;
            # consulting the current getter here would let that new client's
            # Open API capability promote an older private-rule result into
            # fabricated relay evidence.
            access_relay_state = (
                desired if apply_result.authoritative_relay else None
            )
            access_rule = f"command:{desired}"
            changed = True

        try:
            await self._persist_convergence(
                eid=eid,
                desired=desired,
                source=source,
                access_rule=access_rule,
                hubs=hubs,
            )
        except Exception:
            _LOGGER.exception("Could not persist hub-sync convergence for %s", eid)
            if desired == "unlocked":
                # Do not leave an unsafe state whose origin cannot survive a
                # restart. Best-effort close both sides; durable hold ownership
                # remains until Access confirms the safe direction.
                await self._drive_ha_state(lock, "locked", fail_safe=True)
                await self._apply_state(
                    lock, "locked", hubs=hubs, fail_safe=True
                )
            return 0

        self._pairing_signature[eid] = self._hub_signature(hubs)
        self._paired_hubs[eid] = [dict(hub) for hub in hubs]
        # A confirmed convergence releases the fail-safe latch (when locked) and
        # clears any prior unsafe-direction backoff so the next genuine change
        # is not needlessly deferred (legacy parity), re-arming hard-rejection
        # tracking + loud logging for a new incident. The latch is only ever set
        # while desired is forced locked, so this shares one helper with the
        # observation-driven release to keep the bookkeeping consistent.
        if (
            eid not in self._fail_safe_reset_eids
            or (
                desired == "locked"
                and ha_state == "locked"
                and access_relay_state == "locked"
            )
        ):
            self._release_fail_safe_latch(eid)

        return 1 if changed else 0

    async def _ensure_ha_origin_relock(self, lock: dict, now: float) -> bool:
        """Write-ahead a timer before mirroring a genuine HA-origin unlock.

        Guarded so it never touches an app-initiated unlock: a manual dashboard
        Unlock (short-TTL marker), a buzz / device-auth / remote unlock (their
        momentary lease marks app-initiated and they already own a durable
        timer), or any entity that already has a live pending re-lock row. The
        caller may issue persistent ``keep_unlock`` only after this returns
        True. False means the opted-in safety owner could not be established,
        so the caller must converge locked instead.
        """
        if not lock.get("relock_on_ha_origin"):
            return True
        eid = lock["entity_id"]
        if self._app_initiated_until.get(eid, 0.0) > now:
            return True
        if self._get_relock_manager is None:
            _LOGGER.error(
                "Could not schedule ha_origin re-lock for %s: manager unavailable",
                eid,
            )
            return False
        try:
            relock_manager = self._get_relock_manager()
        except Exception:
            _LOGGER.exception(
                "Could not schedule ha_origin re-lock for %s: manager getter failed",
                eid,
            )
            return False
        if relock_manager is None:
            _LOGGER.error(
                "Could not schedule ha_origin re-lock for %s: manager unavailable",
                eid,
            )
            return False
        try:
            # A buzz / device-auth / remote unlock already owns a durable timer.
            # Never replace or double it.
            if await self._db.get_pending_relock(eid) is not None:
                return True
            await relock_manager.schedule(
                entity_id=eid,
                duration=float(lock.get("relock_duration", 30)),
                lock_id=lock.get("id"),
                lock_name=lock.get("name", eid),
                source="ha_origin",
            )
            return True
        except Exception:
            _LOGGER.exception(
                "Could not schedule ha_origin re-lock for %s", eid
            )
            return False

    async def _apply_state(
        self,
        lock: dict,
        state: str,
        *,
        hubs: Optional[list[dict]] = None,
        enforcing_lockdown: bool = False,
        fail_safe: bool = False,
        unsafe_expected_access: str | None = None,
    ) -> _HubDriveResult | None:
        """Drive all paired hubs and retain exact-client relay provenance."""
        eid = lock["entity_id"]
        lock_name = lock.get("name", eid)

        if hubs is None:
            hubs = await self._resolve_hub_locks(lock)
        if not hubs:
            # Misconfiguration (option on, no paired Access door). Do NOT
            # report success: doing so records the HA state as applied, so a
            # hub paired later never converges until the HA lock changes
            # again. Retain the unapplied state and retry with backoff.
            _LOGGER.warning(
                "Hub sync enabled for %s but no associated Access hub found — "
                "link the door via Entry Devices (Access location or Protect "
                "doorbell) or the legacy access_location_id",
                lock_name,
            )
            if eid not in self._failure_notified:
                self._failure_notified.add(eid)
                await self._notify_sync_failed(
                    eid, lock_name, reason="no_paired_hub"
                )
            return None

        ok_all = True
        drove_any = False
        all_relays_authoritative = True
        expected_rows: dict[str, dict] = {}
        if unsafe_expected_access is not None:
            try:
                decoded = json.loads(unsafe_expected_access)
                expected_rows = {
                    str(row["device_id"]): row
                    for row in decoded
                    if isinstance(row, dict) and row.get("device_id")
                }
            except (TypeError, ValueError, KeyError):
                _LOGGER.warning(
                    "Hub sync refused unsafe write for %s: invalid observation guard",
                    lock_name,
                )
                return None
        for hub in hubs:
            device_id = hub["device_id"]
            hub_name = hub.get("name", device_id)
            durable_state_ok = True
            persistent_lock = bool(
                state == "locked" and (enforcing_lockdown or fail_safe)
            )
            persistent_rule_requested = persistent_lock
            force_transient = False
            release_persistent = bool(
                state == "locked"
                and any(
                    item.get("device_id") == device_id
                    for item in self._held_locked.get(eid, [])
                )
                and not persistent_rule_requested
            )
            if state == "unlocked" or persistent_lock:
                if self._in_lockdown():
                    if state == "unlocked":
                        _LOGGER.warning(
                            "Hub sync refused hold-open for %s because lockdown "
                            "became active before the physical command",
                            hub_name,
                        )
                        ok_all = False
                        break
                try:
                    # Write-ahead ownership closes the crash window between a
                    # successful persistent command and persistence. A stale
                    # row is safe: recovery reasserts keep_lock before release.
                    if persistent_lock:
                        await self._record_hub_state(
                            eid,
                            hub,
                            state,
                            persistent_lock=True,
                        )
                except Exception:
                    _LOGGER.exception(
                        "Hub sync refused persistent rule for %s because durable "
                        "ownership could not be recorded",
                        hub_name,
                    )
                    if state == "unlocked":
                        ok_all = False
                        continue
                    # A failed safety-bookkeeping write must not leave the door
                    # open. During persisted lockdown, still apply keep_lock;
                    # otherwise use non-persistent lock_now so a crash cannot
                    # strand future schedules disabled.
                    durable_state_ok = False
                    persistent_lock = False
                    force_transient = not enforcing_lockdown

            async def before_command(hub_row: dict = hub) -> None:
                if state == "unlocked":
                    await self._record_hub_state(eid, hub_row, "unlocked")

            async def unsafe_guard(hub_row: dict = hub) -> bool:
                if unsafe_expected_access is None:
                    return True
                expected = expected_rows.get(str(hub_row.get("device_id")))
                if expected is None:
                    return False
                ha = self._get_ha()
                access = self._get_access()
                if (
                    ha is None
                    or not getattr(ha, "connected", False)
                    or not self._access_available(access)
                    or await ha.get_entity_state(eid) != "unlocked"
                ):
                    return False
                try:
                    # This guard runs with the global physical-command barrier
                    # held: one bounded non-settling read, and any ambiguity
                    # suppresses the unlock (fail-safe) rather than stalling
                    # every other door behind the relay-lag window.
                    async with asyncio.timeout(_GUARD_OBSERVE_TIMEOUT):
                        current_state, current_rule, _active, _relay_state = (
                            await self._observe_access_hub(
                                access, hub_row, settle=False
                            )
                        )
                except Exception:
                    return False
                current = {
                    "device_id": hub_row.get("device_id"),
                    "rule": current_rule,
                    "state": current_state,
                }
                if current != expected:
                    _LOGGER.info(
                        "Hub sync suppressed stale HA-origin unlock for %s; "
                        "Access changed after observation",
                        hub_name,
                    )
                    return False
                return True

            drove = await self._drive_hub(
                device_id,
                state,
                hub_name,
                eid=eid,
                location_id=hub.get("location_id"),
                enforcing_lockdown=enforcing_lockdown,
                fail_safe=fail_safe,
                force_transient=force_transient,
                release_persistent=release_persistent,
                guard=unsafe_guard if unsafe_expected_access is not None else None,
                before_command=before_command if state == "unlocked" else None,
            )
            if self._urgent_lockdown.is_set() and not enforcing_lockdown:
                return None
            if (
                drove
                and state == "locked"
                and not persistent_lock
                and not persistent_rule_requested
            ):
                try:
                    # force_lock/reset replaces any persistent app override.
                    # Clear ownership only after Access confirms that command.
                    await self._record_hub_state(eid, hub, state)
                except Exception:
                    _LOGGER.exception(
                        "Hub sync reset %s but could not clear durable "
                        "ownership",
                        hub_name,
                    )
                    durable_state_ok = False
            if not drove:
                ok_all = False
                continue
            drove_any = True
            all_relays_authoritative = bool(
                all_relays_authoritative
                and drove.authoritative_relay
                and drove.state == state
            )
            if not durable_state_ok:
                ok_all = False
            if self._on_hub_state is not None:
                try:
                    self._on_hub_state(
                        device_id,
                        (
                            drove.state
                            if drove.authoritative_relay
                            else "unknown"
                        ),
                    )
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
            # no-hub misconfiguration must not trip the flap breaker. Prune
            # to the flap window at append time so the list stays bounded for
            # the install's lifetime. The legacy _poll_once path pruned lazily
            # on read; the bidirectional reconcile never read it, so an
            # unpruned list grew without bound (one entry per hub drive).
            now = time.monotonic()
            self._last_applied_at[eid] = now
            recent = [
                t for t in self._apply_times.get(eid, ())
                if now - t <= _FLAP_WINDOW
            ]
            recent.append(now)
            self._apply_times[eid] = recent

        if (
            not ok_all
            and eid not in self._failure_notified
            and (enforcing_lockdown or not self._urgent_lockdown.is_set())
        ):
            self._failure_notified.add(eid)
            await self._notify_sync_failed(eid, lock_name, reason="apply_failed")
        if ok_all:
            self._pairing_signature[eid] = self._hub_signature(hubs)
            self._paired_hubs[eid] = [dict(hub) for hub in hubs]
        if not ok_all:
            return None
        return _HubDriveResult(
            state=state,
            authoritative_relay=bool(
                drove_any and all_relays_authoritative
            ),
        )

    async def _record_hub_state(
        self,
        eid: str,
        hub: dict,
        state: str,
        *,
        persistent_lock: bool = False,
    ) -> None:
        """Durably track app-owned persistent rules before physical writes."""
        held_open = self._held_open.setdefault(eid, [])
        held_locked = self._held_locked.setdefault(eid, [])
        if state == "unlocked":
            await self._db.record_hub_sync_hold(
                eid,
                hub["device_id"],
                hub.get("id"),
                hub.get("name", hub["device_id"]),
                hub_location_id=hub.get("location_id"),
                override_type="keep_unlock",
            )
            if not any(
                h.get("device_id") == hub.get("device_id") for h in held_open
            ):
                held_open.append(hub)
            self._held_locked[eid] = [
                h for h in held_locked
                if h.get("device_id") != hub.get("device_id")
            ]
        elif persistent_lock:
            await self._db.record_hub_sync_hold(
                eid,
                hub["device_id"],
                hub.get("id"),
                hub.get("name", hub["device_id"]),
                hub_location_id=hub.get("location_id"),
                override_type="keep_lock",
            )
            if not any(
                h.get("device_id") == hub.get("device_id") for h in held_locked
            ):
                held_locked.append(hub)
            self._held_open[eid] = [
                h for h in held_open
                if h.get("device_id") != hub.get("device_id")
            ]
        else:
            await self._db.clear_hub_sync_hold(eid, hub["device_id"])
            self._held_open[eid] = [
                h for h in held_open
                if h.get("device_id") != hub.get("device_id")
            ]
            self._held_locked[eid] = [
                h for h in held_locked
                if h.get("device_id") != hub.get("device_id")
            ]

    async def _suspend_flapping(self, lock: dict) -> None:
        """
        The entity earned too many hub drives inside the flap window.
        Suspend sync for it, fail-safe any held-open hub back to reset,
        and alert. Tracking is dropped so the first poll after the
        suspension re-converges to the then-current state.
        """
        eid = lock["entity_id"]
        lock_name = lock.get("name", eid)
        self._suspended_until[eid] = time.monotonic() + _FLAP_SUSPEND
        _LOGGER.error(
            "Hub sync SUSPENDED for %s — %d hub drives inside %.0fs "
            "(flapping lock or abuse). Hub fail-safes to reset; sync "
            "re-converges in %.0fs.",
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

    @staticmethod
    def _append_unique_hubs(target: list[dict], hubs: list[dict]) -> None:
        """Merge hubs by stable Access device id, preserving full rows."""
        known = {hub.get("device_id"): hub for hub in target}
        for hub in hubs:
            device_id = hub.get("device_id")
            if not device_id:
                continue
            existing = known.get(device_id)
            if existing is not None:
                for key, value in hub.items():
                    if (
                        value is not None
                        and (
                            existing.get(key) is None
                            or existing.get(key) == ""
                        )
                    ):
                        existing[key] = value
                continue
            target.append(hub)
            known[device_id] = hub

    async def _load_persisted_holds(self) -> None:
        """Merge durable ownership rows into held and release tracking."""
        rows = await self._db.get_hub_sync_holds()
        for row in rows:
            eid = row["entity_id"]
            hub = {
                "id": row.get("hub_lock_id"),
                "device_id": row["hub_device_id"],
                "location_id": row.get("hub_location_id"),
                "name": row.get("hub_name") or row["hub_device_id"],
                "type": "access_native",
            }
            override_type = row.get("override_type") or "keep_unlock"
            owned = (
                self._held_locked if override_type == "keep_lock"
                else self._held_open
            )
            self._append_unique_hubs(owned.setdefault(eid, []), [hub])
            self._append_unique_hubs(
                self._pending_release.setdefault(eid, []), [hub]
            )

    @staticmethod
    def _preserve_opted_eids(all_locks: list[dict]) -> set[str]:
        """Entity ids whose current row opts into graceful-restart holds."""
        return {
            row["entity_id"]
            for row in all_locks
            if row.get("type") == "ha_external"
            and row.get("entity_id")
            and row.get("sync_hub_state")
            and row.get("preserve_hold_on_restart")
            and not row.get("hidden")
        }

    def _preservable_holds(
        self,
        candidates: set[str],
        all_locks: Optional[list[dict]],
        *,
        lockdown_active: bool,
    ) -> set[str]:
        """Select holds a graceful shutdown may leave physically in place.

        Only pure app-owned keep_unlock ownership qualifies (no keep_lock
        rows, no fail-safe latch), only on locks whose *current* row opts in,
        only when this process actually resolved prior-run ownership, and
        never during lockdown.
        """
        if lockdown_active or not self._lifecycle_recovered or not all_locks:
            return set()
        opted = self._preserve_opted_eids(all_locks)
        return {
            eid
            for eid in candidates
            if eid in opted
            and self._held_open.get(eid)
            and not self._held_locked.get(eid)
            and eid not in self._fail_safe_reset_eids
        }

    async def _write_clean_shutdown_marker(self, preserved: set[str]) -> set[str]:
        """Persist the marker; return the holds it actually vouches for."""
        setter = self._method(self._db, "set_config")
        if setter is None:
            # Legacy injected databases cannot carry a marker — nothing is
            # preservable, and there is no stale marker to overwrite.
            return set()
        try:
            await setter(
                _CLEAN_SHUTDOWN_KEY,
                json.dumps({"ts": time.time(), "preserved": sorted(preserved)}),
            )
        except Exception:
            _LOGGER.exception(
                "Hub sync: could not write clean-shutdown marker; releasing "
                "all holds instead"
            )
            return set()
        return preserved

    async def _consume_clean_shutdown_marker(self) -> set[str]:
        """Read and delete the single-use clean-shutdown marker.

        The row is deleted before its contents are trusted: if it cannot be
        removed, single-use cannot be guaranteed and the marker is ignored.
        Malformed, stale, or future-dated contents also fail closed.
        """
        getter = self._method(self._db, "get_config")
        deleter = self._method(self._db, "delete_config")
        if getter is None or deleter is None:
            return set()
        try:
            raw = await getter(_CLEAN_SHUTDOWN_KEY)
            if not raw:
                return set()
            await deleter(_CLEAN_SHUTDOWN_KEY)
        except Exception:
            _LOGGER.exception("Hub sync: clean-shutdown marker read failed")
            return set()
        try:
            data = json.loads(raw)
            age = time.time() - float(data["ts"])
            eids = data["preserved"]
            if not isinstance(eids, list) or not all(
                isinstance(eid, str) for eid in eids
            ):
                raise ValueError("preserved is not a list of entity ids")
        except Exception:
            _LOGGER.warning("Hub sync: ignoring malformed clean-shutdown marker")
            return set()
        if not -_CLEAN_SHUTDOWN_FUTURE_SKEW <= age <= _CLEAN_SHUTDOWN_MAX_AGE:
            _LOGGER.warning(
                "Hub sync: ignoring stale clean-shutdown marker (age %.0fs); "
                "holds fail closed",
                age,
            )
            return set()
        return set(eids)

    async def _preserve_clean_holds(
        self, candidates: set[str], all_locks: list[dict]
    ) -> set[str]:
        """Return the marked holds that readback proves safe to re-adopt.

        Eligibility is re-checked against the *current* database row (the
        opt-in may have been cleared while stopped), then both sides are read
        back: HA must still report the deadbolt unlocked, and a readback-
        capable Access client must still report keep_unlock on every held
        hub. Any doubt leaves the hold on the normal fail-closed path.
        """
        if not candidates:
            return set()
        opted = self._preserve_opted_eids(all_locks)
        ha = self._get_ha()
        access = self._get_access()
        bidirectional = self._supports_bidirectional_access(access)
        preserved: set[str] = set()
        for eid in sorted(candidates):
            if eid not in opted:
                continue
            hubs = self._held_open.get(eid)
            if not hubs or self._held_locked.get(eid):
                continue
            try:
                if ha is None or not getattr(ha, "connected", False):
                    continue
                if await ha.get_entity_state(eid) != "unlocked":
                    continue
                if bidirectional:
                    confirmed = True
                    for hub in hubs:
                        state, rule, _schedule, _relay = (
                            await self._observe_access_hub(
                                access, hub, settle=False
                            )
                        )
                        if (
                            rule.get("type") != "keep_unlock"
                            or state != "unlocked"
                        ):
                            confirmed = False
                            break
                    if not confirmed:
                        continue
            except Exception:
                _LOGGER.exception(
                    "Hub sync: preservation readback failed for %s; "
                    "failing closed",
                    eid,
                )
                continue
            _LOGGER.info(
                "Hub sync: re-adopting keep_unlock hold for %s after a "
                "graceful restart (readback confirmed both sides open)",
                eid,
            )
            preserved.add(eid)
        return preserved

    async def _load_persisted_sync_state(self) -> None:
        """Restore only fully confirmed origin observations."""
        if self._sync_state_loaded:
            return
        getter = self._method(self._db, "get_hub_sync_states")
        if getter is None:
            self._sync_state_loaded = True
            return
        rows = await getter()
        for row in rows:
            eid = row.get("entity_id")
            ha_state = row.get("ha_state")
            access_state = row.get("access_state")
            desired = row.get("desired_state")
            if (
                not eid
                or ha_state not in {"locked", "unlocked"}
                or access_state not in {"locked", "unlocked"}
                or desired not in {"locked", "unlocked"}
            ):
                _LOGGER.warning(
                    "Ignoring malformed durable hub-sync state for %r", eid
                )
                continue
            self._last_ha_observed[eid] = ha_state
            self._last_access_observed[eid] = access_state
            self._last_access_rule[eid] = str(
                row.get("access_rule_fingerprint") or ""
            )
            self._last_converged[eid] = desired
            try:
                signature = json.loads(row.get("pairing_signature") or "[]")
            except (TypeError, ValueError):
                signature = []
            if isinstance(signature, list) and all(
                isinstance(device_id, str) for device_id in signature
            ):
                self._pairing_signature[eid] = tuple(sorted(signature))
        self._sync_state_loaded = True

    async def _persist_convergence(
        self,
        *,
        eid: str,
        desired: str,
        source: str,
        access_rule: str,
        hubs: list[dict],
    ) -> None:
        setter = self._method(self._db, "set_hub_sync_state")
        if setter is not None:
            await setter(
                entity_id=eid,
                desired_state=desired,
                source=source,
                ha_state=desired,
                access_state=desired,
                access_rule_fingerprint=access_rule,
                pairing_signature=json.dumps(self._hub_signature(hubs)),
            )
        self._last_ha_observed[eid] = desired
        self._last_access_observed[eid] = desired
        self._last_access_rule[eid] = access_rule
        self._last_converged[eid] = desired

    async def _clear_persisted_convergence(self, eid: str) -> None:
        clearer = self._method(self._db, "clear_hub_sync_state")
        if clearer is not None:
            await clearer(eid)

    async def _queue_release(
        self,
        eid: str,
        all_locks: Optional[list[dict]],
        lock_row: Optional[dict] = None,
    ) -> None:
        """
        If ``eid`` may have hubs in keep_unlock, queue them to be driven
        back to reset. Hubs are resolved from the lock row when available
        (covers opt-out/hide, and survives restarts because convergence
        re-establishes the applied state); the in-memory held-open record
        covers deleted rows.
        """
        held: list[dict] = []
        self._append_unique_hubs(held, self._held_open.get(eid, []))
        self._append_unique_hubs(held, self._held_locked.get(eid, []))
        baseline_unlocked = self._applied.get(eid) == "unlocked"
        if not held and not baseline_unlocked:
            return
        if baseline_unlocked:
            self._append_unique_hubs(held, self._paired_hubs.get(eid, []))

        if lock_row is None and all_locks is not None:
            matching_rows = [
                row for row in all_locks if row.get("entity_id") == eid
            ]
            grouped = self._group_synced_locks(matching_rows)
            lock_row = grouped[0] if grouped else None
        resolved: list[dict] = []
        if lock_row is not None:
            try:
                resolved = await self._resolve_hub_locks(lock_row)
            except Exception:
                _LOGGER.exception("Hub sync: release resolution failed for %s", eid)
        # Union, never fallback: partial multi-hub apply can leave a held hub
        # that no longer resolves from the latest topology. Conversely, the
        # current resolution can include another hub that may have received
        # keep-unlock just before a partial failure. Resetting the union is
        # harmless and prevents either path from stranding a door open.
        hubs: list[dict] = []
        self._append_unique_hubs(hubs, held)
        self._append_unique_hubs(hubs, self._pending_release.get(eid, []))
        self._append_unique_hubs(hubs, resolved)
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
        self._append_unique_hubs(pending, hubs)
        self._release_backoff.pop(eid, None)

    async def _process_pending_releases(
        self,
        *,
        force: bool = False,
        enforcing_lockdown: bool = False,
    ) -> int:
        """Drive queued hubs back to reset; keep failures for retry.

        Returns the number of confirmed resets. ``force`` ignores an existing
        retry deadline for lifecycle safety paths (startup/shutdown/lockdown).
        """
        if not self._pending_release:
            return 0
        now = time.monotonic()
        reset_count = 0
        for eid in list(self._pending_release):
            if self._urgent_lockdown.is_set() and not enforcing_lockdown:
                return reset_count
            if not force and self._release_backoff.get(eid, 0.0) > now:
                continue
            remaining: list[dict] = []
            pending_hubs = list(self._pending_release[eid])
            for index, hub in enumerate(pending_hubs):
                if self._urgent_lockdown.is_set() and not enforcing_lockdown:
                    self._append_unique_hubs(remaining, pending_hubs[index:])
                    break
                device_id = hub["device_id"]
                hub_name = hub.get("name", device_id)
                persistent_lock = bool(
                    enforcing_lockdown or eid in self._fail_safe_reset_eids
                )
                ownership_recorded = True
                if persistent_lock:
                    try:
                        # Write ownership before a keep_lock command. If the
                        # process exits between these operations, recovery may
                        # send one extra safe close but cannot strand a rule.
                        await self._record_hub_state(
                            eid,
                            hub,
                            "locked",
                            persistent_lock=True,
                        )
                    except Exception:
                        ownership_recorded = False
                        _LOGGER.exception(
                            "Hub sync refused fail-safe rule for %s because "
                            "durable ownership could not be recorded",
                            hub_name,
                        )
                drove = await self._drive_hub(
                    device_id,
                    "locked",
                    hub_name,
                    eid=eid,
                    location_id=hub.get("location_id"),
                    enforcing_lockdown=enforcing_lockdown,
                    fail_safe=persistent_lock and ownership_recorded,
                    restore_native=not persistent_lock,
                    force_transient=(
                        persistent_lock
                        and not ownership_recorded
                        and not enforcing_lockdown
                    ),
                )
                if persistent_lock and not ownership_recorded:
                    # The physical close may have succeeded, but lifecycle
                    # ownership is unresolved. Keep retrying and keep lockdown
                    # visibly unresolved rather than claiming convergence.
                    remaining.append(hub)
                    continue
                if drove and not persistent_lock:
                    try:
                        await self._record_hub_state(eid, hub, "locked")
                    except Exception:
                        _LOGGER.exception(
                            "Hub sync reset %s but could not clear durable "
                            "ownership; retaining it for retry",
                            hub_name,
                        )
                        drove = False
                if not drove:
                    remaining.append(hub)
                    continue
                reset_count += 1
                if self._on_hub_state is not None:
                    try:
                        self._on_hub_state(
                            device_id,
                            (
                                drove.state
                                if drove.authoritative_relay
                                else "unknown"
                            ),
                        )
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
                # The hub is now confirmed reset. This suppresses repeat
                # fail-safe traffic while HA remains invalid and lets the
                # first later valid `unlocked` observation reconverge open.
                if eid in self._fail_safe_reset_eids:
                    self._applied[eid] = "locked"
        return reset_count

    def _drop_tracking(self, eid: str) -> None:
        self._applied.pop(eid, None)
        self._pairing_signature.pop(eid, None)
        self._paired_hubs.pop(eid, None)
        self._backoff_until.pop(eid, None)
        self._last_applied_at.pop(eid, None)
        self._apply_times.pop(eid, None)
        self._suspended_until.pop(eid, None)
        self._lockdown_reset.discard(eid)
        self._held_open.pop(eid, None)
        self._held_locked.pop(eid, None)
        self._fail_safe_reset_eids.discard(eid)
        self._last_ha_observed.pop(eid, None)
        self._last_access_observed.pop(eid, None)
        self._last_access_rule.pop(eid, None)
        self._last_converged.pop(eid, None)
        self._access_momentary_until.pop(eid, None)
        self._app_initiated_until.pop(eid, None)
        self._ha_transition_started.pop(eid, None)
        self._clear_incident_signatures(eid)

    def _clear_incident_signatures(self, eid: str) -> None:
        """Drop hard-rejection state and re-arm loud logging for ``eid``.

        Called on convergence (and when tracking is dropped) so the NEXT
        distinct incident logs at full volume and starts a fresh backoff.
        """
        self._hard_reject_state.pop(eid, None)
        self._last_drive_hard.pop(eid, None)
        self._drive_log_signature.pop(eid, None)
        self._observe_log_signature.pop(eid, None)

    def _release_fail_safe_latch(self, eid: str) -> None:
        """Release the locked-wins fail-safe latch and its incident bookkeeping.

        Shared by the confirmed-convergence path and the observation-driven
        release so both discard the same latch, unsafe-direction backoff,
        one-shot failure notification, and hard-rejection/log-once signatures.
        The latch is only set while ``desired`` is forced locked, so discarding
        it on an unlocked convergence is a harmless no-op.
        """
        self._fail_safe_reset_eids.discard(eid)
        self._backoff_until.pop(eid, None)
        self._failure_notified.discard(eid)
        self._clear_incident_signatures(eid)

    @staticmethod
    def _hard_rejection_signature(exc: BaseException) -> str | None:
        """Return a stable bucket when ``exc`` is a permanent hard rejection.

        A hard rejection is the typed legacy-endpoint-gone error or an explicit
        legacy rule rejection (matched against a tiny exact-message allowlist).
        Transient faults (timeouts, 5xx, resets) return None so they keep
        retrying at full cadence and never trip the hard-rejection backoff.
        """
        if isinstance(exc, AccessLegacyEndpointGoneError):
            return "legacy_endpoint_gone"
        if (
            isinstance(exc, AccessClientError)
            and str(exc) in _HARD_REJECTION_MARKERS
        ):
            return "legacy_rule_rejected"
        return None

    def _note_locked_drive_failure(self, eid: str) -> None:
        """Track consecutive hard-rejected locked drives; engage bounded backoff.

        Only a permanent hard rejection (surfaced by _drive_hub into
        ``_last_drive_hard``) counts. Transient/other failures reset the counter
        so they keep retrying every poll. Once the same signature recurs past
        the threshold the locked drive is spaced by _FAILURE_BACKOFF — retried
        forever, only spaced, never stopped.
        """
        signature = self._last_drive_hard.get(eid)
        if signature is None:
            self._hard_reject_state.pop(eid, None)
            return
        prev_signature, count = self._hard_reject_state.get(eid, (None, 0))
        count = count + 1 if prev_signature == signature else 1
        self._hard_reject_state[eid] = (signature, count)
        if count >= _HARD_REJECT_BACKOFF_THRESHOLD:
            self._backoff_until[eid] = time.monotonic() + _FAILURE_BACKOFF

    # ------------------------------------------------------------------
    # Internal — resolution / actuation / alerting
    # ------------------------------------------------------------------

    async def _resolve_hub_locks(self, lock: dict) -> list[dict]:
        """
        Return native Access locks paired with an HA-external lock.

        Location ids come from entry_devices access_reader rows (direct
        location id), entry_devices protect_doorbell rows (camera id →
        location via the live camera map — G6 Entry pairings), and the
        legacy access_location_id column. Hidden native locks are
        included: hiding a hub card from the dashboard is cosmetic and
        must not silently break sync.
        """
        rows = lock.get("_sync_rows") or [lock]
        location_ids: set[str] = {
            row["access_location_id"]
            for row in rows
            if row.get("access_location_id")
        }

        camera_map: dict = {}
        if self._get_camera_map is not None:
            try:
                camera_map = self._get_camera_map() or {}
            except Exception:
                _LOGGER.exception("Hub sync: camera map getter raised")

        try:
            lock_ids = [row["id"] for row in rows]
            devices_by_lock = await self._db.get_entry_devices_for_locks(lock_ids)
        except Exception:
            _LOGGER.exception(
                "Hub sync: entry-device lookup failed for lock(s) %s",
                [row.get("id") for row in rows],
            )
            devices_by_lock = {}
        for row in rows:
            for device in devices_by_lock.get(row["id"], []):
                device_id = device.get("device_id")
                if not device_id:
                    continue
                if device.get("type") == "access_reader":
                    location_ids.add(device_id)
                elif device.get("type") == "protect_doorbell":
                    mapped = camera_map.get(device_id)
                    if mapped:
                        location_ids.add(mapped)
                    else:
                        _LOGGER.debug(
                            "Hub sync: doorbell %s has no camera→location mapping yet",
                            device_id,
                        )

        hubs: list[dict] = []
        seen_device_ids: set[str] = set()
        for location_id in sorted(location_ids):
            for candidate in await self._db.get_locks_for_location(
                location_id, include_hidden=True
            ):
                if (
                    candidate.get("type") == "access_native"
                    and candidate.get("device_id")
                    and candidate["device_id"] not in seen_device_ids
                ):
                    hubs.append(candidate)
                    seen_device_ids.add(candidate["device_id"])
        return hubs

    async def _drive_hub(
        self,
        device_id: str,
        state: str,
        hub_name: str,
        **kwargs: Any,
    ) -> _HubDriveResult | None:
        entity_lock = self._entity_command_locks.setdefault(
            f"access:{device_id}", asyncio.Lock()
        )
        async with entity_lock:
            return await self._drive_hub_coordinated(
                device_id,
                state,
                hub_name,
                **kwargs,
            )

    async def _drive_hub_coordinated(
        self,
        device_id: str,
        state: str,
        hub_name: str,
        *,
        eid: str | None = None,
        location_id: str | None = None,
        enforcing_lockdown: bool = False,
        fail_safe: bool = False,
        restore_native: bool = False,
        force_transient: bool = False,
        release_persistent: bool = False,
        guard: Callable[[], Awaitable[bool]] | None = None,
        before_command: Callable[[], Awaitable[None]] | None = None,
    ) -> _HubDriveResult | None:
        """Call Access with bounded retries and return exact-client evidence.

        Incident/shutdown safety passes make one breadth-first attempt per
        hub. Durable ownership keeps failures queued for later convergence;
        spending the retry delay on the first broken hub would postpone every
        still-open hub behind it. Normal convergence retains bounded retries.
        """
        max_attempts = 1 if enforcing_lockdown else _APPLY_RETRIES
        for attempt in range(1, max_attempts + 1):
            if self._urgent_lockdown.is_set() and not enforcing_lockdown:
                return None
            barrier_released = False

            def _release_barrier() -> None:
                # Release the global command barrier exactly once, after the
                # physical *write* is accepted and before the multi-second
                # relay confirm. Threaded into the Access command as
                # ``on_written`` so the ordered write stays serialized while the
                # idempotent readback GETs do not (mirrors the HA re-lock path).
                nonlocal barrier_released
                if not barrier_released:
                    barrier_released = True
                    self._command_lock.release()

            try:
                # Hold the global barrier for exactly one physical *write*.
                # Retry sleeps, SQLite bookkeeping, and the extended relay
                # confirm all run outside it, so a degraded or slow-to-actuate
                # hub cannot stall every unrelated door for the confirm window.
                await self._command_lock.acquire()
                try:
                    if self._urgent_lockdown.is_set() and not enforcing_lockdown:
                        return None
                    if state == "unlocked" and self._in_lockdown():
                        _LOGGER.warning(
                            "Hub sync refused hold-open for %s during lockdown",
                            hub_name,
                        )
                        return None
                    # Settings publishes and retires Access clients under this
                    # same barrier. Resolve the getter only now so a waiter can
                    # never re-authenticate or command the object that Settings
                    # just closed.
                    access = self._get_access()
                    if not self._access_available(access):
                        _LOGGER.warning(
                            "Hub sync attempt %d/%d deferred for %s — current "
                            "Access client unavailable",
                            attempt,
                            max_attempts,
                            hub_name,
                        )
                    else:
                        authoritative_client = (
                            self._has_authoritative_relay_state(access)
                        )
                        if guard is not None and not await guard():
                            return None
                        if before_command is not None:
                            await before_command()
                        if state == "unlocked" and self._in_lockdown():
                            _LOGGER.warning(
                                "Hub sync aborted hold-open for %s because "
                                "lockdown activated during write-ahead",
                                hub_name,
                            )
                            return None
                        if state == "unlocked":
                            command = self._method(access, "hold_unlocked")
                            if command is not None:
                                confirmation = await self._invoke_access_command(
                                    command,
                                    device_id,
                                    location_id,
                                    _release_barrier,
                                )
                            else:
                                confirmation = await access.unlock_persistent(
                                    device_id
                                )
                        elif force_transient:
                            command = self._method(access, "force_lock")
                            if command is not None:
                                confirmation = await self._invoke_access_command(
                                    command,
                                    device_id,
                                    location_id,
                                    _release_barrier,
                                )
                            else:
                                confirmation = await access.lock(device_id)
                        elif release_persistent:
                            command = self._method(
                                access, "release_persistent_lock"
                            )
                            if command is None:
                                command = self._method(access, "force_lock")
                            if command is not None:
                                confirmation = await self._invoke_access_command(
                                    command,
                                    device_id,
                                    location_id,
                                    _release_barrier,
                                )
                            else:
                                confirmation = await access.lock(device_id)
                        elif restore_native:
                            command = self._method(access, "restore_native_rule")
                            if command is not None:
                                confirmation = await self._invoke_access_command(
                                    command,
                                    device_id,
                                    location_id,
                                    _release_barrier,
                                )
                            else:
                                confirmation = await access.lock(device_id)
                        elif enforcing_lockdown or fail_safe:
                            command = self._method(access, "hold_locked")
                            if command is not None:
                                confirmation = await self._invoke_access_command(
                                    command,
                                    device_id,
                                    location_id,
                                    _release_barrier,
                                )
                            else:
                                confirmation = await access.lock(device_id)
                        else:
                            command = self._method(access, "force_lock")
                            if command is not None:
                                confirmation = await self._invoke_access_command(
                                    command,
                                    device_id,
                                    location_id,
                                    _release_barrier,
                                )
                            else:
                                confirmation = await access.lock(device_id)
                        _LOGGER.info("Hub sync: %s driven to %s", hub_name, state)
                        if isinstance(confirmation, dict):
                            confirmed_state = confirmation.get("state")
                            if confirmed_state in {"locked", "unlocked"}:
                                return _HubDriveResult(
                                    state=str(confirmed_state),
                                    authoritative_relay=authoritative_client,
                                )
                        # A legacy command may confirm only the private rule,
                        # and test doubles/older clients may return no relay
                        # payload. Preserve command success for convergence,
                        # but never present the requested state as physical
                        # evidence.
                        return _HubDriveResult(
                            state=state,
                            authoritative_relay=False,
                        )
                finally:
                    _release_barrier()
            except Exception as exc:
                # Record whether this failure is a permanent hard rejection so
                # the bidirectional reconcile can space (never stop) the locked
                # retry. Log once at the natural level per distinct signature,
                # then drop to debug so a removed endpoint cannot flood logs.
                hard = self._hard_rejection_signature(exc)
                if eid is not None and hard is not None:
                    self._last_drive_hard[eid] = hard
                signature = f"{type(exc).__name__}:{exc}"
                if eid is not None and self._drive_log_signature.get(eid) == signature:
                    _LOGGER.debug(
                        "Hub sync attempt %d/%d failed for %s (→ %s): %s",
                        attempt, max_attempts, hub_name, state, exc,
                    )
                else:
                    if eid is not None:
                        self._drive_log_signature[eid] = signature
                    _LOGGER.exception(
                        "Hub sync attempt %d/%d failed for %s (→ %s): %s",
                        attempt, max_attempts, hub_name, state, exc,
                    )
            if attempt < max_attempts:
                if enforcing_lockdown:
                    await asyncio.sleep(_APPLY_RETRY_DELAY)
                    continue
                try:
                    # Wake immediately when incident enforcement queues behind
                    # this poll instead of making it wait out a retry sleep.
                    await asyncio.wait_for(
                        self._urgent_lockdown.wait(),
                        timeout=_APPLY_RETRY_DELAY,
                    )
                except asyncio.TimeoutError:
                    pass
                if self._urgent_lockdown.is_set():
                    return None
        return None

    async def _notify_sync_failed(
        self, entity_id: str, lock_name: str, reason: str = "apply_failed"
    ) -> None:
        """
        Fire an ``access_control_hub_sync_failed`` HA event so automations
        can alert on a hub that failed to follow its lock (or was
        suspended for flapping). Best-effort — fired once per failing
        change, not on every backoff retry.
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
