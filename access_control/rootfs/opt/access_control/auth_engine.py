"""
Authorization engine for the Access Control App.

Evaluates NFC/face events against access rules and executes unlock commands.
"""
from __future__ import annotations

import asyncio
import logging
import os
from contextlib import AsyncExitStack
from datetime import datetime, time, timezone, tzinfo
from typing import Any, Awaitable, Callable, Optional
from zoneinfo import ZoneInfo

from .access_client import (
    AccessClient,
    AccessCommandAcceptedUnconfirmedError,
    AccessCommandOutcomeUnknownError,
)
from .config import decrypt_value
from .database import Database
from .ha_client import HAClient, ha_client_operation

_LOGGER = logging.getLogger(__name__)

# Maps weekday() index (0=Monday) to short day name used in schedule_days
DAY_NAMES = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")

# Non-disarmed alarm states with no dedicated per-state blocking flag.
# These are treated as fully restrictive: a user is blocked if they hold
# ANY blocking flag (blocked_when_armed_away OR blocked_when_armed_home).
#   - triggered / unknown: already handled this way historically.
#   - armed_night: no dedicated flag exists; blocking must still apply.
#   - arming / pending: the exit-delay and entry-delay windows — a blocked
#     user tapping here would otherwise slip in (and auto-disarm) before the
#     panel ever trips. _get_alarm_state() ranks all of these as armed, so
#     the block gate below must recognise them too (audit 2026-07-05).
_FULLY_RESTRICTIVE_ALARM_STATES = frozenset(
    {"triggered", "unknown", "armed_night", "arming", "pending"}
)
_HA_CONFIRM_ATTEMPTS = 3
_HA_CONFIRM_INTERVAL = 0.25


class HACommandAcceptedUnconfirmedError(RuntimeError):
    """HA accepted a lock mutation but exact state readback did not converge."""


async def _confirm_ha_state(ha, entity_id: str, expected: str) -> bool:
    """Boundedly confirm the exact state using the client that wrote it."""
    for attempt in range(_HA_CONFIRM_ATTEMPTS):
        if await ha.get_entity_state(entity_id) == expected:
            return True
        if attempt < _HA_CONFIRM_ATTEMPTS - 1:
            await asyncio.sleep(_HA_CONFIRM_INTERVAL)
    return False


async def _complete_safety_operation(
    awaitable,
    *,
    name: str,
) -> tuple[Any, asyncio.CancelledError | None]:
    """Run relock ownership work to completion despite caller cancellation."""
    task = asyncio.create_task(awaitable, name=name)
    cancellation: asyncio.CancelledError | None = None
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError as exc:
            # Record cancellation for the caller, but do not allow it to strand
            # a paused durable row or interrupt the only live relock intent.
            if cancellation is None:
                cancellation = exc
    return task.result(), cancellation


def _default_timezone() -> tzinfo:
    """
    Best-effort local timezone for schedule evaluation before HA's
    configured zone is known: the TZ env var if valid, else the
    container's local time (UTC on a stock HAOS container).

    Schedules were previously evaluated in a hardcoded America/New_York —
    a systematic authorization bug for every install outside Eastern
    time (e2e review 2026-07-12). main.py overrides this with HA's
    `time_zone` via set_timezone() as soon as HA is reachable.
    """
    tz_name = os.environ.get("TZ")
    if tz_name:
        try:
            return ZoneInfo(tz_name)
        except Exception:
            _LOGGER.warning(
                "Invalid TZ env value %r — falling back to container-local time",
                tz_name,
            )
    return datetime.now(timezone.utc).astimezone().tzinfo or timezone.utc


class AuthEngine:
    """
    Authorization engine: evaluates events against rules and fires unlocks.

    Typical call flow:
        result = await engine.process_event(ulp_id, location_id, method="nfc")
    """

    def __init__(
        self,
        db: Database,
        access_client: AccessClient,
        ha_client: HAClient,
        relock_tasks: dict[str, asyncio.Task] | None = None,
        enc_key: bytes | None = None,
        relock_manager=None,
        camera_map_getter: Callable[[], dict[str, str]] | None = None,
        command_lock: asyncio.Lock | None = None,
        on_lockdown_enabled: Callable[[], Awaitable[None]] | None = None,
        hub_sync_getter: Callable[[], Any] | None = None,
        on_lock_state: Callable[[str, str], None] | None = None,
        entity_command_locks: dict[str, asyncio.Lock] | None = None,
    ) -> None:
        self._db = db
        self._access_client = access_client
        self._ha_client = ha_client
        self._lockdown: bool = False
        self._relock_tasks: dict[str, asyncio.Task] = relock_tasks if relock_tasks is not None else {}
        self._enc_key = enc_key
        self._relock_manager = relock_manager
        self._get_camera_map = camera_map_getter
        # Lazily fetched HubSyncManager (constructed after the engine) — used to
        # lease a momentary Access unlock so a device-auth timed unlock on a
        # synced lock is not echoed back as a persistent keep_unlock override.
        self._get_hub_sync = hub_sync_getter
        self._command_lock = command_lock or asyncio.Lock()
        self._lockdown_transition_lock = asyncio.Lock()
        self._on_lockdown_enabled = on_lockdown_enabled
        self._on_lock_state = on_lock_state
        self._entity_command_locks = (
            entity_command_locks
            if entity_command_locks is not None
            else {}
        )
        # Tiny in-memory cache for alarm state to avoid hammering HA on each event
        self._alarm_cache_value: str | None = None
        self._alarm_cache_expires: float = 0.0
        self._alarm_cache_ttl: float = 1.5
        # Timezone for schedule evaluation. Seeded from TZ env / container
        # local time; main.py upgrades it to HA's configured time_zone via
        # set_timezone() once HA is reachable.
        self._tz: tzinfo = _default_timezone()

    # ------------------------------------------------------------------
    # Timezone
    # ------------------------------------------------------------------

    @property
    def tz(self) -> tzinfo:
        """Timezone used for all schedule evaluation."""
        return self._tz

    def set_timezone(self, tz_name: str) -> bool:
        """
        Switch schedule evaluation to ``tz_name`` (an IANA zone like
        "Europe/Berlin"). Returns False and keeps the current zone if the
        name is invalid — a bad HA config must not break authorization.
        """
        try:
            self._tz = ZoneInfo(tz_name)
        except Exception:
            _LOGGER.warning(
                "Ignoring invalid timezone %r — schedules keep evaluating in %s",
                tz_name, self._tz,
            )
            return False
        _LOGGER.info("Schedule evaluation timezone set to %s", tz_name)
        return True

    # ------------------------------------------------------------------
    # Lockdown property
    # ------------------------------------------------------------------

    @property
    def lockdown(self) -> bool:
        """When True, all access requests are denied regardless of rules."""
        return self._lockdown

    async def set_lockdown(self, value: bool) -> None:
        """Serialize desired-state transitions, persistence, and enforcement."""
        async with self._lockdown_transition_lock:
            await self._set_lockdown_serialized(value)

    async def _set_lockdown_serialized(self, value: bool) -> None:
        """
        Set lockdown mode AND persist it to the config table.

        Lockdown is an incident-response control: it must survive a restart
        (scheduled reboot, Supervisor watchdog, HAOS update). Persisting here
        — rather than in a synchronous property setter that can't await a DB
        write — is what keeps the door locked across a restart mid-incident.
        Callers MUST use this instead of assigning `.lockdown` directly.
        """
        enabled = bool(value)
        persistence_error: Exception | None = None
        if enabled:
            # Publish enable before awaiting a busy command. Every unsafe
            # command rechecks after acquiring the barrier, so no new unlock
            # starts while an older request drains.
            self._lockdown = True
            _LOGGER.warning("Lockdown mode ENABLED")
            async with self._command_lock:
                pass
            try:
                await self._db.set_config("lockdown", "1")
            except Exception as exc:
                # Keep the safer in-memory state even when durability fails.
                _LOGGER.exception(
                    "Failed to persist lockdown state to config table"
                )
                persistence_error = exc
        else:
            # Disable is the opposite ordering: while still under the command
            # barrier, durable state must change first. A failed write leaves
            # runtime fail-closed instead of silently allowing unlocks.
            try:
                async with self._command_lock:
                    await self._db.set_config("lockdown", "0")
                    self._lockdown = False
                    _LOGGER.warning("Lockdown mode DISABLED")
            except Exception as exc:
                _LOGGER.exception(
                    "Failed to persist lockdown disable; remaining enabled"
                )
                persistence_error = exc

        # Run after releasing the shared command barrier: hub convergence also
        # takes that barrier for physical commands. Awaiting this callback means
        # an enable request does not return while a hub is still held open.
        enforcement_error: Exception | None = None
        if enabled and self._on_lockdown_enabled is not None:
            try:
                await self._on_lockdown_enabled()
            except Exception as exc:
                _LOGGER.exception("Immediate hub reset during lockdown failed")
                enforcement_error = exc

        if persistence_error is not None or enforcement_error is not None:
            raise RuntimeError(
                "Lockdown changed in memory, but durable/physical enforcement "
                "reported an error; inspect the application log immediately"
            )

    async def load_persisted_lockdown(self) -> None:
        """
        Restore lockdown mode from the config table on startup.

        A missing row means the installation has never enabled lockdown.
        Read errors are ambiguous and therefore fail closed: startup remains
        locked down until persistence is healthy and an operator explicitly
        disables the incident control.
        """
        try:
            value = await self._db.get_config("lockdown")
        except Exception:
            self._lockdown = True
            _LOGGER.exception(
                "Failed to read persisted lockdown — failing closed as ENABLED"
            )
            return
        self._lockdown = value == "1"
        if self._lockdown:
            _LOGGER.warning("Lockdown mode restored as ENABLED from persisted state")

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def process_event(
        self,
        ulp_id: str,
        location_id: str,
        method: str = "nfc",
    ) -> dict:
        """
        Process an NFC or face access event.

        Steps:
        1. Look up user by ulp_id
        2. Check user status (must be "active")
        3. Check lockdown mode
        4. Find locks associated with the door/location
        5. Check access rules for user+lock, evaluate schedules
        6. If authorized: unlock and fire HA event
        7. Log everything

        Returns a dict with keys:
            granted (bool), user_name (str|None), reason (str), locks (list[str])
        """
        user: Optional[dict] = None
        granted_locks: list[str] = []

        # Step 1: Look up user
        try:
            user = await self._db.get_user_by_ulp_id(ulp_id)
        except Exception as exc:
            _LOGGER.error("DB error looking up ulp_id %s: %s", ulp_id, exc)
            await self._log(method=method, result="error", reason=f"DB error: {exc}")
            return {"granted": False, "user_name": None, "reason": f"DB error: {exc}", "locks": []}

        if user is None:
            reason = f"Unknown user (ulp_id={ulp_id})"
            _LOGGER.info("Access DENIED — %s", reason)
            await self._log(method=method, result="denied", reason=reason)
            return {"granted": False, "user_name": None, "reason": reason, "locks": []}

        user_id: int = user["id"]
        user_name: str = user["name"]

        # Step 2: Check user status (UNVR API returns uppercase "ACTIVE")
        if (user.get("status") or "").lower() != "active":
            reason = f"User not active (status={user.get('status')})"
            _LOGGER.info("Access DENIED for %s — %s", user_name, reason)
            await self._log(
                method=method, result="denied",
                user_id=user_id, user_name=user_name, reason=reason,
            )
            return {"granted": False, "user_name": user_name, "reason": reason, "locks": []}

        # Step 3: Check lockdown
        if self._lockdown:
            reason = "Lockdown mode active"
            _LOGGER.info("Access DENIED for %s — %s", user_name, reason)
            await self._log(
                method=method, result="denied",
                user_id=user_id, user_name=user_name, reason=reason,
            )
            return {"granted": False, "user_name": user_name, "reason": reason, "locks": []}

        # Step 3.5: Check alarm state vs group permissions
        user_groups = await self._db.get_user_groups(user_id)
        alarm_state = await self._get_alarm_state()

        # Pre-compute schedule-active groups here (we previously only
        # computed this below the alarm check). The `can_disarm` override
        # below must only honor groups that are ACTIVE per their schedule —
        # otherwise a Cleaner whose "Tue 10-2 disarm" group is out of
        # schedule at 11 PM still bypasses an alarm-armed block from a
        # different group. Audit 2026-05-24, clients-#8.
        active_groups = [
            g for g in user_groups
            if not g.get("schedule_enabled") or self._check_schedule(g)
        ]

        # can_disarm is computed under the armed branch below and reused for
        # the auto-disarm decision after a grant. Default False so a disarmed
        # panel (nothing to disarm) never triggers auto-disarm.
        can_disarm = False
        if alarm_state != "disarmed":
            # Block-when-armed always applies regardless of schedule (a
            # blocking group blocks deny-first). can_disarm overrides only
            # from schedule-active groups.
            any_blocking = any(
                (alarm_state == "armed_away" and g.get("blocked_when_armed_away"))
                or (alarm_state == "armed_home" and g.get("blocked_when_armed_home"))
                or (alarm_state in _FULLY_RESTRICTIVE_ALARM_STATES and (g.get("blocked_when_armed_away") or g.get("blocked_when_armed_home")))
                for g in user_groups
            )
            can_disarm = any(
                g.get("can_disarm")
                and not (alarm_state == "armed_away" and g.get("blocked_when_armed_away"))
                and not (alarm_state == "armed_home" and g.get("blocked_when_armed_home"))
                and not (alarm_state in _FULLY_RESTRICTIVE_ALARM_STATES and (g.get("blocked_when_armed_away") or g.get("blocked_when_armed_home")))
                for g in active_groups
            )

            if any_blocking and not can_disarm:
                reason = f"Access blocked — alarm is {alarm_state.replace('_', ' ')}"
                _LOGGER.info("Access DENIED for %s — %s", user_name, reason)
                await self._log(
                    method=method, result="denied",
                    user_id=user_id, user_name=user_name, reason=reason,
                )
                return {"granted": False, "user_name": user_name, "reason": reason, "locks": []}

        # Step 4: Find relevant locks
        locks = await self.get_locks_for_location(location_id)
        if not locks:
            reason = f"No locks found for location {location_id}"
            _LOGGER.info("Access DENIED for %s — %s", user_name, reason)
            await self._log(
                method=method, result="denied",
                user_id=user_id, user_name=user_name, reason=reason,
            )
            return {"granted": False, "user_name": user_name, "reason": reason, "locks": []}

        # Steps 5-7: Check rules (group + individual) and unlock per lock
        any_granted = False
        last_denied_reason = "No matching access rules"

        # active_groups was already computed above (Step 3.5) so the
        # can_disarm override could honor it. Re-using the same list here.

        group_all_locks = any(g.get("all_locks") for g in active_groups)
        group_lock_ids: set[int] = set()
        if not group_all_locks:
            for g in active_groups:
                g_locks = await self._db.get_group_locks(g["id"])
                group_lock_ids.update(l["id"] for l in g_locks)

        for lock in locks:
            lock_id: int = lock["id"]
            lock_name: str = lock["name"]

            # Step 5a: Check group access (all_locks or specific lock assignment)
            group_granted = group_all_locks or lock_id in group_lock_ids

            # Step 5b: Check individual access rule
            rule = None
            if not group_granted:
                try:
                    rule = await self._db.get_rules_for_user_and_lock(user_id, lock_id)
                except Exception as exc:
                    _LOGGER.error("DB error fetching rule for user %s lock %s: %s", user_id, lock_id, exc)
                    await self._log(
                        method=method, result="error",
                        user_id=user_id, user_name=user_name,
                        lock_id=lock_id, lock_name=lock_name,
                        reason=f"DB error: {exc}",
                    )
                    continue

                if rule is None:
                    reason = f"No rule or group for lock '{lock_name}'"
                    _LOGGER.debug("No rule for user %s on lock %s", user_name, lock_name)
                    await self._log(
                        method=method, result="denied",
                        user_id=user_id, user_name=user_name,
                        lock_id=lock_id, lock_name=lock_name,
                        reason=reason,
                    )
                    last_denied_reason = reason
                    continue

                if not rule.get("enabled"):
                    reason = f"Rule disabled for lock '{lock_name}'"
                    _LOGGER.info("Access DENIED for %s — %s", user_name, reason)
                    await self._log(
                        method=method, result="denied",
                        user_id=user_id, user_name=user_name,
                        lock_id=lock_id, lock_name=lock_name,
                        reason=reason,
                    )
                    last_denied_reason = reason
                    continue

                if rule.get("schedule_enabled"):
                    if not self._check_schedule(rule):
                        reason = f"Outside schedule for lock '{lock_name}'"
                        _LOGGER.info("Access DENIED for %s — %s", user_name, reason)
                        await self._log(
                            method=method, result="denied",
                            user_id=user_id, user_name=user_name,
                            lock_id=lock_id, lock_name=lock_name,
                            reason=reason,
                        )
                        last_denied_reason = reason
                        continue

            # Step 6: Authorized — issue the physical unlock under the same
            # barrier used by set_lockdown(). HA state confirmation deliberately
            # happens after releasing it so an eventually-consistent readback
            # cannot block unrelated physical commands or a lockdown transition.
            lockdown_won = False
            try:
                if lock.get("type") == "ha_external":
                    issued = await self._unlock_ha_external(
                        lock,
                        command_lock=self._command_lock,
                        recheck_lockdown=True,
                    )
                    lockdown_won = not issued
                elif lock.get("type") == "access_native":
                    issued = await self._unlock_access_native(
                        lock,
                        command_lock=self._command_lock,
                        recheck_lockdown=True,
                    )
                    lockdown_won = not issued
                else:
                    async with self._command_lock:
                        if self._lockdown:
                            lockdown_won = True
                        else:
                            await self._unlock(lock)
            except asyncio.CancelledError:
                reason = (
                    "Unlock workflow was cancelled before physical state "
                    "confirmation completed"
                )
                try:
                    await _complete_safety_operation(
                        self._log(
                            method=method,
                            result="accepted_unconfirmed",
                            user_id=user_id,
                            user_name=user_name,
                            lock_id=lock_id,
                            lock_name=lock_name,
                            reason=reason,
                        ),
                        name=f"audit-cancelled-auth-unlock-{lock_id}",
                    )
                except Exception:
                    _LOGGER.exception(
                        "Failed to audit cancelled unlock for %s",
                        lock_name,
                    )
                raise
            except HACommandAcceptedUnconfirmedError as exc:
                reason = (
                    "Home Assistant accepted the unlock, but the lock entity "
                    "did not confirm unlocked"
                )
                _LOGGER.warning(
                    "Authorized HA unlock for %s remains unconfirmed: %s",
                    lock_name,
                    exc,
                )
                await self._log(
                    method=method,
                    result="accepted_unconfirmed",
                    user_id=user_id,
                    user_name=user_name,
                    lock_id=lock_id,
                    lock_name=lock_name,
                    reason=reason,
                )
                last_denied_reason = reason
                continue
            except AccessCommandAcceptedUnconfirmedError as exc:
                reason = (
                    "UniFi Access accepted the momentary unlock, but the "
                    "door relay did not confirm unlocked"
                )
                _LOGGER.warning(
                    "Authorized unlock for %s remains unconfirmed: %s",
                    lock_name,
                    exc,
                )
                await self._log(
                    method=method,
                    result="accepted_unconfirmed",
                    user_id=user_id,
                    user_name=user_name,
                    lock_id=lock_id,
                    lock_name=lock_name,
                    reason=reason,
                )
                last_denied_reason = reason
                continue
            except AccessCommandOutcomeUnknownError as exc:
                reason = (
                    "UniFi Access command outcome is unknown; the momentary "
                    "unlock may already have occurred"
                )
                _LOGGER.warning(
                    "Authorized unlock outcome for %s is unknown: %s",
                    lock_name,
                    exc,
                )
                await self._log(
                    method=method,
                    result="accepted_unconfirmed",
                    user_id=user_id,
                    user_name=user_name,
                    lock_id=lock_id,
                    lock_name=lock_name,
                    reason=reason,
                )
                last_denied_reason = reason
                continue
            except Exception as exc:
                _LOGGER.error("Unlock failed for lock %s: %s", lock_name, exc)
                await self._log(
                    method=method, result="error",
                    user_id=user_id, user_name=user_name,
                    lock_id=lock_id, lock_name=lock_name,
                    reason=f"Unlock error: {exc}",
                )
                continue

            if lockdown_won:
                reason = "Lockdown mode became active before unlock"
                _LOGGER.warning("Access DENIED for %s — %s", user_name, reason)
                await self._log(
                    method=method,
                    result="denied",
                    user_id=user_id,
                    user_name=user_name,
                    lock_id=lock_id,
                    lock_name=lock_name,
                    reason=reason,
                )
                last_denied_reason = reason
                continue

            # Step 7: Log granted
            await self._log(
                method=method, result="granted",
                user_id=user_id, user_name=user_name,
                lock_id=lock_id, lock_name=lock_name,
            )
            granted_locks.append(lock_name)
            any_granted = True

        # Fire HA event and auto-disarm if at least one lock was granted
        if any_granted:
            await self._fire_ha_event(
                user_id=user_id,
                user_name=user_name,
                ulp_id=ulp_id,
                location_id=location_id,
                method=method,
                locks=granted_locks,
            )
            # Auto-disarm reuses the SAME guarded predicate computed above:
            # a group that is blocked-when-armed for the current state must
            # not be able to trigger a disarm (otherwise a blocked user could
            # auto-disarm the panel on a single tap). can_disarm is False when
            # the panel is already disarmed, so this is a no-op then.
            if can_disarm:
                await self._auto_disarm(user_name)
            else:
                _LOGGER.info("Skipping auto-disarm — user %s has no eligible can_disarm group", user_name)
            return {
                "granted": True,
                "user_name": user_name,
                "reason": "Access granted",
                "locks": granted_locks,
            }

        return {
            "granted": False,
            "user_name": user_name,
            "reason": last_denied_reason,
            "locks": [],
        }

    # ------------------------------------------------------------------
    # Lock resolution
    # ------------------------------------------------------------------

    async def get_locks_for_location(self, location_id: str) -> list[dict]:
        """
        Return locks relevant to a given location_id.

        - Native locks: matched by location_id column.
        - HA external locks: matched via entry_devices table (access_reader type)
          or legacy access_location_id column.

        Public because this is THE canonical resolution — every consumer
        of "which locks live at this location" must use it. main.py's
        remote-relock path previously used only the DB column lookup and
        silently missed entry-device-paired locks, leaving doors unlocked
        after a remote unlock (e2e review 2026-07-12).
        """
        # Native locks by location_id + legacy access_location_id
        locks = [
            lock
            for lock in await self._db.get_locks_for_location(location_id)
            if not lock.get("hidden")
        ]
        seen_ids = {l["id"] for l in locks}

        # Access reader rows store the door/location id directly.
        ed_locks = await self._db.get_locks_by_entry_device(
            "access_reader", device_id=location_id
        )
        for lock in ed_locks:
            if not lock.get("hidden") and lock["id"] not in seen_ids:
                locks.append(lock)
                seen_ids.add(lock["id"])

        # Protect rows store a camera id. Protect-origin events already pass
        # that id; Access-origin events pass a door location, so resolve the
        # inverse of the live camera→location topology map as well.
        protect_device_ids = {location_id}
        if self._get_camera_map is not None:
            try:
                protect_device_ids.update(
                    camera_id
                    for camera_id, mapped_location in self._get_camera_map().items()
                    if mapped_location == location_id
                )
            except Exception:
                _LOGGER.exception("Failed to resolve camera mapping for %s", location_id)
        for device_id in protect_device_ids:
            ed_locks = await self._db.get_locks_by_entry_device(
                "protect_doorbell", device_id=device_id
            )
            for l in ed_locks:
                if not l.get("hidden") and l["id"] not in seen_ids:
                    locks.append(l)
                    seen_ids.add(l["id"])

        return locks

    # ------------------------------------------------------------------
    # Unlock dispatch
    # ------------------------------------------------------------------

    def _entity_command_lock(self, key: str) -> asyncio.Lock:
        """Serialize write+readback workflows for one physical endpoint."""
        return self._entity_command_locks.setdefault(key, asyncio.Lock())

    async def _unlock(self, lock: dict) -> None:
        """Dispatch unlock to the appropriate client based on lock type."""
        lock_type = lock.get("type", "")

        if lock_type == "access_native":
            await self._unlock_access_native(lock)

        elif lock_type == "ha_external":
            await self._unlock_ha_external(lock)

        else:
            raise ValueError(f"Unknown lock type: {lock_type!r}")

    async def _unlock_access_native(
        self,
        lock: dict,
        *,
        command_lock: asyncio.Lock | None = None,
        recheck_lockdown: bool = False,
    ) -> bool:
        key = str(lock.get("device_id") or lock.get("location_id") or "")
        async with self._entity_command_lock(f"access:{key}"):
            return await self._unlock_access_native_coordinated(
                lock,
                command_lock=command_lock,
                recheck_lockdown=recheck_lockdown,
            )

    async def _unlock_access_native_coordinated(
        self,
        lock: dict,
        *,
        command_lock: asyncio.Lock | None = None,
        recheck_lockdown: bool = False,
    ) -> bool:
        """Issue a native momentary write, then confirm official relay state."""
        location_id = lock.get("location_id")
        if not location_id:
            raise ValueError(
                f"Native lock {lock.get('name')} has no location_id"
            )

        access = None
        barrier_acquired = False
        device_id = lock.get("device_id")

        def mark_unknown() -> None:
            if device_id and self._on_lock_state is not None:
                self._on_lock_state(device_id, "unknown")

        def release_barrier() -> None:
            nonlocal barrier_acquired
            if barrier_acquired:
                command_lock.release()
                barrier_acquired = False

        async def issue_and_confirm() -> bool:
            nonlocal access
            if recheck_lockdown and self._lockdown:
                return False
            access = self._access_client
            if access is None:
                raise RuntimeError("UniFi Access client is unavailable")
            confirmed_command = getattr(
                access, "unlock_momentary_confirmed", None
            )
            try:
                if callable(confirmed_command):
                    confirmation = await confirmed_command(
                        location_id,
                        on_written=release_barrier,
                    )
                    if (
                        not isinstance(confirmation, dict)
                        or confirmation.get("state") != "unlocked"
                    ):
                        raise AccessCommandAcceptedUnconfirmedError(
                            "momentary unlock returned without exact unlocked "
                            "relay confirmation"
                        )
                else:
                    # Compatibility clients can issue the private mutation, but
                    # cannot promote acceptance into a physical relay result.
                    await access.unlock_momentary(location_id)
                    release_barrier()
                    raise AccessCommandAcceptedUnconfirmedError(
                        "momentary unlock accepted without authoritative readback"
                    )
            except BaseException:
                # Cancellation, transport loss, and bounded readback failure
                # can all occur after the controller observed the write.
                mark_unknown()
                raise
            return True

        try:
            if command_lock is None:
                issued = await issue_and_confirm()
            else:
                await command_lock.acquire()
                barrier_acquired = True
                if recheck_lockdown and self._lockdown:
                    return False
                issued = await issue_and_confirm()
        finally:
            release_barrier()

        if not issued:
            return False
        if self._on_lock_state is not None:
            if device_id:
                self._on_lock_state(device_id, "unlocked")
        _LOGGER.info(
            "Confirmed momentary unlock via Access API: lock=%s location=%s",
            lock.get("name"),
            location_id,
        )
        return True

    async def _unlock_ha_external(
        self,
        lock: dict,
        *,
        command_lock: asyncio.Lock | None = None,
        recheck_lockdown: bool = False,
    ) -> bool:
        entity_id = str(lock.get("entity_id") or "")
        async with self._entity_command_lock(f"ha:{entity_id}"):
            return await self._unlock_ha_external_coordinated(
                lock,
                command_lock=command_lock,
                recheck_lockdown=recheck_lockdown,
            )

    async def _unlock_ha_external_coordinated(
        self,
        lock: dict,
        *,
        command_lock: asyncio.Lock | None = None,
        recheck_lockdown: bool = False,
    ) -> bool:
        """Write, release the global barrier, then confirm a credential unlock.

        Returns False only when a last-moment lockdown recheck prevents the
        physical write. Every accepted HA write must be observed as exactly
        ``unlocked`` before the credential is reported as granted.
        """
        entity_id = lock.get("entity_id")
        if not entity_id:
            raise ValueError(f"HA external lock {lock.get('name')} has no entity_id")

        relock_manager = self._relock_manager
        relock_enabled = bool(lock.get("relock_on_device_auth"))
        if relock_enabled and relock_manager is None:
            raise RuntimeError(
                "Automatic relock is enabled but the relock manager is unavailable"
            )

        duration = lock.get("relock_duration", 30)
        ha = None
        accepted = False
        relock_intent = None
        paused_relock = None
        paused_needs_resolution = False
        physical_command_attempted = False
        state_confirmed = False
        ha_lease_stack = AsyncExitStack()
        await ha_lease_stack.__aenter__()

        async def issue_unlock() -> bool:
            nonlocal ha
            nonlocal accepted
            nonlocal relock_intent
            nonlocal paused_relock
            nonlocal paused_needs_resolution
            nonlocal physical_command_attempted

            if recheck_lockdown and self._lockdown:
                return False

            # Capture the currently-published client while holding the same
            # barrier used by settings swaps. Confirmation below intentionally
            # keeps using this client after the barrier is released.
            ha = self._ha_client
            if ha is None:
                raise RuntimeError("Home Assistant client is unavailable")
            # Acquire the lease while the client-publication barrier is held.
            # It then keeps this exact writer alive through readback after the
            # barrier is released.
            await ha_lease_stack.enter_async_context(
                ha_client_operation(ha)
            )

            if relock_enabled:
                # Persist the safety deadline before the physical unlock.
                relock_intent = await relock_manager.schedule(
                    entity_id=entity_id,
                    duration=duration,
                    lock_id=lock.get("id"),
                    lock_name=lock.get("name", entity_id),
                    source="device_auth",
                )
                if lock.get("sync_hub_state") and self._get_hub_sync is not None:
                    hub_sync = self._get_hub_sync()
                    if hub_sync is not None:
                        hub_sync.mark_access_momentary(
                            entity_id, float(duration)
                        )
            elif relock_manager is not None:
                paused_relock = await relock_manager.pause(entity_id)
                paused_needs_resolution = True
                # With credential relocking disabled, this is a deliberate
                # hold-open. Exclude its edge from HA-origin relock policy.
                if lock.get("sync_hub_state") and self._get_hub_sync is not None:
                    hub_sync = self._get_hub_sync()
                    if hub_sync is not None:
                        hub_sync.mark_app_initiated_unlock(entity_id)

            physical_command_attempted = True
            accepted = bool(await ha.unlock(entity_id))
            return True

        async def retain_intent() -> asyncio.CancelledError | None:
            nonlocal relock_intent
            intent = relock_intent
            cancellation = None
            if relock_manager is not None and intent is not None:
                _, cancellation = await _complete_safety_operation(
                    relock_manager.retain_after_uncertain_unlock(intent),
                    name=f"retain-device-relock-{entity_id}",
                )
            relock_intent = None
            return cancellation

        async def resume_paused() -> asyncio.CancelledError | None:
            nonlocal paused_needs_resolution
            cancellation = None
            if relock_manager is not None and paused_needs_resolution:
                _, cancellation = await _complete_safety_operation(
                    relock_manager.resume(paused_relock),
                    name=f"resume-device-relock-{entity_id}",
                )
            paused_needs_resolution = False
            return cancellation

        async def resolve_relock_safety() -> asyncio.CancelledError | None:
            if relock_intent is not None:
                return await retain_intent()
            if paused_needs_resolution:
                return await resume_paused()
            return None

        def mark_unknown_if_needed() -> None:
            if (
                physical_command_attempted
                and not state_confirmed
                and self._on_lock_state is not None
            ):
                self._on_lock_state(entity_id, "unknown")

        try:
            if command_lock is None:
                issued = await issue_unlock()
            else:
                async with command_lock:
                    issued = await issue_unlock()

            # The global physical-command barrier is no longer held from this
            # point onward. HA readback is bounded, but may be eventually
            # consistent and must not serialize unrelated door commands.
            if not issued:
                return False
            if not accepted:
                raise RuntimeError(
                    f"HA unlock call returned failure for {entity_id}"
                )
            if not await _confirm_ha_state(ha, entity_id, "unlocked"):
                raise HACommandAcceptedUnconfirmedError(
                    f"HA accepted unlock but {entity_id} was not confirmed unlocked"
                )

            state_confirmed = True
            if self._on_lock_state is not None:
                self._on_lock_state(entity_id, "unlocked")
            _LOGGER.info(
                "Confirmed unlock via HA API: lock=%s entity=%s",
                lock.get("name"),
                entity_id,
            )

            cancellation = None
            if relock_intent is not None:
                try:
                    _, cancellation = await _complete_safety_operation(
                        relock_manager.extend_after_success(
                            relock_intent, duration
                        ),
                        name=f"extend-device-relock-{entity_id}",
                    )
                except Exception:
                    # The original pre-unlock deadline remains durable/live.
                    _LOGGER.exception(
                        "Could not extend relock from unlock-success time for %s; "
                        "retaining earlier fail-safe deadline",
                        entity_id,
                    )
                relock_intent = None
            elif relock_manager is not None:
                # A confirmed hold-open supersedes the paused older timer.
                _, cancellation = await _complete_safety_operation(
                    relock_manager.cancel(entity_id),
                    name=f"cancel-device-relock-{entity_id}",
                )
                paused_needs_resolution = False

            if cancellation is not None:
                raise cancellation
            return True
        except asyncio.CancelledError:
            mark_unknown_if_needed()
            try:
                await resolve_relock_safety()
            except Exception:
                _LOGGER.exception(
                    "Failed to restore relock safety after cancelled unlock for %s",
                    entity_id,
                )
            raise
        except Exception:
            mark_unknown_if_needed()
            cancellation = None
            try:
                cancellation = await resolve_relock_safety()
            except Exception:
                _LOGGER.exception(
                    "Failed to restore relock safety after unlock failure for %s",
                    entity_id,
                )
            if cancellation is not None:
                raise cancellation
            raise
        finally:
            await ha_lease_stack.aclose()

    # ------------------------------------------------------------------
    # Schedule evaluation
    # ------------------------------------------------------------------

    def _check_schedule(self, rule: dict) -> bool:
        """
        Return True if the current time falls within the rule's schedule.

        Schedule fields on rule:
            schedule_days  — comma-separated day names, e.g. "mon,tue,wed,thu,fri"
            schedule_start — HH:MM (24-hour)
            schedule_end   — HH:MM (24-hour)

        Supports overnight windows such as 22:00–06:00 where end < start.
        An empty/missing schedule_days means all days are allowed.
        """
        now = datetime.now(tz=self._tz)
        current_day = DAY_NAMES[now.weekday()]
        current_time = now.time().replace(second=0, microsecond=0)

        # Parse time window first (needed for overnight day-boundary logic)
        start_str = rule.get("schedule_start") or ""
        end_str = rule.get("schedule_end") or ""
        start_t = end_t = None

        # An enabled schedule with exactly one bound is corrupt/incomplete.
        # Treat it as inactive rather than silently turning it into an
        # all-day grant. A days-only schedule remains a supported all-day
        # restriction, and a time-only schedule applies on every day.
        if bool(start_str) != bool(end_str):
            _LOGGER.warning(
                "Incomplete schedule time range: start=%r end=%r",
                start_str,
                end_str,
            )
            return False

        if start_str and end_str:
            try:
                start_h, start_m = (int(x) for x in start_str.split(":"))
                end_h, end_m = (int(x) for x in end_str.split(":"))
                start_t = time(start_h, start_m)
                end_t = time(end_h, end_m)
            except (ValueError, AttributeError, TypeError):
                _LOGGER.warning("Invalid schedule time format: start=%r end=%r", start_str, end_str)
                return False

        # Check day restriction — supports both name ("mon,tue") and index ("0,1") formats
        raw_days = rule.get("schedule_days") or ""
        if not raw_days.strip() and start_t is None:
            _LOGGER.warning(
                "Enabled schedule has no day or time restriction — failing closed"
            )
            return False
        if raw_days.strip():
            allowed_days = {d.strip().lower() for d in raw_days.split(",") if d.strip()}
            # Convert numeric indices to day names if needed
            if any(d.isdigit() for d in allowed_days):
                allowed_days = {DAY_NAMES[int(d)] if d.isdigit() and int(d) < 7 else d for d in allowed_days}

            # For overnight windows (e.g. 22:00–06:00), the after-midnight portion
            # belongs to the previous day's schedule. A tap at 01:00 Tuesday should
            # check if Monday is in allowed_days, not Tuesday.
            if start_t and end_t and start_t > end_t and current_time <= end_t:
                prev_day = DAY_NAMES[(now.weekday() - 1) % 7]
                if prev_day not in allowed_days:
                    return False
            elif current_day not in allowed_days:
                return False

        # Check time window
        if start_t is not None and end_t is not None:
            if start_t <= end_t:
                # Normal window: e.g. 08:00–18:00
                if not (start_t <= current_time <= end_t):
                    return False
            else:
                # Overnight window: e.g. 22:00–06:00
                if not (current_time >= start_t or current_time <= end_t):
                    return False

        return True

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _log(
        self,
        method: str,
        result: str,
        user_id: Optional[int] = None,
        user_name: Optional[str] = None,
        lock_id: Optional[int] = None,
        lock_name: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> None:
        """Write an entry to the access log, swallowing any DB errors."""
        try:
            await self._db.log_access(
                method=method,
                result=result,
                user_id=user_id,
                user_name=user_name,
                lock_id=lock_id,
                lock_name=lock_name,
                reason=reason,
            )
        except Exception as exc:
            _LOGGER.error("Failed to write access log: %s", exc)

    async def _fire_ha_event(
        self,
        user_id: int,
        user_name: str,
        ulp_id: str,
        location_id: str,
        method: str,
        locks: list[str],
    ) -> None:
        """Fire access_granted event on the HA event bus."""
        event_data = {
            "user_id": user_id,
            "user_name": user_name,
            "ulp_id": ulp_id,
            "location_id": location_id,
            "method": method,
            "locks": locks,
        }
        try:
            await self._ha_client.fire_event("access_control_granted", event_data)
            _LOGGER.debug("Fired HA event access_control_granted for %s", user_name)
        except Exception as exc:
            _LOGGER.error("Failed to fire HA event: %s", exc)

    async def _get_alarm_state(self) -> str:
        """Get the most restrictive alarm state across all configured panels.

        Returns 'disarmed' only when no panels are configured or all panels are disarmed.
        Returns 'unknown' on any error — callers treat unknown as restrictive.

        Cached for `_alarm_cache_ttl` seconds to avoid hammering HA on event bursts.
        """
        # Short-lived cache — bursts of access events shouldn't fan out to HA
        loop_time = asyncio.get_running_loop().time()
        if self._alarm_cache_value is not None and loop_time < self._alarm_cache_expires:
            return self._alarm_cache_value

        try:
            panels = await self._db.get_all_alarm_panels()
            if not panels:
                result = "disarmed"
            elif not self._ha_client:
                _LOGGER.error(
                    "Alarm panels are configured but HA is unavailable — "
                    "treating state as unknown"
                )
                return "unknown"
            else:
                # A scalar state is sufficient only when every armed panel
                # agrees. Unknown/unavailable values and mixed armed modes
                # are returned as ``unknown`` so both block flags are
                # evaluated conservatively by the caller. Previously an HA
                # state literally equal to ``unknown`` fell through to
                # ``disarmed``, and an away+home pair collapsed to away,
                # bypassing home-only blocking rules.
                known_states = {
                    "disarmed",
                    "triggered",
                    "armed_away",
                    "armed_home",
                    "armed_night",
                    "arming",
                    "pending",
                }
                fetched_states = await asyncio.gather(
                    *(
                        self._ha_client.get_entity_state(panel["entity_id"])
                        for panel in panels
                    ),
                    return_exceptions=True,
                )
                states: list[str] = []
                for panel, state in zip(panels, fetched_states):
                    if not isinstance(state, str) or state not in known_states:
                        _LOGGER.error(
                            "Failed to get alarm state for %s — treating as unknown",
                            panel["entity_id"],
                        )
                        # Don't cache the failure — retry on next event so we recover quickly
                        return "unknown"
                    states.append(state)
                armed_states = {state for state in states if state != "disarmed"}
                if not armed_states:
                    result = "disarmed"
                elif len(armed_states) == 1:
                    result = next(iter(armed_states))
                else:
                    _LOGGER.warning(
                        "Alarm panels report mixed armed states %s — treating as unknown",
                        sorted(armed_states),
                    )
                    result = "unknown"
        except Exception:
            _LOGGER.exception("Failed to get alarm state — treating as unknown")
            return "unknown"

        # Never cache the permissive state. If a panel arms immediately after
        # a disarmed read, even a 1.5s cache can grant on stale information.
        # Restrictive states are safe to coalesce during event bursts.
        if result != "disarmed":
            self._alarm_cache_value = result
            self._alarm_cache_expires = loop_time + self._alarm_cache_ttl
        else:
            self._alarm_cache_value = None
            self._alarm_cache_expires = 0.0
        return result

    async def _auto_disarm(self, user_name: str) -> None:
        """Disarm all configured alarm panels after a successful access grant."""
        any_success = False
        try:
            alarm_panels = await self._db.get_all_alarm_panels()
            for panel in alarm_panels:
                code = self._decrypt_panel_code(panel)
                async with self._command_lock:
                    if self._lockdown:
                        _LOGGER.warning(
                            "Stopping auto-disarm for %s — lockdown active",
                            user_name,
                        )
                        break
                    ha = self._ha_client
                    if ha is None:
                        return
                    ok = await ha.alarm_disarm(
                        panel["entity_id"], code=code
                    )
                if ok:
                    any_success = True
                    _LOGGER.info("Auto-disarmed %s after access by %s", panel["entity_id"], user_name)
                else:
                    _LOGGER.error("Auto-disarm FAILED for %s — HA service call returned failure", panel["entity_id"])
        except Exception as exc:
            _LOGGER.error("Auto-disarm FAILED: %s", exc)
        # Invalidate the alarm-state cache so the next event re-reads from HA
        # rather than returning the stale "armed" value we just disarmed away.
        if any_success:
            self._alarm_cache_value = None
            self._alarm_cache_expires = 0.0

    def _decrypt_panel_code(self, panel: dict) -> str | None:
        """Decrypt the disarm code for an alarm panel, or return None."""
        enc = panel.get("disarm_code_encrypted")
        if not enc or not self._enc_key:
            return None
        try:
            return decrypt_value(enc, self._enc_key)
        except Exception:
            _LOGGER.error("Failed to decrypt disarm code for %s", panel["entity_id"])
            return None
