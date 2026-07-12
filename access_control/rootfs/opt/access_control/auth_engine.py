"""
Authorization engine for the Access Control App.

Evaluates NFC/face events against access rules and executes unlock commands.
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, time, timezone, tzinfo
from typing import Optional
from zoneinfo import ZoneInfo

from .access_client import AccessClient, AccessClientError
from .config import decrypt_value
from .database import Database
from .ha_client import HAClient

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
    ) -> None:
        self._db = db
        self._access_client = access_client
        self._ha_client = ha_client
        self._lockdown: bool = False
        self._relock_tasks: dict[str, asyncio.Task] = relock_tasks if relock_tasks is not None else {}
        self._enc_key = enc_key
        self._relock_manager = relock_manager
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
        """
        Set lockdown mode AND persist it to the config table.

        Lockdown is an incident-response control: it must survive a restart
        (scheduled reboot, Supervisor watchdog, HAOS update). Persisting here
        — rather than in a synchronous property setter that can't await a DB
        write — is what keeps the door locked across a restart mid-incident.
        Callers MUST use this instead of assigning `.lockdown` directly.
        """
        self._lockdown = bool(value)
        _LOGGER.warning("Lockdown mode %s", "ENABLED" if self._lockdown else "DISABLED")
        try:
            await self._db.set_config("lockdown", "1" if self._lockdown else "0")
        except Exception:
            # Fail loud but don't crash the toggle — the in-memory flag is set,
            # and an operator enabling lockdown during an incident must not get
            # an error back. The persistence gap is logged for follow-up.
            _LOGGER.exception("Failed to persist lockdown state to config table")

    async def load_persisted_lockdown(self) -> None:
        """
        Restore lockdown mode from the config table on startup.

        Fail-safe: if the row can't be read, lockdown stays disabled (the
        prior behavior), but a persisted ENABLED state is honored so an
        incident lockdown is not silently dropped by a restart.
        """
        try:
            value = await self._db.get_config("lockdown")
        except Exception:
            _LOGGER.exception("Failed to read persisted lockdown — leaving disabled")
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

            # Step 6: Authorized — unlock
            try:
                await self._unlock(lock)
            except Exception as exc:
                _LOGGER.error("Unlock failed for lock %s: %s", lock_name, exc)
                await self._log(
                    method=method, result="error",
                    user_id=user_id, user_name=user_name,
                    lock_id=lock_id, lock_name=lock_name,
                    reason=f"Unlock error: {exc}",
                )
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
        locks = await self._db.get_locks_for_location(location_id)
        seen_ids = {l["id"] for l in locks}

        # Check entry_devices for access_reader and protect_doorbell mappings
        for device_type in ("access_reader", "protect_doorbell"):
            ed_locks = await self._db.get_locks_by_entry_device(device_type, device_id=location_id)
            for l in ed_locks:
                if l["id"] not in seen_ids:
                    locks.append(l)
                    seen_ids.add(l["id"])

        return locks

    # ------------------------------------------------------------------
    # Unlock dispatch
    # ------------------------------------------------------------------

    async def _unlock(self, lock: dict) -> None:
        """Dispatch unlock to the appropriate client based on lock type."""
        lock_type = lock.get("type", "")

        if lock_type == "access_native":
            location_id = lock.get("location_id")
            if not location_id:
                raise ValueError(f"Native lock {lock.get('name')} has no location_id")
            await self._access_client.unlock_momentary(location_id)
            _LOGGER.info("Momentary unlock via Access API: lock=%s location=%s",
                         lock.get("name"), location_id)

        elif lock_type == "ha_external":
            entity_id = lock.get("entity_id")
            if not entity_id:
                raise ValueError(f"HA external lock {lock.get('name')} has no entity_id")
            success = await self._ha_client.unlock(entity_id)
            if not success:
                raise RuntimeError(f"HA unlock call returned failure for {entity_id}")
            _LOGGER.info("Unlock via HA API: lock=%s entity=%s", lock.get("name"), entity_id)

            # Schedule device-auth re-lock if enabled
            if lock.get("relock_on_device_auth") and self._relock_manager is not None:
                await self._relock_manager.schedule(
                    entity_id=entity_id,
                    duration=lock.get("relock_duration", 30),
                    lock_id=lock.get("id"),
                    lock_name=lock.get("name", entity_id),
                    source="device_auth",
                )

        else:
            raise ValueError(f"Unknown lock type: {lock_type!r}")

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

        if start_str and end_str:
            try:
                start_h, start_m = (int(x) for x in start_str.split(":"))
                end_h, end_m = (int(x) for x in end_str.split(":"))
            except (ValueError, AttributeError):
                _LOGGER.warning("Invalid schedule time format: start=%r end=%r", start_str, end_str)
                return False
            start_t = time(start_h, start_m)
            end_t = time(end_h, end_m)

        # Check day restriction — supports both name ("mon,tue") and index ("0,1") formats
        raw_days = rule.get("schedule_days") or ""
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
        if not self._ha_client:
            return "disarmed"

        # Short-lived cache — bursts of access events shouldn't fan out to HA
        loop_time = asyncio.get_running_loop().time()
        if self._alarm_cache_value is not None and loop_time < self._alarm_cache_expires:
            return self._alarm_cache_value

        try:
            panels = await self._db.get_all_alarm_panels()
            if not panels:
                result = "disarmed"
            else:
                # Return the most restrictive state across all panels
                priority = ["triggered", "armed_away", "armed_home", "armed_night", "arming", "pending"]
                states: list[str] = []
                result = "disarmed"
                for panel in panels:
                    state = await self._ha_client.get_entity_state(panel["entity_id"])
                    if state is None:
                        _LOGGER.error("Failed to get alarm state for %s — treating as unknown", panel["entity_id"])
                        # Don't cache the failure — retry on next event so we recover quickly
                        return "unknown"
                    states.append(state)
                for p in priority:
                    if p in states:
                        result = p
                        break
        except Exception:
            _LOGGER.exception("Failed to get alarm state — treating as unknown")
            return "unknown"

        self._alarm_cache_value = result
        self._alarm_cache_expires = loop_time + self._alarm_cache_ttl
        return result

    async def _auto_disarm(self, user_name: str) -> None:
        """Disarm all configured alarm panels after a successful access grant."""
        if not self._ha_client:
            return
        any_success = False
        try:
            alarm_panels = await self._db.get_all_alarm_panels()
            for panel in alarm_panels:
                code = self._decrypt_panel_code(panel)
                ok = await self._ha_client.alarm_disarm(panel["entity_id"], code=code)
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
