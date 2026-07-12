"""Transport-neutral manual/API lock command execution.

The dashboard and Bearer API deliberately share this module.  Keeping the
physical-command barrier, lockdown recheck, durable re-lock handling, state
confirmation, cache update, audit, and auto-disarm in one place prevents the
two HTTP surfaces from acquiring subtly different safety semantics.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Literal

from .config import decrypt_value

logger = logging.getLogger(__name__)

LockAction = Literal["lock", "unlock", "buzz", "restore_schedule"]
LockOutcome = Literal["granted", "denied", "error", "not_found"]

# Restoring an Access schedule can immediately reopen a door when its unlock
# window is active, so it belongs on the same fail-closed path as unlock/buzz.
_DANGEROUS_DURING_LOCKDOWN = frozenset(
    {"unlock", "buzz", "restore_schedule"}
)
_HA_CONFIRM_ATTEMPTS = 3
_HA_CONFIRM_INTERVAL = 0.25


@dataclass(frozen=True)
class LockActionResult:
    """Sanitized result suitable for either an HTML or JSON adapter."""

    lock_id: int
    action: LockAction
    outcome: LockOutcome
    reason: str | None = None
    confirmed_state: str | None = None
    lock_name: str | None = None

    @property
    def granted(self) -> bool:
        return self.outcome == "granted"


async def _confirm_ha_state(ha, entity_id: str, expected: str) -> bool:
    """Boundedly confirm a state using the client that accepted the command."""
    for attempt in range(_HA_CONFIRM_ATTEMPTS):
        if await ha.get_entity_state(entity_id) == expected:
            return True
        if attempt < _HA_CONFIRM_ATTEMPTS - 1:
            await asyncio.sleep(_HA_CONFIRM_INTERVAL)
    return False


def _lockdown_active(state) -> bool:
    engine = getattr(state, "auth_engine", None)
    return bool(engine and engine.lockdown)


def _decrypt_panel_code(state, panel: dict) -> str | None:
    encrypted = panel.get("disarm_code_encrypted")
    if not encrypted:
        return None
    try:
        return decrypt_value(encrypted, getattr(state, "enc_key", None))
    except Exception:
        logger.error("Failed to decrypt disarm code for %s", panel["entity_id"])
        return None


async def _audit_result(
    db,
    result: LockActionResult,
    *,
    actor: str,
    source: str,
) -> None:
    if result.outcome == "not_found":
        return
    await db.log_access(
        method=f"{source}_{result.action}",
        result=result.outcome,
        lock_id=result.lock_id,
        lock_name=result.lock_name,
        user_name=actor,
        reason=result.reason,
    )


async def _auto_disarm(
    state,
    *,
    db,
    command_lock,
    lock: dict,
    action: LockAction,
    actor: str,
    source: str,
) -> None:
    """Preserve dashboard auto-disarm semantics for every command transport."""
    if _lockdown_active(state):
        logger.warning("Skipping %s auto-disarm -- lockdown became active", source)
        return

    for panel in await db.get_all_alarm_panels():
        try:
            code = _decrypt_panel_code(state, panel)
            if command_lock is not None:
                async with command_lock:
                    if _lockdown_active(state):
                        logger.warning("Stopping %s auto-disarm -- lockdown active", source)
                        break
                    ha = getattr(state, "ha_client", None)
                    if ha is None:
                        return
                    ok = await ha.alarm_disarm(panel["entity_id"], code=code)
            else:
                ha = getattr(state, "ha_client", None)
                if ha is None:
                    return
                ok = await ha.alarm_disarm(panel["entity_id"], code=code)

            if ok:
                logger.info(
                    "Auto-disarmed %s after %s on %s",
                    panel["entity_id"],
                    action,
                    lock.get("name"),
                )
            else:
                logger.error(
                    "Auto-disarm returned failure for %s after %s on %s",
                    panel["entity_id"],
                    action,
                    lock.get("name"),
                )
            await db.log_access(
                method=f"{source}_auto_disarm",
                result="granted" if ok else "error",
                user_name=actor,
                lock_id=lock["id"],
                lock_name=lock.get("name"),
                reason=(
                    f"Disarmed {panel['entity_id']}"
                    if ok
                    else f"HA rejected disarm for {panel['entity_id']}"
                ),
            )
        except Exception:
            logger.exception("Failed to auto-disarm %s", panel["entity_id"])
            try:
                await db.log_access(
                    method=f"{source}_auto_disarm",
                    result="error",
                    user_name=actor,
                    lock_id=lock["id"],
                    lock_name=lock.get("name"),
                    reason=f"Disarm raised for {panel['entity_id']}",
                )
            except Exception:
                logger.exception("Failed to audit auto-disarm error")


async def execute_lock_action(
    state,
    lock_id: int,
    action: LockAction,
    *,
    actor: str,
    source: str,
    auto_disarm: bool = True,
) -> LockActionResult:
    """Execute and confirm a lock action independent of its HTTP transport."""
    if action not in {"lock", "unlock", "buzz", "restore_schedule"}:
        raise ValueError(f"Unsupported lock action: {action}")

    db = state.db
    lock = await db.get_lock(lock_id)
    if lock is None:
        return LockActionResult(
            lock_id,
            action,
            "not_found",
            reason="Lock not found",
        )

    def finish(
        outcome: LockOutcome,
        *,
        reason: str | None = None,
        confirmed_state: str | None = None,
    ) -> LockActionResult:
        return LockActionResult(
            lock_id,
            action,
            outcome,
            reason=reason,
            confirmed_state=confirmed_state,
            lock_name=lock.get("name"),
        )

    if action in _DANGEROUS_DURING_LOCKDOWN and _lockdown_active(state):
        result = finish("denied", reason="Lockdown mode active")
        await _audit_result(db, result, actor=actor, source=source)
        return result
    if action == "buzz" and not lock.get("buzz_enabled"):
        result = finish("denied", reason="Buzz is disabled for this lock")
        await _audit_result(db, result, actor=actor, source=source)
        return result

    relock_manager = getattr(state, "relock_manager", None)
    command_lock = getattr(state, "physical_command_lock", None)
    command_lock_acquired = False
    relock_intent = None
    paused_relock = None
    paused_needs_resolution = False

    async def release_barrier() -> None:
        nonlocal command_lock_acquired
        if command_lock_acquired:
            command_lock.release()
            command_lock_acquired = False

    async def retain_intent() -> None:
        nonlocal relock_intent
        intent = relock_intent
        relock_intent = None
        if relock_manager is not None and intent is not None:
            await relock_manager.retain_after_uncertain_unlock(intent)

    async def resume_paused() -> None:
        nonlocal paused_needs_resolution
        if relock_manager is not None and paused_needs_resolution:
            paused_needs_resolution = False
            await relock_manager.resume(paused_relock)

    result: LockActionResult | None = None
    try:
        if command_lock is not None:
            await command_lock.acquire()
            command_lock_acquired = True

        # Fetch clients only after entering the client-publication barrier. A
        # request queued behind a Settings swap must not use the retired client.
        access = getattr(state, "access_client", None)
        ha = getattr(state, "ha_client", None)

        # Force-lock is the only fail-safe direction that stays available
        # during lockdown. Restoring an active schedule may open the door.
        if action in _DANGEROUS_DURING_LOCKDOWN and _lockdown_active(state):
            await release_barrier()
            result = finish("denied", reason="Lockdown mode active")
        elif lock["type"] == "access_native":
            device_id = lock.get("device_id")
            location_id = lock.get("location_id")
            if access is None:
                result = finish("error", reason="Access client unavailable")
            elif action == "buzz":
                if not location_id:
                    result = finish(
                        "error", reason="Access location is not configured"
                    )
                else:
                    await access.unlock_momentary(location_id)
                    result = finish("granted", confirmed_state="momentary")
            elif not device_id:
                result = finish(
                    "error", reason="Access device is not configured"
                )
            elif action == "unlock":
                await access.hold_unlocked(
                    device_id, location_id=location_id
                )
                state.lock_states[device_id] = "unlocked"
                result = finish("granted", confirmed_state="unlocked")
            elif action == "lock":
                await access.force_lock(device_id, location_id=location_id)
                state.lock_states[device_id] = "locked"
                result = finish("granted", confirmed_state="locked")
            else:
                confirmation = await access.restore_native_rule(
                    device_id, location_id=location_id
                )
                # Restoring a schedule confirms the control rule, not a single
                # physical state: the active schedule decides open vs closed.
                observed_state = (
                    confirmation.get("state")
                    if isinstance(confirmation, dict)
                    else None
                )
                if observed_state in {"locked", "unlocked"}:
                    state.lock_states[device_id] = observed_state
                result = finish("granted", confirmed_state="scheduled")

        elif lock["type"] == "ha_external":
            entity_id = lock.get("entity_id")
            if action == "restore_schedule":
                result = finish(
                    "denied",
                    reason="Follow-schedule mode is only available for native Access locks",
                )
            elif ha is None or not entity_id:
                result = finish(
                    "error",
                    reason="Home Assistant client or lock entity is unavailable",
                )
            elif action == "buzz":
                if relock_manager is None:
                    result = finish(
                        "error",
                        reason="Relock manager unavailable; timed unlock refused",
                    )
                else:
                    duration = lock.get("relock_duration", 30)
                    relock_intent = await relock_manager.schedule(
                        entity_id=entity_id,
                        duration=duration,
                        lock_id=lock_id,
                        lock_name=lock.get("name", entity_id),
                        source="buzz",
                    )
                    accepted = await ha.unlock(entity_id)
                    await release_barrier()
                    confirmed = bool(
                        accepted
                        and await _confirm_ha_state(ha, entity_id, "unlocked")
                    )
                    if confirmed:
                        state.lock_states[entity_id] = "unlocked"
                        try:
                            await relock_manager.extend_after_success(
                                relock_intent, duration
                            )
                        except Exception:
                            logger.exception(
                                "Could not extend buzz relock for %s; earlier deadline retained",
                                entity_id,
                            )
                        relock_intent = None
                        result = finish(
                            "granted", confirmed_state="unlocked"
                        )
                    else:
                        await retain_intent()
                        result = finish(
                            "error",
                            reason=(
                                "Home Assistant accepted unlock but did not confirm unlocked"
                                if accepted
                                else "Home Assistant rejected unlock"
                            ),
                        )
            else:
                if relock_manager is not None:
                    paused_relock = await relock_manager.pause(entity_id)
                    paused_needs_resolution = True
                accepted = (
                    await ha.unlock(entity_id)
                    if action == "unlock"
                    else await ha.lock(entity_id)
                )
                await release_barrier()
                expected = "unlocked" if action == "unlock" else "locked"
                confirmed = bool(
                    accepted
                    and await _confirm_ha_state(ha, entity_id, expected)
                )
                if confirmed:
                    state.lock_states[entity_id] = expected
                    if relock_manager is not None:
                        await relock_manager.cancel(entity_id)
                        paused_needs_resolution = False
                    result = finish("granted", confirmed_state=expected)
                else:
                    await resume_paused()
                    result = finish(
                        "error",
                        reason=(
                            f"HA accepted {action} command but entity was not confirmed {expected}"
                            if accepted
                            else f"HA {action} call failed"
                        ),
                    )
        else:
            result = finish(
                "denied", reason=f"Unsupported lock type: {lock['type']}"
            )
    except Exception:
        logger.exception("Lock action %s failed for lock %s", action, lock_id)
        try:
            if relock_intent is not None:
                await retain_intent()
            elif paused_needs_resolution:
                await resume_paused()
        except Exception:
            logger.exception(
                "Failed to restore relock safety after %s on lock %s",
                action,
                lock_id,
            )
        result = finish("error", reason="Upstream lock command failed")
    finally:
        await release_barrier()

    assert result is not None
    await _audit_result(db, result, actor=actor, source=source)
    if auto_disarm and result.granted and action in {"unlock", "buzz"}:
        await _auto_disarm(
            state,
            db=db,
            command_lock=command_lock,
            lock=lock,
            action=action,
            actor=actor,
            source=source,
        )
    return result
