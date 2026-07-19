"""Transport-neutral manual/API lock command execution.

The dashboard and Bearer API deliberately share this module.  Keeping the
physical-command barrier, lockdown recheck, durable re-lock handling, state
confirmation, cache update, audit, and auto-disarm in one place prevents the
two HTTP surfaces from acquiring subtly different safety semantics.
"""
from __future__ import annotations

import asyncio
import inspect
import logging
import time
from contextlib import AsyncExitStack
from dataclasses import dataclass
from typing import Literal

from .access_client import (
    AccessCommandAcceptedUnconfirmedError,
    AccessCommandOutcomeUnknownError,
)
from .config import decrypt_value
from .ha_client import ha_client_operation

logger = logging.getLogger(__name__)

LockAction = Literal["lock", "unlock", "buzz", "restore_schedule"]
LockOutcome = Literal[
    "granted",
    "accepted_unconfirmed",
    "denied",
    "error",
    "not_found",
]

# Restoring an Access schedule can immediately reopen a door when its unlock
# window is active, so it belongs on the same fail-closed path as unlock/buzz.
_DANGEROUS_DURING_LOCKDOWN = frozenset(
    {"unlock", "buzz", "restore_schedule"}
)
_HA_CONFIRM_ATTEMPTS = 3
_HA_CONFIRM_INTERVAL = 0.25


def publish_lock_state(
    state,
    entity_id: str,
    value: str,
    *,
    observed_at: float | None = None,
) -> bool:
    """Publish state unless a newer observation already owns the cache."""
    lock_states = getattr(state, "lock_states", None)
    if lock_states is None:
        lock_states = {}
        state.lock_states = lock_states
    updated_at = getattr(state, "lock_state_updated_at", None)
    if updated_at is None:
        updated_at = {}
        state.lock_state_updated_at = updated_at
    timestamp = (
        time.monotonic() if observed_at is None else float(observed_at)
    )
    if updated_at.get(entity_id, -1.0) > timestamp:
        return False
    lock_states[entity_id] = value
    updated_at[entity_id] = timestamp
    return True


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


def _has_authoritative_access_relay(access) -> bool:
    """Whether this exact client can read the official physical relay."""
    if access is None:
        return False
    configured = bool(vars(access).get("open_api_configured", False))
    if isinstance(
        getattr(type(access), "open_api_configured", None), property
    ):
        configured = bool(access.open_api_configured)
    return configured


async def _complete_safety_cleanup(
    awaitable, *, name: str
) -> asyncio.CancelledError | None:
    """Finish relock ownership cleanup even if the caller is cancelled again."""
    task = asyncio.create_task(awaitable, name=name)
    cancellation: asyncio.CancelledError | None = None
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError as exc:
            # Relock ownership must be resolved before cancellation escapes.
            if cancellation is None:
                cancellation = exc
    task.result()
    return cancellation


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
    entity_lock_acquired = False
    relock_intent = None
    paused_relock = None
    paused_needs_resolution = False
    physical_command_attempted = False
    entity_locks = getattr(state, "physical_entity_locks", None)
    if entity_locks is None:
        entity_locks = {}
        state.physical_entity_locks = entity_locks
    if lock["type"] == "ha_external":
        entity_key = f"ha:{lock.get('entity_id') or ''}"
    else:
        entity_key = (
            f"access:{lock.get('device_id') or lock.get('location_id') or ''}"
        )
    entity_lock = entity_locks.setdefault(entity_key, asyncio.Lock())

    def release_barrier_now() -> None:
        nonlocal command_lock_acquired
        if command_lock_acquired:
            command_lock.release()
            command_lock_acquired = False

    async def release_barrier() -> None:
        release_barrier_now()

    async def invoke_access_command(command, *args, **kwargs):
        """Release the global barrier after write acceptance, before readback."""
        nonlocal physical_command_attempted
        physical_command_attempted = True
        try:
            supports_hook = (
                "on_written" in inspect.signature(command).parameters
            )
        except (TypeError, ValueError):
            supports_hook = False
        if supports_hook:
            return await command(
                *args,
                **kwargs,
                on_written=release_barrier_now,
            )
        result = await command(*args, **kwargs)
        release_barrier_now()
        return result

    async def retain_intent() -> None:
        nonlocal relock_intent
        intent = relock_intent
        if relock_manager is not None and intent is not None:
            await relock_manager.retain_after_uncertain_unlock(intent)
        relock_intent = None

    async def resume_paused() -> None:
        nonlocal paused_needs_resolution
        if relock_manager is not None and paused_needs_resolution:
            await relock_manager.resume(paused_relock)
            paused_needs_resolution = False

    result: LockActionResult | None = None
    ha_lease_stack = AsyncExitStack()
    await ha_lease_stack.__aenter__()
    try:
        await entity_lock.acquire()
        entity_lock_acquired = True
        if command_lock is not None:
            await command_lock.acquire()
            command_lock_acquired = True

        # Fetch clients only after entering the client-publication barrier. A
        # request queued behind a Settings swap must not use the retired client.
        access = getattr(state, "access_client", None)
        ha = getattr(state, "ha_client", None)
        if lock["type"] == "ha_external" and ha is not None:
            # Enter while the publication barrier is held, then keep the exact
            # client alive after releasing that barrier for state readback.
            await ha_lease_stack.enter_async_context(
                ha_client_operation(ha)
            )

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
            else:
                try:
                    if action == "buzz":
                        if not location_id:
                            result = finish(
                                "error",
                                reason="Access location is not configured",
                            )
                        else:
                            confirmed_command = getattr(
                                access,
                                "unlock_momentary_confirmed",
                                None,
                            )
                            if callable(confirmed_command):
                                confirmation = await invoke_access_command(
                                    confirmed_command,
                                    location_id,
                                )
                                if (
                                    not isinstance(confirmation, dict)
                                    or confirmation.get("state") != "unlocked"
                                ):
                                    raise AccessCommandAcceptedUnconfirmedError(
                                        "momentary unlock returned without "
                                        "exact unlocked relay confirmation"
                                    )
                            else:
                                # Compatibility clients can still issue the
                                # write, but without official relay readback it
                                # must remain explicitly unconfirmed.
                                await invoke_access_command(
                                    access.unlock_momentary,
                                    location_id,
                                )
                                raise AccessCommandAcceptedUnconfirmedError(
                                    "momentary unlock accepted without "
                                    "authoritative relay readback"
                                )
                            if device_id:
                                publish_lock_state(
                                    state, device_id, "unlocked"
                                )
                            result = finish(
                                "granted", confirmed_state="unlocked"
                            )
                    elif not device_id:
                        result = finish(
                            "error",
                            reason="Access device is not configured",
                        )
                    elif action == "unlock":
                        confirmation = await invoke_access_command(
                            access.hold_unlocked,
                            device_id,
                            location_id=location_id,
                        )
                        if (
                            not _has_authoritative_access_relay(access)
                            or not isinstance(confirmation, dict)
                            or confirmation.get("state") != "unlocked"
                        ):
                            raise AccessCommandAcceptedUnconfirmedError(
                                "persistent unlock lacks authoritative "
                                "unlocked relay confirmation"
                            )
                        publish_lock_state(state, device_id, "unlocked")
                        result = finish(
                            "granted", confirmed_state="unlocked"
                        )
                    elif action == "lock":
                        confirmation = await invoke_access_command(
                            access.force_lock,
                            device_id,
                            location_id=location_id,
                        )
                        if (
                            not _has_authoritative_access_relay(access)
                            or not isinstance(confirmation, dict)
                            or confirmation.get("state") != "locked"
                        ):
                            raise AccessCommandAcceptedUnconfirmedError(
                                "immediate lock lacks authoritative locked "
                                "relay confirmation"
                            )
                        publish_lock_state(state, device_id, "locked")
                        result = finish("granted", confirmed_state="locked")
                    else:
                        confirmation = await invoke_access_command(
                            access.restore_native_rule,
                            device_id,
                            location_id=location_id,
                        )
                        # Restoring a schedule confirms the control rule, not a
                        # single physical state: the active schedule decides
                        # open vs closed.
                        observed_state = (
                            confirmation.get("state")
                            if isinstance(confirmation, dict)
                            else None
                        )
                        if (
                            not _has_authoritative_access_relay(access)
                            or observed_state not in {"locked", "unlocked"}
                        ):
                            raise AccessCommandAcceptedUnconfirmedError(
                                "schedule restore lacks authoritative relay "
                                "confirmation"
                            )
                        publish_lock_state(state, device_id, observed_state)
                        result = finish(
                            "granted", confirmed_state="scheduled"
                        )
                except AccessCommandAcceptedUnconfirmedError:
                    # The mutation may already be active. Do not publish a
                    # guessed state or permit the granted-only auto-disarm path.
                    release_barrier_now()
                    if device_id:
                        publish_lock_state(state, device_id, "unknown")
                    operation = {
                        "buzz": "momentary unlock",
                        "unlock": "persistent unlock",
                        "lock": "immediate lock",
                        "restore_schedule": "schedule restore",
                    }[action]
                    result = finish(
                        "accepted_unconfirmed",
                        reason=(
                            f"UniFi Access accepted the {operation}, "
                            "but the resulting door state is unconfirmed"
                        ),
                    )
                except AccessCommandOutcomeUnknownError:
                    # The transport failed after a mutating request began. The
                    # controller may already have applied it, so neither
                    # success nor a definite no-op is truthful.
                    release_barrier_now()
                    if device_id:
                        publish_lock_state(state, device_id, "unknown")
                    result = finish(
                        "accepted_unconfirmed",
                        reason=(
                            "UniFi Access command outcome is unknown; the "
                            "requested change may already be active"
                        ),
                    )

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
                    # A buzz on a bidirectionally synced lock is a momentary,
                    # app-owned timed unlock: lease it so the hub poller does
                    # not echo HA's temporary unlocked state back as a
                    # persistent Access keep_unlock override (which would also
                    # burn flap budget). Same duration semantics as the remote
                    # path; set before the physical unlock. The lease also marks
                    # the unlock app-initiated so relock_on_ha_origin ignores it.
                    if lock.get("sync_hub_state"):
                        hub_sync = getattr(state, "hub_sync_manager", None)
                        if hub_sync is not None:
                            hub_sync.mark_access_momentary(
                                entity_id, float(duration)
                            )
                    physical_command_attempted = True
                    accepted = await ha.unlock(entity_id)
                    await release_barrier()
                    confirmed = bool(
                        accepted
                        and await _confirm_ha_state(ha, entity_id, "unlocked")
                    )
                    if confirmed:
                        publish_lock_state(state, entity_id, "unlocked")
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
                        publish_lock_state(state, entity_id, "unknown")
                        result = finish(
                            (
                                "accepted_unconfirmed"
                                if accepted
                                else "error"
                            ),
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
                # A manual dashboard Unlock is a deliberate hold-open (it cancels
                # pending re-locks below). Mark it app-initiated with a short TTL
                # so relock_on_ha_origin does not observe this HA edge as an
                # external thumb-turn and time-bound the operator's hold-open.
                if action == "unlock" and lock.get("sync_hub_state"):
                    hub_sync = getattr(state, "hub_sync_manager", None)
                    if hub_sync is not None:
                        hub_sync.mark_app_initiated_unlock(entity_id)
                physical_command_attempted = True
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
                    publish_lock_state(state, entity_id, expected)
                    if relock_manager is not None:
                        await relock_manager.cancel(entity_id)
                        paused_needs_resolution = False
                    result = finish("granted", confirmed_state=expected)
                else:
                    await resume_paused()
                    publish_lock_state(state, entity_id, "unknown")
                    result = finish(
                        (
                            "accepted_unconfirmed"
                            if accepted
                            else "error"
                        ),
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
    except asyncio.CancelledError:
        # HA may have accepted the command even though the request task was
        # cancelled. Release the global physical-command barrier promptly, but
        # do not let cancellation strand a durable relock row in `_paused` (or
        # abandon a write-ahead timed-unlock intent) before propagating it.
        await release_barrier()
        if physical_command_attempted:
            if lock["type"] == "access_native" and lock.get("device_id"):
                publish_lock_state(
                    state, lock["device_id"], "unknown"
                )
            elif lock["type"] == "ha_external" and lock.get("entity_id"):
                publish_lock_state(
                    state, lock["entity_id"], "unknown"
                )
        try:
            if relock_intent is not None:
                await _complete_safety_cleanup(
                    retain_intent(),
                    name=f"retain-relock-after-cancel-{lock_id}",
                )
            elif paused_needs_resolution:
                await _complete_safety_cleanup(
                    resume_paused(),
                    name=f"resume-relock-after-cancel-{lock_id}",
                )
        except Exception:
            logger.exception(
                "Failed to restore relock safety after cancelled %s on lock %s",
                action,
                lock_id,
            )
        cancelled_result = finish(
            (
                "accepted_unconfirmed"
                if physical_command_attempted
                else "error"
            ),
            reason=(
                "Request cancelled after the upstream command was attempted; "
                "the resulting physical state is unknown"
                if physical_command_attempted
                else "Request cancelled before the upstream command completed"
            ),
        )
        try:
            await _complete_safety_cleanup(
                _audit_result(
                    db,
                    cancelled_result,
                    actor=actor,
                    source=source,
                ),
                name=f"audit-cancelled-lock-action-{lock_id}",
            )
        except Exception:
            logger.exception(
                "Failed to audit cancelled %s on lock %s",
                action,
                lock_id,
            )
        raise
    except Exception:
        logger.exception("Lock action %s failed for lock %s", action, lock_id)
        if physical_command_attempted:
            if lock["type"] == "access_native" and lock.get("device_id"):
                publish_lock_state(
                    state, lock["device_id"], "unknown"
                )
            elif lock["type"] == "ha_external" and lock.get("entity_id"):
                publish_lock_state(
                    state, lock["entity_id"], "unknown"
                )
        cancellation = None
        try:
            if relock_intent is not None:
                cancellation = await _complete_safety_cleanup(
                    retain_intent(),
                    name=f"retain-relock-after-error-{lock_id}",
                )
            elif paused_needs_resolution:
                cancellation = await _complete_safety_cleanup(
                    resume_paused(),
                    name=f"resume-relock-after-error-{lock_id}",
                )
        except Exception:
            logger.exception(
                "Failed to restore relock safety after %s on lock %s",
                action,
                lock_id,
            )
        if cancellation is not None:
            raise cancellation
        result = finish("error", reason="Upstream lock command failed")
    finally:
        await release_barrier()
        await ha_lease_stack.aclose()
        if entity_lock_acquired:
            entity_lock.release()

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
