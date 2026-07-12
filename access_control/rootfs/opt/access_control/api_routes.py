"""REST API endpoints for external consumers (HA integration, etc.)."""
from __future__ import annotations

import asyncio
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .api_auth import verify_api_key
from .lock_actions import LockActionResult, execute_lock_action
from .web_routes import _DAY_NAMES, _schedule_validation_error

router = APIRouter(prefix="/api")


class LockModeUpdate(BaseModel):
    """Explicit desired lock-control mode."""

    mode: Literal["force_locked", "hold_unlocked", "follow_schedule"]


class RuleScheduleUpdate(BaseModel):
    """Local authorization schedule persisted on an individual rule."""

    enabled: bool
    days: list[Literal["mon", "tue", "wed", "thu", "fri", "sat", "sun"]] = Field(
        default_factory=list
    )
    start: str | None = None
    end: str | None = None


_MODE_ACTION = {
    "force_locked": "lock",
    "hold_unlocked": "unlock",
    "follow_schedule": "restore_schedule",
}


def _require_scope(auth: dict, *allowed: str) -> None:
    if auth["scope"] not in allowed:
        raise HTTPException(
            status_code=403,
            detail=f"API key scope '{auth['scope']}' insufficient",
        )


@router.get("/health")
async def health(request: Request, auth: dict = Depends(verify_api_key)):
    """System health status."""
    # All scopes can read health — but require explicit allowlist rather
    # than implicit acceptance, so a future scope can't accidentally see
    # the health endpoint without an audit. (Audit 2026-05-24, M1.)
    _require_scope(auth, "full", "read_only", "locks_only")
    app = request.app
    access = app.state.access_client
    ha = app.state.ha_client
    db = app.state.db

    user_count = await db.get_user_count()
    lock_count = await db.get_lock_count()

    return {
        "status": "ok",
        "unvr_connected": access.connected if access else False,
        "access_open_api_configured": bool(
            access and getattr(access, "open_api_configured", False)
        ),
        "access_open_api_ready": bool(
            getattr(app.state, "access_open_api_ready", False)
        ),
        "access_open_api_error": getattr(
            app.state, "access_open_api_error", None
        ),
        "protect_connected": app.state.protect_client.connected if app.state.protect_client else False,
        "ha_connected": ha.connected if ha else False,
        "ha_last_error": ha.last_error if ha else None,
        "ha_circuit_state": ha.circuit_state if ha else "closed",
        "websocket_connected": access.ws_connected if access else False,
        "user_count": user_count,
        "lock_count": lock_count,
        "lockdown": app.state.auth_engine.lockdown if app.state.auth_engine else False,
        "lockdown_enforcement_pending": list(
            getattr(app.state.hub_sync_manager, "lockdown_unresolved", ())
            if getattr(app.state, "hub_sync_manager", None)
            else ()
        ),
    }


@router.get("/log")
async def get_log(
    request: Request,
    limit: int = Query(default=50, ge=1, le=1000),
    auth: dict = Depends(verify_api_key),
):
    """Get recent access log."""
    _require_scope(auth, "full", "read_only")
    db = request.app.state.db
    entries = await db.get_recent_log(limit)
    return {"entries": entries}


@router.post("/lockdown")
async def set_lockdown(
    request: Request,
    enabled: bool = Query(..., description="Explicit desired lockdown state"),
    auth: dict = Depends(verify_api_key),
):
    """Idempotently set lockdown to an explicit desired state."""
    _require_scope(auth, "full")
    engine = request.app.state.auth_engine
    if engine is None:
        raise HTTPException(status_code=503, detail="Authorization engine unavailable")
    try:
        await engine.set_lockdown(enabled)
    except RuntimeError as exc:
        # The engine deliberately retains the requested fail-closed in-memory
        # state; 503 tells automation that durable/physical convergence still
        # needs operator attention or a retry.
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {"lockdown": engine.lockdown}


@router.get("/locks")
async def get_locks(request: Request, auth: dict = Depends(verify_api_key)):
    """Get all locks with current state."""
    _require_scope(auth, "full", "read_only", "locks_only")
    db = request.app.state.db
    locks = await db.get_all_locks()
    return {"locks": locks}


def _command_response(result: LockActionResult, mode: str) -> dict:
    return {
        "lock_id": result.lock_id,
        "mode": mode,
        "result": result.outcome,
        "confirmed": result.granted and result.confirmed_state is not None,
        "confirmed_state": result.confirmed_state,
        "reason": result.reason,
    }


@router.put("/locks/{lock_id}/mode")
async def set_lock_mode(
    lock_id: int,
    update: LockModeUpdate,
    request: Request,
    auth: dict = Depends(verify_api_key),
):
    """Idempotently set a lock override mode and confirm upstream state."""
    _require_scope(auth, "full", "locks_only")
    result = await execute_lock_action(
        request.app.state,
        lock_id,
        _MODE_ACTION[update.mode],
        actor=f"api:{auth.get('name') or 'unnamed-key'}",
        source="api",
        # A locks_only credential can operate locks but must not inherit the
        # browser's separate alarm-panel side effect.
        auto_disarm=auth["scope"] == "full",
    )
    payload = _command_response(result, update.mode)
    status_code = {
        "granted": 200,
        "not_found": 404,
        "denied": 409,
        "error": 503,
    }[result.outcome]
    if status_code != 200:
        return JSONResponse(status_code=status_code, content=payload)
    return payload


@router.put("/rules/{rule_id}/schedule")
async def set_rule_schedule(
    rule_id: int,
    update: RuleScheduleUpdate,
    request: Request,
    auth: dict = Depends(verify_api_key),
):
    """Idempotently replace one local authorization rule's schedule."""
    _require_scope(auth, "full")
    db = request.app.state.db
    rule = await db.get_rule(rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")

    start = update.start.strip() if update.start else None
    end = update.end.strip() if update.end else None
    start = start or None
    end = end or None
    selected_days = set(update.days)
    days = ",".join(day for day in _DAY_NAMES if day in selected_days) or None
    schedule_error = _schedule_validation_error(
        enabled=update.enabled,
        days=days,
        start=start,
        end=end,
    )
    if schedule_error:
        raise HTTPException(status_code=422, detail=schedule_error)

    await db.update_rule(
        rule_id,
        enabled=bool(rule["enabled"]),
        schedule_enabled=update.enabled,
        schedule_days=days,
        schedule_start=start,
        schedule_end=end,
    )
    return {
        "rule_id": rule_id,
        "user_id": rule["user_id"],
        "enabled": bool(rule["enabled"]),
        "schedule": {
            "enabled": update.enabled,
            "days": [day for day in _DAY_NAMES if day in selected_days],
            "start": start,
            "end": end,
        },
    }


@router.get("/users")
async def get_users(request: Request, auth: dict = Depends(verify_api_key)):
    """Get all users."""
    _require_scope(auth, "full", "read_only")
    db = request.app.state.db
    users = [
        {
            key: user.get(key)
            for key in (
                "id",
                "ulp_id",
                "name",
                "email",
                "status",
                "hidden",
                "synced_at",
                "rule_count",
            )
        }
        for user in await db.get_all_users()
    ]
    return {"users": users}


@router.get("/debug")
async def debug_info(request: Request, auth: dict = Depends(verify_api_key)):
    """Internal diagnostic state — reconnect counters, circuit state, last events."""
    _require_scope(auth, "full")
    app = request.app
    access = app.state.access_client
    protect = app.state.protect_client
    ha = app.state.ha_client
    rm = getattr(app.state, "relock_manager", None)
    db = app.state.db

    _loop_time = asyncio.get_running_loop().time()

    pending_relocks_db = 0
    try:
        pending_relocks_db = len(await db.get_pending_relocks())
    except Exception:
        # Diagnostics must not fail just because this count is unavailable,
        # but the underlying DB problem still belongs in the server log.
        import logging

        logging.getLogger(__name__).exception("Failed to count pending relocks")

    return {
        "access_closed_connections": access.reconnect_count if access else 0,
        "protect_closed_connections": protect.reconnect_count if protect else 0,
        "access_ws_connected": access.ws_connected if access else False,
        "protect_ws_connected": protect.ws_connected if protect else False,
        "access_secs_since_last_event": (
            round(_loop_time - access.last_event_at, 1) if (access and access.last_event_at > 0) else None
        ),
        "protect_secs_since_last_event": (
            round(_loop_time - protect.last_event_at, 1) if (protect and protect.last_event_at > 0) else None
        ),
        "ha_connected": ha.connected if ha else False,
        "ha_last_error": ha.last_error if ha else None,
        "ha_circuit_state": ha.circuit_state if ha else "closed",
        "ws_last_event": app.state.ws_last_event,
        "pending_relocks_live": len(rm.tasks) if rm else 0,
        "pending_relocks_db": pending_relocks_db,
    }
