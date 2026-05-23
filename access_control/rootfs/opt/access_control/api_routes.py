"""REST API endpoints for external consumers (HA integration, etc.)."""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from .api_auth import verify_api_key

router = APIRouter(prefix="/api")


def _require_scope(auth: dict, *allowed: str) -> None:
    if auth["scope"] not in allowed:
        raise HTTPException(
            status_code=403,
            detail=f"API key scope '{auth['scope']}' insufficient",
        )


@router.get("/health")
async def health(request: Request, auth: dict = Depends(verify_api_key)):
    """System health status."""
    app = request.app
    access = app.state.access_client
    ha = app.state.ha_client
    db = app.state.db

    user_count = await db.get_user_count()
    lock_count = await db.get_lock_count()

    return {
        "status": "ok",
        "unvr_connected": access.connected if access else False,
        "protect_connected": app.state.protect_client.connected if app.state.protect_client else False,
        "ha_connected": ha.connected if ha else False,
        "ha_last_error": ha.last_error if ha else None,
        "ha_circuit_state": ha.circuit_state if ha else "closed",
        "websocket_connected": access.ws_connected if access else False,
        "user_count": user_count,
        "lock_count": lock_count,
        "lockdown": app.state.auth_engine.lockdown if app.state.auth_engine else False,
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
async def toggle_lockdown(request: Request, auth: dict = Depends(verify_api_key)):
    """Toggle lockdown mode."""
    _require_scope(auth, "full")
    engine = request.app.state.auth_engine
    engine.lockdown = not engine.lockdown
    return {"lockdown": engine.lockdown}


@router.get("/locks")
async def get_locks(request: Request, auth: dict = Depends(verify_api_key)):
    """Get all locks with current state."""
    _require_scope(auth, "full", "read_only", "locks_only")
    db = request.app.state.db
    locks = await db.get_all_locks()
    return {"locks": locks}


@router.get("/users")
async def get_users(request: Request, auth: dict = Depends(verify_api_key)):
    """Get all users."""
    _require_scope(auth, "full", "read_only")
    db = request.app.state.db
    users = await db.get_all_users()
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
        pass

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
