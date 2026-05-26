"""Dashboard HTML routes for the Access Control App."""
from __future__ import annotations

import asyncio
import logging
import os
import re
import shlex
import sqlite3
from pathlib import Path
from urllib.parse import quote_plus

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .access_client import AccessClient, AccessClientError
from .protect_client import ProtectClient
from .config import (
    decrypt_value,
    derive_key,
    encrypt_value,
    generate_api_key,
    hash_api_key,
    hash_password,
    verify_password,
)
from .ha_client import HAClient
from . import web_auth
from .web_auth import (
    clear_session_cookie,
    generate_csrf_token,
    get_session_user,
    refresh_session_cookie,  # noqa: F401  (re-exported for backward compat)
    require_csrf,
    require_login,
    set_session_cookie,
)

logger = logging.getLogger(__name__)

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


# --- Jinja filters --------------------------------------------------------

# Map raw credential / method strings (from UniFi event payloads + our
# legacy paths) to human-readable display labels. Used by the Activity
# Log and per-lock history pages so values render as `NFC` / `PIN` /
# `Face` instead of `Nfc` / `Pin_code` / `Face`.
_CREDENTIAL_LABELS: dict[str, str] = {
    # UniFi Access reader credentials (G6 Entry Pro, NFC pad, Hub)
    "nfc": "NFC",
    "pin_code": "PIN",
    "pin": "PIN",
    "face": "Face",
    "fingerprint": "Fingerprint",
    # UniFi Access legacy / non-G6 method values
    "remote_unlock": "Remote unlock",
    "remote_through_uah": "Remote (UniFi app)",
    "device_auth": "Device auth",
    "access_device": "Reader",
    # UniFi Protect (doorbell-driven flows)
    "doorbell_ring": "Doorbell ring",
    # Manual actions issued from the in-app dashboard
    "manual": "Manual",
    "manual_unlock": "Manual unlock",
    "manual_lock": "Manual lock",
    "manual_buzz": "Manual buzz",
    "buzz": "Buzz",
    # Internal / synthetic events
    "system": "System",
}


def _credential_label(value: str | None) -> str:
    """Display label for a credential / authentication method.

    Unknown values fall back to a title-cased version of the raw string,
    with underscores swapped for spaces — so a new UniFi method we don't
    know about still renders reasonably.
    """
    if not value:
        return "—"
    key = str(value).strip().lower()
    if key in _CREDENTIAL_LABELS:
        return _CREDENTIAL_LABELS[key]
    return str(value).replace("_", " ").strip().title()


try:
    templates.env.filters["credential_label"] = _credential_label
except AttributeError:
    # Test suites that stub fastapi.templating with a minimal class won't
    # have an `env` attribute. Production Jinja2Templates always does.
    pass

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DAY_NAMES = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
_HA_ENTITY_ID_RE = re.compile(r"^[a-z_]+\.[a-z0-9_]+$")
# 24-hour HH:MM. Validated wherever schedule start/end strings are
# accepted; the auth engine treats malformed values as "always inactive"
# which fails closed, but rejecting at the form layer is friendlier.
_TIME_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
_LOCKS_CACHE_TTL = 30
_VISITORS_CACHE_TTL = 30
_ALARM_CACHE_TTL = 5
_ACTION_RATE_LIMIT = {"max_attempts": 20, "window": 60, "lockout": 60}
_LOGIN_RATE_LIMIT = {"max_attempts": 5, "window": 300, "lockout": 60}
# /setup is intentionally CSRF + login exempt (first-run has no session
# yet). Rate-limited harder than /login because every attempt drives a
# live UNVR + HA connection test — attacker brute-forces upstream creds
# through us if we don't cap. Audit 2026-05-24, C2.
_SETUP_RATE_LIMIT = {"max_attempts": 3, "window": 300, "lockout": 300}


def _log_task_exception(task: asyncio.Task) -> None:
    """Callback for fire-and-forget tasks — log any unhandled exceptions."""
    if task.cancelled():
        return
    exc = task.exception()
    if exc:
        logger.error("Unhandled exception in task %r: %s", task.get_name(), exc, exc_info=exc)


def _extract_schedule_days(form) -> str | None:
    """Extract checked day checkboxes from form and return comma-separated day names."""
    selected = [d for d in _DAY_NAMES if form.get(d)]
    return ",".join(selected) if selected else None


def _redirect(request: Request, url: str, *, delete_cookie: bool = False) -> RedirectResponse:
    """
    Redirect helper that honors the HA Ingress URL prefix.

    Absolute paths (starting with `/`) are rewritten to include the ingress
    prefix when present. Use this everywhere the app issues a Location
    header so links survive the ingress proxy.
    """
    root = request.scope.get("root_path", "")
    if root and url.startswith("/"):
        url = root + url
    resp = RedirectResponse(url=url, status_code=303)
    if delete_cookie:
        clear_session_cookie(resp, request)
    return resp


_LOGGED_PARTIAL_ENV_INJECTION = False


def _supervisor_proxy_active() -> bool:
    """True when both Supervisor-proxy env vars are present.

    `run.sh` exports `ACCESS_CONTROL_HA_URL=http://supervisor/core` and
    `ACCESS_CONTROL_HA_TOKEN=$SUPERVISOR_TOKEN` when `use_supervisor_api`
    is true. Both arrive together or neither does — that's the contract.

    A partial injection (exactly one set) is a misconfiguration: a
    Supervisor regression, a typoed env-export, or a downstream
    workflow that strips one. Treating it as "off" would silently fall
    back to user creds and pair them with a Supervisor URL on the next
    boot, producing an addon that looks healthy but 401s every HA call.
    Log loudly (once per process) and fail closed.
    """
    global _LOGGED_PARTIAL_ENV_INJECTION
    url = os.environ.get("ACCESS_CONTROL_HA_URL")
    token = os.environ.get("ACCESS_CONTROL_HA_TOKEN")
    if bool(url) != bool(token):
        if not _LOGGED_PARTIAL_ENV_INJECTION:
            logger.error(
                "Partial Supervisor env injection detected: "
                "ACCESS_CONTROL_HA_URL set=%s, ACCESS_CONTROL_HA_TOKEN set=%s. "
                "Both must be set or neither. Treating as 'not active' and "
                "falling back to user-entered creds. Fix run.sh / Supervisor "
                "env injection — this state is unsupported.",
                bool(url),
                bool(token),
            )
            _LOGGED_PARTIAL_ENV_INJECTION = True
        return False
    return bool(url and token)


def _inject_ingress_context(request: Request, context: dict) -> dict:
    """
    Mutate `context` to include `ingress_path`, `ingress_active`, and
    `supervisor_proxy_active` so every template knows where to point
    `<base href>`, whether to hide UI elements that don't make sense under
    HA SSO (e.g. the logout button), and whether to hide the HA URL + token
    fields (when Supervisor injects them automatically).

    Returns the same dict (for convenient chaining).
    """
    context["ingress_active"] = bool(getattr(request.state, "ingress_active", False))
    context["ingress_path"] = request.scope.get("root_path", "") or ""
    context["supervisor_proxy_active"] = _supervisor_proxy_active()
    return context


async def _render(template: str, request: Request, context: dict) -> HTMLResponse:
    """Render a template with CSRF token injected and session refreshed.

    Also injects `ingress_path` and `ingress_active` so templates can render
    `<base href>` correctly and hide UI elements that don't make sense under
    HA SSO (e.g. the logout button).
    """
    user = get_session_user(request)
    ingress_user = getattr(request.state, "ingress_user", None)
    effective_user = user or (f"ha:{ingress_user['name']}" if ingress_user else None)

    context["csrf_token"] = generate_csrf_token(effective_user) if effective_user else ""
    _inject_ingress_context(request, context)

    response = templates.TemplateResponse(request, template, context)
    if user:
        refresh_session_cookie(response, request, user)
    return response


def _client_ip(request: Request) -> str:
    # Use getattr so test fixtures with stripped-down Request stand-ins
    # (no `.client` attribute) don't crash this helper.
    client = getattr(request, "client", None)
    return client.host if client else "unknown"


def _action_key(request: Request, user: str, action: str) -> str:
    return f"{_client_ip(request)}:{user}:{action}"


async def _enforce_action_rate_limit(request: Request, user: str, action: str) -> HTMLResponse | None:
    db = request.app.state.db
    allowed = await db.consume_rate_limit(
        "action",
        _action_key(request, user, action),
        **_ACTION_RATE_LIMIT,
    )
    if allowed:
        return None
    return HTMLResponse(
        "<h1>429 Too Many Requests</h1><p>Action rate limit exceeded. Try again in 60 seconds.</p>",
        status_code=429,
    )


# ---------------------------------------------------------------------------
# Public routes
# ---------------------------------------------------------------------------


@router.get("/login", response_class=HTMLResponse)
async def login_get(request: Request):
    """Login page — redirect to / if already logged in.

    Under HA Ingress + SSO, `request.state.ingress_user` is populated by
    the ingress middleware before this route runs, so an SSO admin who
    lands here (e.g. via a stale bookmark) should never see the login
    form — they're already authenticated.
    """
    if get_session_user(request) or getattr(request.state, "ingress_user", None):
        return _redirect(request, "/")
    return templates.TemplateResponse(
        request,
        "login.html",
        _inject_ingress_context(request, {"request": request, "page": "login", "error": None}),
    )


@router.post("/login", response_class=HTMLResponse)
async def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    """Validate credentials and set session cookie."""
    client_ip = _client_ip(request)
    db = request.app.state.db
    if await db.is_rate_limited("login", client_ip):
        return templates.TemplateResponse(
            request,
            "login.html",
            _inject_ingress_context(request, {"request": request, "error": "Too many failed attempts. Try again in 60 seconds."}),
            status_code=429,
        )

    stored_username = await db.get_config("admin_username")
    stored_password_hash = await db.get_config("admin_password_hash")

    if (
        stored_username is None
        or stored_password_hash is None
        or username != stored_username
        or not verify_password(password, stored_password_hash)
    ):
        await db.record_rate_limit_failure("login", client_ip, **_LOGIN_RATE_LIMIT)
        return templates.TemplateResponse(
            request,
            "login.html",
            _inject_ingress_context(request, {
                "request": request,
                "page": "login",
                "error": "Invalid username or password.",
            }),
            status_code=401,
        )

    await db.clear_rate_limit("login", client_ip)
    resp = _redirect(request, "/")
    set_session_cookie(resp, request, username)
    return resp


@router.get("/logout")
async def logout(request: Request):
    """Delete session cookie and redirect to /login."""
    return _redirect(request, "/login", delete_cookie=True)


@router.get("/setup", response_class=HTMLResponse)
async def setup_get(request: Request):
    """First-run wizard — redirect to /login if already configured."""
    db = request.app.state.db
    if await db.get_config("admin_username") is not None:
        return _redirect(request, "/login")
    return templates.TemplateResponse(
        request,
        "setup.html",
        _inject_ingress_context(request, {"request": request, "page": "setup", "error": None}),
    )


@router.post("/setup", response_class=HTMLResponse)
async def setup_post(
    request: Request,
    admin_username: str = Form(""),
    admin_password: str = Form(""),
    unvr_host: str = Form(...),
    unvr_username: str = Form(...),
    unvr_password: str = Form(...),
    ha_url: str = Form(""),
    ha_token: str = Form(""),
):
    """Validate UNVR + HA connections, save encrypted config, generate initial API key.

    Security: this route is intentionally exempt from CSRF + login (no
    session exists during first-run). To prevent re-execution after the
    app is configured — which would overwrite admin credentials, rotate
    the encryption_salt (orphaning previously-encrypted UNVR/HA tokens
    and visitor PINs), and emit new API keys — we hard-guard against
    `configured=True` here and rate-limit unauthenticated POSTs.
    """
    db = request.app.state.db

    # Code-review audit 2026-05-24, C1: hard refuse setup after configured.
    if await db.get_config("admin_username") is not None:
        logger.warning(
            "Setup POST received after first-run completed; refusing. client_ip=%s",
            _client_ip(request),
        )
        raise HTTPException(status_code=404, detail="Not found")

    # Code-review audit 2026-05-24, C2: rate-limit setup POSTs by client IP.
    # Each attempt drives real UNVR + HA connection tests, so unmetered
    # access lets an attacker brute-force those upstream credentials.
    client_ip = _client_ip(request)
    if await db.is_rate_limited("setup", client_ip):
        raise HTTPException(
            status_code=429,
            detail="Too many setup attempts. Try again in a minute.",
        )

    async def _render_error_and_record(error: str) -> HTMLResponse:
        # Record a rate-limit failure on every error path so repeated
        # bad-credential attempts get throttled (see C2).
        await db.record_rate_limit_failure("setup", client_ip, **_SETUP_RATE_LIMIT)
        return templates.TemplateResponse(
            request,
            "setup.html",
            _inject_ingress_context(request, {"request": request, "page": "setup", "error": error}),
            status_code=422,
        )

    # Under HA SSO, the admin user is auto-created from the HA account
    # signed into Supervisor — the legacy username/password fields are
    # hidden in the template and unused thereafter. Generate a random
    # password so the admin_password_hash row exists (downstream code
    # assumes it does) but make it unreachable: /login is unreachable
    # under ingress-only deployments, and SSO bypasses it anyway.
    ingress_user = getattr(request.state, "ingress_user", None)
    if ingress_user:
        import secrets as _secrets
        admin_username = ingress_user.get("name") or f"ha-{(ingress_user.get('id') or '')[:8]}"
        admin_password = _secrets.token_urlsafe(48)
    elif not admin_username or not admin_password:
        return await _render_error_and_record("Admin username and password are required.")

    # 1. Test UNVR connection
    access_client = AccessClient(unvr_host, unvr_username, unvr_password)
    try:
        await access_client.login()
    except AccessClientError as exc:
        logger.warning("Setup UNVR connection test failed: %s", exc)
        return await _render_error_and_record("Failed to connect to UNVR. Check host and credentials.")
    finally:
        await access_client.close()

    # 2. Test HA connection.
    #
    # When the addon runs under Supervisor with `use_supervisor_api: true`
    # (the default), run.sh exports ACCESS_CONTROL_HA_URL=http://supervisor/core
    # and ACCESS_CONTROL_HA_TOKEN=$SUPERVISOR_TOKEN. In that mode the user
    # doesn't need to enter URL/token in the form, and we test against the
    # Supervisor proxy. ha_url/ha_token form fields are left blank → we
    # skip persisting them so main.py's env-var fallback (already wired)
    # keeps working across Supervisor token rotations.
    if _supervisor_proxy_active() and not ha_url and not ha_token:
        ha_url_for_test = os.environ["ACCESS_CONTROL_HA_URL"]
        ha_token_for_test = os.environ["ACCESS_CONTROL_HA_TOKEN"]
        persist_ha_creds = False
    else:
        if not ha_url or not ha_token:
            return await _render_error_and_record(
                "Home Assistant URL and Long-Lived Access Token are required."
            )
        ha_url_for_test = ha_url
        ha_token_for_test = ha_token
        persist_ha_creds = True

    ha_client = HAClient(ha_url_for_test, ha_token_for_test)
    try:
        ok = await ha_client.test_connection()
        if not ok:
            return await _render_error_and_record("Failed to connect to Home Assistant. Check URL and token.")
    except Exception as exc:
        logger.warning("Setup HA connection test failed: %s", exc)
        return await _render_error_and_record("Failed to connect to Home Assistant. Check URL and token.")
    finally:
        await ha_client.close()

    # 3. Generate a random secret_key (used for session signing) and encryption salt
    import secrets
    secret_key = secrets.token_hex(32)
    salt = os.urandom(16)
    enc_key = derive_key(secret_key, salt)

    # 4. Save credentials to config
    await db.set_config("admin_username", admin_username)
    await db.set_config("admin_password_hash", hash_password(admin_password))
    await db.set_config("secret_key", secret_key)
    await db.set_config("encryption_salt", salt.hex())
    await db.set_config("unvr_host", unvr_host)
    await db.set_config("unvr_username", encrypt_value(unvr_username, enc_key))
    await db.set_config("unvr_password", encrypt_value(unvr_password, enc_key))
    if persist_ha_creds:
        await db.set_config("ha_url", ha_url)
        await db.set_config("ha_token", encrypt_value(ha_token, enc_key))

    # 5. Generate initial API key
    raw_key = generate_api_key()
    await db.add_api_key("default", hash_api_key(raw_key))

    # Mark app as configured so the setup-guard middleware stops redirecting,
    # then initialize the same runtime state used on a normal configured startup.
    request.app.state.configured = True
    try:
        init_runtime = getattr(request.app.state, "initialize_configured_state", None)
        if init_runtime is None:
            raise RuntimeError("Runtime initializer unavailable")
        await init_runtime()
    except Exception as exc:
        logger.exception("Setup completed but runtime initialization failed")
        request.app.state.configured = False
        return await _render_error_and_record(f"Setup saved, but runtime initialization failed: {exc}")

    # Under SSO, send the admin straight into the dashboard — they're already
    # authenticated by HA, no need to bounce through the legacy /login form.
    # Direct-port deployments still need to enter the username/password just
    # captured by setup.
    if getattr(request.state, "ingress_user", None):
        return _redirect(request, "/")
    return _redirect(request, "/login")


# ---------------------------------------------------------------------------
# Authenticated routes
# ---------------------------------------------------------------------------


@router.get("/", response_class=HTMLResponse)
async def home(request: Request, user: str = Depends(require_login)):
    """Home/status page — health indicators, recent log, lock buzz buttons, lockdown status."""
    db = request.app.state.db
    access = request.app.state.access_client
    ha = request.app.state.ha_client
    auth_engine = request.app.state.auth_engine

    log_entries = await db.get_recent_log(20)
    locks = await db.get_all_locks()

    alarm_panels = await db.get_all_alarm_panels()
    cache_key = "home_alarm_states"
    cached_states = await db.get_ui_cache(cache_key)
    if cached_states is not None:
        for panel in alarm_panels:
            panel["state"] = cached_states.get(panel["entity_id"], "unknown")
    elif ha and ha.connected and alarm_panels:
        states = await asyncio.gather(
            *(ha.get_entity_state(panel["entity_id"]) for panel in alarm_panels),
            return_exceptions=True,
        )
        resolved_states: dict[str, str] = {}
        for panel, state in zip(alarm_panels, states):
            resolved = state if isinstance(state, str) and state else "unknown"
            panel["state"] = resolved
            resolved_states[panel["entity_id"]] = resolved
        await db.set_ui_cache(cache_key, resolved_states, _ALARM_CACHE_TTL)
    else:
        for panel in alarm_panels:
            panel["state"] = "unknown"

    ws_last_event = getattr(request.app.state, "ws_last_event", {})
    return await _render(
        "home.html",
        request,
        {
            "request": request,
            "user": user,
            "page": "home",
            "unvr_connected": access.connected if access else False,
            "protect_connected": request.app.state.protect_client.connected if request.app.state.protect_client else False,
            "ha_connected": ha.connected if ha else False,
            "ws_connected": access.ws_connected if access else False,
            "lockdown": auth_engine.lockdown if auth_engine else False,
            "locks": locks,
            "log_entries": log_entries,
            "alarm_panels": alarm_panels,
            "ws_last_event": ws_last_event,
        },
    )


@router.get("/users", response_class=HTMLResponse)
async def users_list(request: Request, user: str = Depends(require_login)):
    """Users list with rule counts and group membership."""
    db = request.app.state.db
    show_hidden = request.query_params.get("show_hidden") == "1"
    users = await db.get_all_users(include_hidden=show_hidden)
    # Enrich with group names (single query instead of N+1)
    user_group_map = await db.get_all_user_group_names()
    for u in users:
        u["groups"] = user_group_map.get(u["id"], [])
    return await _render(
        "users.html",
        request,
        {"request": request, "user": user, "page": "users", "users": users, "show_hidden": show_hidden},
    )


@router.post("/users/{user_id}/hide")
async def hide_user(user_id: int, request: Request, user: str = Depends(require_csrf)):
    """Hide a user from the default list."""
    limited = await _enforce_action_rate_limit(request, user, "user_admin")
    if limited:
        return limited
    db = request.app.state.db
    await db.set_user_hidden(user_id, True)
    await db.log_admin_action(user, "user_hide", str(user_id))
    return _redirect(request, "/users")


@router.post("/users/{user_id}/unhide")
async def unhide_user(user_id: int, request: Request, user: str = Depends(require_csrf)):
    """Unhide a user."""
    limited = await _enforce_action_rate_limit(request, user, "user_admin")
    if limited:
        return limited
    db = request.app.state.db
    await db.set_user_hidden(user_id, False)
    await db.log_admin_action(user, "user_unhide", str(user_id))
    return _redirect(request, "/users?show_hidden=1")


@router.get("/users/{user_id}", response_class=HTMLResponse)
async def user_detail(
    user_id: int, request: Request, user: str = Depends(require_login)
):
    """User detail page with rules editor."""
    db = request.app.state.db

    target_user = await db.get_user(user_id)
    if target_user is None:
        return _redirect(request, "/users")

    rules = await db.get_rules_for_user(user_id)
    locks = await db.get_all_locks()

    # Collect lock IDs already assigned to this user
    assigned_lock_ids = {r["lock_id"] for r in rules}
    available_locks = [lk for lk in locks if lk["id"] not in assigned_lock_ids]

    return await _render(
        "user_detail.html",
        request,
        {
            "request": request,
            "user": user,
            "page": "users",
            "target_user": target_user,
            "rules": rules,
            "available_locks": available_locks,
            "has_stored_pin": bool(target_user.get("pin_encrypted")),
        },
    )


@router.post("/users/{user_id}/rules")
async def add_rule(
    user_id: int,
    request: Request,
    lock_id: int = Form(...),
    user: str = Depends(require_csrf),
):
    """Add a rule (lock_id from form) for a user."""
    limited = await _enforce_action_rate_limit(request, user, "user_admin")
    if limited:
        return limited
    db = request.app.state.db

    # Prevent duplicate rules
    existing = await db.get_rules_for_user_and_lock(user_id, lock_id)
    if existing is None:
        await db.add_rule(user_id, lock_id)

    return _redirect(request, f"/users/{user_id}")


@router.post("/rules/{rule_id}/toggle")
async def toggle_rule(
    rule_id: int,
    request: Request,
    user: str = Depends(require_csrf),
):
    """Toggle a rule's enabled state."""
    limited = await _enforce_action_rate_limit(request, user, "user_admin")
    if limited:
        return limited
    db = request.app.state.db

    rule = await db.get_rule(rule_id)
    if rule is None:
        return _redirect(request, "/users")

    user_id = rule["user_id"]
    new_enabled = not bool(rule["enabled"])

    await db.update_rule(
        rule_id,
        enabled=new_enabled,
        schedule_enabled=bool(rule["schedule_enabled"]),
        schedule_days=rule["schedule_days"],
        schedule_start=rule["schedule_start"],
        schedule_end=rule["schedule_end"],
    )

    return _redirect(request, f"/users/{user_id}")


@router.post("/rules/{rule_id}/delete")
async def delete_rule(
    rule_id: int,
    request: Request,
    user: str = Depends(require_csrf),
):
    """Delete a rule."""
    limited = await _enforce_action_rate_limit(request, user, "user_admin")
    if limited:
        return limited
    db = request.app.state.db

    rule = await db.get_rule(rule_id)
    user_id = rule["user_id"] if rule else None
    await db.delete_rule(rule_id)

    if user_id:
        return _redirect(request, f"/users/{user_id}")
    return _redirect(request, "/users")


@router.post("/rules/{rule_id}/schedule")
async def update_schedule(
    rule_id: int,
    request: Request,
    user: str = Depends(require_csrf),
    schedule_enabled: str = Form(default="off"),
    schedule_start: str = Form(default=""),
    schedule_end: str = Form(default=""),
    mon: str = Form(default=""),
    tue: str = Form(default=""),
    wed: str = Form(default=""),
    thu: str = Form(default=""),
    fri: str = Form(default=""),
    sat: str = Form(default=""),
    sun: str = Form(default=""),
):
    """Update a rule's schedule (days, start time, end time)."""
    limited = await _enforce_action_rate_limit(request, user, "user_admin")
    if limited:
        return limited
    db = request.app.state.db

    rule = await db.get_rule(rule_id)
    if rule is None:
        return _redirect(request, "/users")

    user_id = rule["user_id"]

    # Build days list from checkbox values (store as day names for _check_schedule)
    day_values = {"mon": mon, "tue": tue, "wed": wed, "thu": thu, "fri": fri, "sat": sat, "sun": sun}
    selected_days = [k for k, v in day_values.items() if v]
    days_str = ",".join(selected_days) if selected_days else None

    enabled_flag = schedule_enabled.lower() in ("on", "1", "true", "yes")

    # Reject malformed time strings up front so the auth engine never
    # receives unparseable schedule bounds. Audit 2026-05-24, M2.
    if schedule_start and not _TIME_RE.match(schedule_start):
        return _redirect(request, f"/users/{user_id}?error=Invalid+start+time")
    if schedule_end and not _TIME_RE.match(schedule_end):
        return _redirect(request, f"/users/{user_id}?error=Invalid+end+time")

    await db.update_rule(
        rule_id,
        enabled=bool(rule["enabled"]),
        schedule_enabled=enabled_flag,
        schedule_days=days_str,
        schedule_start=schedule_start or None,
        schedule_end=schedule_end or None,
    )

    return _redirect(request, f"/users/{user_id}")


@router.get("/locks", response_class=HTMLResponse)
async def locks_list(request: Request, user: str = Depends(require_login)):
    """Locks list with state, actions, and add form."""
    db = request.app.state.db
    ha = request.app.state.ha_client
    locks = await db.get_all_locks(include_hidden=True)
    entry_devices_by_lock = await db.get_entry_devices_for_locks([lock["id"] for lock in locks])

    # Fetch live state for all locks — prefer in-memory cache, fall back to HA API
    lock_states = getattr(request.app.state, "lock_states", {})
    all_ha_locks = []
    ha_states = {}
    if ha and ha.connected:
        try:
            all_ha_locks = await ha.get_lock_entities()
            ha_states = {l["entity_id"]: l["state"] for l in all_ha_locks}
        except Exception:
            logger.exception("Failed to fetch HA lock states")

    for lock in locks:
        if lock["type"] == "ha_external" and lock.get("entity_id"):
            lock["state"] = lock_states.get(lock["entity_id"], ha_states.get(lock["entity_id"], "unknown"))
        elif lock["type"] == "access_native" and lock.get("device_id"):
            lock["state"] = lock_states.get(lock["device_id"], "unknown")
        else:
            lock["state"] = "unknown"
        lock["entry_devices"] = entry_devices_by_lock.get(lock["id"], [])

    # Available HA locks for adding (exclude already-added)
    ha_locks = []
    if all_ha_locks:
        existing_eids = {l["entity_id"] for l in locks if l.get("entity_id")}
        ha_locks = [l for l in all_ha_locks if l["entity_id"] not in existing_eids]

    # Fetch Access locations for device association
    access = request.app.state.access_client
    access_locations = []
    if access and access.connected:
        access_locations = await db.get_ui_cache("locks_access_locations") or []
        if not access_locations:
            try:
                bootstrap = await access.get_bootstrap()
                access_locations = access.parse_door_locations(bootstrap)
                await db.set_ui_cache("locks_access_locations", access_locations, _LOCKS_CACHE_TTL)
            except Exception:
                logger.exception("Failed to fetch Access locations")

    # Fetch Protect cameras/doorbells for device association
    protect = request.app.state.protect_client
    protect_doorbells = []
    protect_cameras = []
    if protect and protect.connected:
        cached_cameras = await db.get_ui_cache("locks_protect_cameras")
        if cached_cameras is not None:
            protect_doorbells, protect_cameras = cached_cameras
        else:
            try:
                all_cams = await protect.get_cameras()
                protect_doorbells = [c for c in all_cams if c["is_doorbell"] and c["connected"]]
                protect_cameras = [c for c in all_cams if not c["is_doorbell"] and c["connected"]]
                await db.set_ui_cache("locks_protect_cameras", [protect_doorbells, protect_cameras], _LOCKS_CACHE_TTL)
            except Exception:
                logger.exception("Failed to fetch Protect cameras")

    return await _render(
        "locks.html",
        request,
        {
            "request": request, "user": user, "page": "locks",
            "locks": locks, "ha_locks": ha_locks,
            "access_locations": access_locations,
            "protect_doorbells": protect_doorbells, "protect_cameras": protect_cameras,
        },
    )


@router.post("/locks/add")
async def add_lock(
    request: Request,
    entity_id: str = Form(...),
    name: str = Form(...),
    door_name: str = Form(default=""),
    buzz_enabled: str = Form(default=""),
    relock_duration: int = Form(default=30),
    user: str = Depends(require_csrf),
):
    """Add an external HA lock."""
    limited = await _enforce_action_rate_limit(request, user, "lock_admin")
    if limited:
        return limited
    if not _HA_ENTITY_ID_RE.match(entity_id):
        return _redirect(request, "/locks?error=Invalid+entity+ID+format")
    db = request.app.state.db
    await db.add_external_lock(
        entity_id=entity_id,
        name=name,
        door_name=door_name or None,
        buzz_enabled=bool(buzz_enabled),
        relock_duration=relock_duration,
    )
    await db.log_admin_action(user, "lock_create", name)
    return _redirect(request, "/locks")


@router.post("/locks/{lock_id}/settings")
async def update_lock_settings(
    lock_id: int,
    request: Request,
    buzz_enabled: str = Form(default=""),
    relock_duration: int = Form(default=30),
    access_location_id: str = Form(default=""),
    relock_on_remote: str = Form(default=""),
    relock_on_device_auth: str = Form(default=""),
    user: str = Depends(require_csrf),
):
    limited = await _enforce_action_rate_limit(request, user, "lock_admin")
    if limited:
        return limited
    db = request.app.state.db
    await db.update_lock_settings(
        lock_id,
        buzz_enabled=bool(buzz_enabled),
        relock_duration=relock_duration,
        access_location_id=access_location_id or None,
        relock_on_remote=bool(relock_on_remote),
        relock_on_device_auth=bool(relock_on_device_auth),
    )
    return _redirect(request, "/locks")


@router.post("/locks/{lock_id}/delete")
async def delete_lock(
    lock_id: int,
    request: Request,
    user: str = Depends(require_csrf),
):
    """Delete a lock (rules cascade via FK)."""
    limited = await _enforce_action_rate_limit(request, user, "lock_admin")
    if limited:
        return limited
    db = request.app.state.db
    await db.delete_lock(lock_id)
    await db.log_admin_action(user, "lock_delete", str(lock_id))
    return _redirect(request, "/locks")


@router.post("/locks/{lock_id}/hide")
async def hide_lock(lock_id: int, request: Request, user: str = Depends(require_csrf)):
    """Hide a lock from the main list."""
    limited = await _enforce_action_rate_limit(request, user, "lock_admin")
    if limited:
        return limited
    db = request.app.state.db
    await db.set_lock_hidden(lock_id, True)
    await db.log_admin_action(user, "lock_hide", str(lock_id))
    return _redirect(request, "/locks")


@router.post("/locks/{lock_id}/unhide")
async def unhide_lock(lock_id: int, request: Request, user: str = Depends(require_csrf)):
    """Show a hidden lock."""
    limited = await _enforce_action_rate_limit(request, user, "lock_admin")
    if limited:
        return limited
    db = request.app.state.db
    await db.set_lock_hidden(lock_id, False)
    await db.log_admin_action(user, "lock_unhide", str(lock_id))
    return _redirect(request, "/locks")


@router.post("/locks/{lock_id}/entry-devices/add")
async def add_entry_device(
    lock_id: int,
    request: Request,
    device_type: str = Form(...),
    device_name: str = Form(...),
    device_id: str = Form(default=""),
    entity_id: str = Form(default=""),
    user: str = Depends(require_csrf),
):
    limited = await _enforce_action_rate_limit(request, user, "lock_admin")
    if limited:
        return limited
    db = request.app.state.db
    await db.add_entry_device(
        lock_id=lock_id,
        device_type=device_type,
        name=device_name,
        device_id=device_id or None,
        entity_id=entity_id or None,
    )
    return _redirect(request, "/locks")


@router.post("/locks/{lock_id}/entry-devices/{ed_id}/delete")
async def delete_entry_device(
    lock_id: int, ed_id: int, request: Request, user: str = Depends(require_csrf),
):
    limited = await _enforce_action_rate_limit(request, user, "lock_admin")
    if limited:
        return limited
    db = request.app.state.db
    await db.delete_entry_device(ed_id)
    return _redirect(request, "/locks")


@router.post("/locks/{lock_id}/unlock")
async def unlock_lock(lock_id: int, request: Request, user: str = Depends(require_csrf)):
    """Persistent unlock."""
    limited = await _enforce_action_rate_limit(request, user, "lock_action")
    if limited:
        return limited
    return await _lock_action(lock_id, "unlock", user, request)


@router.post("/locks/{lock_id}/lock")
async def lock_lock(lock_id: int, request: Request, user: str = Depends(require_csrf)):
    """Lock."""
    limited = await _enforce_action_rate_limit(request, user, "lock_action")
    if limited:
        return limited
    return await _lock_action(lock_id, "lock", user, request)


@router.post("/locks/{lock_id}/buzz")
async def buzz_lock(lock_id: int, request: Request, user: str = Depends(require_csrf)):
    """Momentary unlock (buzz) — timed unlock then re-lock for HA locks."""
    limited = await _enforce_action_rate_limit(request, user, "lock_action")
    if limited:
        return limited
    return await _lock_action(lock_id, "buzz", user, request)


async def _lock_action(lock_id: int, action: str, user: str, request):
    """Execute a lock/unlock/buzz action on a lock."""
    db = request.app.state.db
    access = request.app.state.access_client
    ha = request.app.state.ha_client

    lock = await db.get_lock(lock_id)
    if lock is None:
        return _redirect(request, "/locks")

    result = "error"
    reason: str | None = None

    try:
        if lock["type"] == "access_native":
            if not access:
                reason = "Access client not available"
            elif action == "buzz":
                if lock.get("location_id"):
                    await access.unlock_momentary(lock["location_id"])
                    result = "granted"
                else:
                    reason = "Missing location_id for momentary unlock"
            elif action == "unlock":
                if lock.get("device_id"):
                    await access.unlock_persistent(lock["device_id"])
                    result = "granted"
                else:
                    reason = "Missing device_id for persistent unlock"
            elif action == "lock":
                if lock.get("device_id"):
                    await access.lock(lock["device_id"])
                    result = "granted"
                else:
                    reason = "Missing device_id for lock"

        elif lock["type"] == "ha_external":
            if not ha or not lock.get("entity_id"):
                reason = "HA client not available or missing entity_id"
            elif action == "buzz":
                # Cancel any pending relock FIRST so an about-to-fire timer
                # can't briefly re-lock the door between our unlock and the
                # new schedule.
                duration = lock.get("relock_duration", 30)
                eid = lock["entity_id"]
                rm = request.app.state.relock_manager
                if rm is not None:
                    await rm.cancel(eid)
                ok = await ha.unlock(eid)
                if ok:
                    result = "granted"
                    lock_name = lock.get("name", eid)
                    request.app.state.lock_states[eid] = "unlocked"

                    if rm is not None:
                        await rm.schedule(
                            entity_id=eid,
                            duration=duration,
                            lock_id=lock_id,
                            lock_name=lock_name,
                            source="buzz",
                        )
                else:
                    reason = "HA unlock call returned failure"
            elif action == "unlock":
                # Cancel any pending relock FIRST so an about-to-fire timer
                # can't re-lock the door immediately after our unlock returns.
                eid = lock["entity_id"]
                rm = request.app.state.relock_manager
                if rm is not None:
                    await rm.cancel(eid)
                ok = await ha.unlock(eid)
                result = "granted" if ok else "error"
                if ok:
                    request.app.state.lock_states[eid] = "unlocked"
                    if rm is not None:
                        logger.info("Cancelled relock timer for %s (manual unlock override)", lock.get("name", eid))
                else:
                    reason = "HA unlock call failed"
            elif action == "lock":
                # Cancel any pending relock FIRST — we're locking now, so
                # the pending timer is redundant and could fire after we've
                # already moved on (no harm here, but keeps state tidy).
                eid = lock["entity_id"]
                rm = request.app.state.relock_manager
                if rm is not None:
                    await rm.cancel(eid)
                ok = await ha.lock(eid)
                result = "granted" if ok else "error"
                if ok:
                    request.app.state.lock_states[eid] = "locked"
                else:
                    reason = "HA lock call failed"
        else:
            reason = f"Unknown lock type: {lock['type']}"
    except Exception as exc:
        result = "error"
        reason = str(exc)
        logger.exception("Error with %s on lock %s: %s", action, lock_id, exc)

    await db.log_access(
        method=f"manual_{action}",
        result=result,
        lock_id=lock_id,
        lock_name=lock.get("name"),
        user_name=user,
        reason=reason,
    )

    # Auto-disarm alarm panels on successful unlock/buzz
    if result == "granted" and action in ("unlock", "buzz") and ha:
        alarm_panels = await db.get_all_alarm_panels()
        for panel in alarm_panels:
            try:
                code = _decrypt_panel_code(request, panel)
                await ha.alarm_disarm(panel["entity_id"], code=code)
                logger.info("Auto-disarmed %s after %s on %s", panel["entity_id"], action, lock.get("name"))
            except Exception:
                logger.exception("Failed to auto-disarm %s", panel["entity_id"])

    return _redirect(request, "/locks")


@router.get("/locks/{lock_id}/history", response_class=HTMLResponse)
async def lock_history(lock_id: int, request: Request, user: str = Depends(require_login)):
    """Per-lock access history."""
    db = request.app.state.db
    lock = await db.get_lock(lock_id)
    if not lock:
        return _redirect(request, "/locks")
    log_entries = await db.get_log_for_lock(lock_id)
    return await _render("lock_history.html", request, {
        "request": request, "user": user, "page": "locks",
        "lock": lock, "log_entries": log_entries,
    })


@router.get("/log", response_class=HTMLResponse)
async def activity_log(request: Request, user: str = Depends(require_login)):
    """Activity log page."""
    db = request.app.state.db
    log_entries = await db.get_recent_log(200)
    return await _render(
        "log.html",
        request,
        {
            "request": request,
            "user": user,
            "page": "log",
            "log_entries": log_entries,
        },
    )


# ---------------------------------------------------------------------------
# Alarm Panels
# ---------------------------------------------------------------------------


@router.post("/alarm/{panel_id}/arm-away")
async def alarm_arm_away(panel_id: int, request: Request, user: str = Depends(require_csrf)):
    limited = await _enforce_action_rate_limit(request, user, "alarm_action")
    if limited:
        return limited
    db = request.app.state.db
    ha = request.app.state.ha_client
    panel = await _get_alarm_panel(db, panel_id)
    if panel and ha:
        ok = await ha.alarm_arm_away(panel["entity_id"])
        if not ok:
            logger.error("Alarm arm-away failed for %s", panel["entity_id"])
    return _redirect(request, "/")


@router.post("/alarm/{panel_id}/arm-home")
async def alarm_arm_home(panel_id: int, request: Request, user: str = Depends(require_csrf)):
    limited = await _enforce_action_rate_limit(request, user, "alarm_action")
    if limited:
        return limited
    db = request.app.state.db
    ha = request.app.state.ha_client
    panel = await _get_alarm_panel(db, panel_id)
    if panel and ha:
        ok = await ha.alarm_arm_home(panel["entity_id"])
        if not ok:
            logger.error("Alarm arm-home failed for %s", panel["entity_id"])
    return _redirect(request, "/")


@router.post("/alarm/{panel_id}/disarm")
async def alarm_disarm(panel_id: int, request: Request, user: str = Depends(require_csrf)):
    limited = await _enforce_action_rate_limit(request, user, "alarm_action")
    if limited:
        return limited
    db = request.app.state.db
    ha = request.app.state.ha_client
    panel = await _get_alarm_panel(db, panel_id)
    if panel and ha:
        code = _decrypt_panel_code(request, panel)
        ok = await ha.alarm_disarm(panel["entity_id"], code=code)
        if not ok:
            logger.error("Alarm disarm failed for %s", panel["entity_id"])
    return _redirect(request, "/")


async def _get_alarm_panel(db, panel_id):
    panels = await db.get_all_alarm_panels()
    return next((p for p in panels if p["id"] == panel_id), None)


def _decrypt_panel_code(request: Request, panel: dict) -> str | None:
    """Decrypt and return the disarm code for an alarm panel, or None if not set."""
    enc = panel.get("disarm_code_encrypted")
    if not enc:
        return None
    try:
        return decrypt_value(enc, request.app.state.enc_key)
    except Exception:
        logger.error("Failed to decrypt disarm code for %s", panel["entity_id"])
        return None


@router.post("/settings/alarm/add")
async def add_alarm_panel(
    request: Request,
    entity_id: str = Form(...),
    name: str = Form(...),
    user: str = Depends(require_csrf),
):
    limited = await _enforce_action_rate_limit(request, user, "alarm_action")
    if limited:
        return limited
    if not _HA_ENTITY_ID_RE.match(entity_id):
        return _redirect(request, "/settings?error=Invalid+entity+ID+format")
    db = request.app.state.db
    await db.add_alarm_panel(entity_id, name)
    await db.log_admin_action(user, "alarm_panel_add", entity_id)
    return _redirect(request, "/settings")


@router.post("/settings/alarm/{panel_id}/code")
async def set_alarm_panel_code(
    panel_id: int,
    request: Request,
    disarm_code: str = Form(""),
    user: str = Depends(require_csrf),
):
    limited = await _enforce_action_rate_limit(request, user, "alarm_action")
    if limited:
        return limited
    db = request.app.state.db
    code = disarm_code.strip()
    if code:
        if not re.fullmatch(r"[0-9]{4,8}", code):
            return _redirect(request, "/settings")
        enc = encrypt_value(code, request.app.state.enc_key)
        action = "alarm_panel_code_set"
    else:
        enc = None
        action = "alarm_panel_code_cleared"
    await db.update_alarm_panel_code(panel_id, enc)
    await db.log_admin_action(user, action, str(panel_id))
    return _redirect(request, "/settings")


@router.post("/settings/alarm/{panel_id}/delete")
async def delete_alarm_panel(panel_id: int, request: Request, user: str = Depends(require_csrf)):
    limited = await _enforce_action_rate_limit(request, user, "alarm_action")
    if limited:
        return limited
    db = request.app.state.db
    await db.delete_alarm_panel(panel_id)
    await db.log_admin_action(user, "alarm_panel_remove", str(panel_id))
    return _redirect(request, "/settings")


# ---------------------------------------------------------------------------
# Groups
# ---------------------------------------------------------------------------


@router.get("/groups", response_class=HTMLResponse)
async def groups_list(request: Request, user: str = Depends(require_login)):
    """Groups list."""
    db = request.app.state.db
    groups = await db.get_all_groups()
    error = request.query_params.get("error")
    return await _render(
        "groups.html",
        request,
        {"request": request, "user": user, "page": "groups", "groups": groups, "error": error},
    )


@router.post("/groups/create")
async def create_group(request: Request, user: str = Depends(require_csrf)):
    limited = await _enforce_action_rate_limit(request, user, "group_admin")
    if limited:
        return limited
    db = request.app.state.db
    form = await request.form()
    days = _extract_schedule_days(form)
    name = form.get("name", "")
    schedule_start = form.get("schedule_start") or None
    schedule_end = form.get("schedule_end") or None
    # Reject malformed time strings up front. Audit 2026-05-24, M2.
    if schedule_start and not _TIME_RE.match(schedule_start):
        return _redirect(request, f"/groups?error={quote_plus('Invalid start time format.')}")
    if schedule_end and not _TIME_RE.match(schedule_end):
        return _redirect(request, f"/groups?error={quote_plus('Invalid end time format.')}")
    try:
        await db.create_group(
            name=name,
            description=form.get("description", ""),
            all_locks=bool(form.get("all_locks")),
            blocked_when_armed_away=bool(form.get("blocked_when_armed_away")),
            blocked_when_armed_home=bool(form.get("blocked_when_armed_home")),
            can_disarm=bool(form.get("can_disarm")),
            schedule_enabled=bool(form.get("schedule_enabled")),
            schedule_days=days,
            schedule_start=schedule_start,
            schedule_end=schedule_end,
        )
    except sqlite3.IntegrityError:
        return _redirect(request, f"/groups?error={quote_plus('Group name already exists.')}")
    await db.log_admin_action(user, "group_create", name)
    return _redirect(request, "/groups")


@router.get("/groups/{group_id}", response_class=HTMLResponse)
async def group_detail(group_id: int, request: Request, user: str = Depends(require_login)):
    db = request.app.state.db
    group = await db.get_group(group_id)
    if not group:
        return _redirect(request, "/groups")
    members = await db.get_group_members(group_id)
    member_ids = {m["id"] for m in members}
    all_users = await db.get_all_users(include_hidden=False)
    available_users = [u for u in all_users if u["id"] not in member_ids]
    group_locks = await db.get_group_locks(group_id)
    group_lock_ids = {l["id"] for l in group_locks}
    all_locks = await db.get_all_locks()
    return await _render(
        "group_detail.html",
        request,
        {
            "request": request,
            "user": user,
            "page": "groups",
            "group": group,
            "members": members,
            "available_users": available_users,
            "group_locks": group_locks,
            "group_lock_ids": group_lock_ids,
            "all_locks": all_locks,
            "error": request.query_params.get("error"),
        },
    )


@router.post("/groups/{group_id}/add-member")
async def add_group_member(
    group_id: int, request: Request, user_id: int = Form(...), user: str = Depends(require_csrf),
):
    limited = await _enforce_action_rate_limit(request, user, "group_admin")
    if limited:
        return limited
    db = request.app.state.db
    await db.add_group_member(group_id, user_id)
    return _redirect(request, f"/groups/{group_id}")


@router.post("/groups/{group_id}/remove-member/{member_id}")
async def remove_group_member(
    group_id: int, member_id: int, request: Request, user: str = Depends(require_csrf),
):
    limited = await _enforce_action_rate_limit(request, user, "group_admin")
    if limited:
        return limited
    db = request.app.state.db
    await db.remove_group_member(group_id, member_id)
    return _redirect(request, f"/groups/{group_id}")


@router.post("/groups/{group_id}/update")
async def update_group(group_id: int, request: Request, user: str = Depends(require_csrf)):
    limited = await _enforce_action_rate_limit(request, user, "group_admin")
    if limited:
        return limited
    db = request.app.state.db
    form = await request.form()
    days = _extract_schedule_days(form)
    schedule_start = form.get("schedule_start") or None
    schedule_end = form.get("schedule_end") or None
    if schedule_start and not _TIME_RE.match(schedule_start):
        return _redirect(request, f"/groups/{group_id}?error={quote_plus('Invalid start time format.')}")
    if schedule_end and not _TIME_RE.match(schedule_end):
        return _redirect(request, f"/groups/{group_id}?error={quote_plus('Invalid end time format.')}")
    try:
        await db.update_group(
            group_id,
            name=form.get("name", ""),
            description=form.get("description", ""),
            all_locks=bool(form.get("all_locks")),
            blocked_when_armed_away=bool(form.get("blocked_when_armed_away")),
            blocked_when_armed_home=bool(form.get("blocked_when_armed_home")),
            can_disarm=bool(form.get("can_disarm")),
            schedule_enabled=bool(form.get("schedule_enabled")),
            schedule_days=days,
            schedule_start=schedule_start,
            schedule_end=schedule_end,
        )
    except sqlite3.IntegrityError:
        return _redirect(request, f"/groups/{group_id}?error={quote_plus('Group name already exists.')}")
    await db.log_admin_action(user, "group_update", str(group_id))
    return _redirect(request, f"/groups/{group_id}")


@router.post("/groups/{group_id}/locks")
async def set_group_locks(group_id: int, request: Request, user: str = Depends(require_csrf)):
    limited = await _enforce_action_rate_limit(request, user, "group_admin")
    if limited:
        return limited
    db = request.app.state.db
    form = await request.form()
    # Drop non-integer entries instead of crashing on bad input.
    # Audit 2026-05-24, M3.
    lock_ids: list[int] = []
    for k, v in form.multi_items():
        if k != "lock_ids":
            continue
        try:
            lock_ids.append(int(v))
        except (TypeError, ValueError):
            logger.warning("set_group_locks ignoring non-integer lock_id %r", v)
    await db.set_group_locks(group_id, lock_ids)
    return _redirect(request, f"/groups/{group_id}")


@router.post("/groups/{group_id}/delete")
async def delete_group(group_id: int, request: Request, user: str = Depends(require_csrf)):
    limited = await _enforce_action_rate_limit(request, user, "group_admin")
    if limited:
        return limited
    db = request.app.state.db
    await db.delete_group(group_id)
    await db.log_admin_action(user, "group_delete", str(group_id))
    return _redirect(request, "/groups")


# ------------------------------------------------------------------
# Visitors
# ------------------------------------------------------------------

@router.get("/visitors", response_class=HTMLResponse)
async def visitors_list(request: Request, user: str = Depends(require_login)):
    """Visitor management page."""
    db = request.app.state.db
    visitors = await db.get_all_visitors()
    for v in visitors:
        v["has_pin"] = bool(v.get("pin_encrypted"))

    access = request.app.state.access_client
    access_locations = []
    if access and access.connected:
        cached = await db.get_ui_cache("visitors_access_locations")
        access_locations = cached if cached is not None else []
        if cached is None:
            try:
                bootstrap = await access.get_bootstrap()
                access_locations = access.parse_door_locations(bootstrap)
                await db.set_ui_cache("visitors_access_locations", access_locations, _VISITORS_CACHE_TTL)
            except Exception:
                logger.exception("Failed to fetch Access locations for visitors")

    error = request.query_params.get("error")
    return await _render("visitors.html", request, {
        "request": request, "user": user, "page": "visitors",
        "visitors": visitors, "access_locations": access_locations,
        "error": error,
    })


@router.post("/visitors/add")
async def add_visitor(
    request: Request,
    user: str = Depends(require_csrf),
    first_name: str = Form(...),
    last_name: str = Form(...),
    location_id: str = Form(default=""),
    start_date: str = Form(...),
    start_time: str = Form(default="00:00"),
    end_date: str = Form(...),
    end_time: str = Form(default="23:59"),
    pin_code: str = Form(default=""),
    notes: str = Form(default=""),
):
    """Create a visitor in UniFi and store locally."""
    limited = await _enforce_action_rate_limit(request, user, "visitor_action")
    if limited:
        return limited
    from datetime import datetime as dt
    from zoneinfo import ZoneInfo

    # Validate PIN if provided
    if pin_code and not re.match(r'^[0-9]{4,8}$', pin_code):
        return _redirect(request, "/visitors?error=Invalid+PIN+format")

    db = request.app.state.db
    access = request.app.state.access_client
    enc_key = getattr(request.app.state, "enc_key", None)
    if not access:
        return _redirect(request, "/visitors?error=Access+client+not+available")

    local_tz = ZoneInfo("America/New_York")
    # Defensive parse — malformed date/time input must not crash the
    # route with an uncaught ValueError. Audit 2026-05-24, M1.
    try:
        start_dt = dt.strptime(f"{start_date} {start_time}", "%Y-%m-%d %H:%M").replace(tzinfo=local_tz)
        end_dt = dt.strptime(f"{end_date} {end_time}", "%Y-%m-%d %H:%M").replace(tzinfo=local_tz)
    except ValueError:
        return _redirect(request, "/visitors?error=Invalid+date+or+time+format")

    # Validate time window
    if end_dt <= start_dt:
        return _redirect(request, "/visitors?error=End+time+must+be+after+start+time")

    start_unix = int(start_dt.timestamp())
    end_unix = int(end_dt.timestamp())

    try:
        visitor_data = await access.create_visitor(first_name, last_name + " - Visitor", start_unix, end_unix)
    except Exception:
        logger.exception("Failed to create visitor in UniFi")
        return _redirect(request, "/visitors?error=Failed+to+create+visitor+in+UniFi")
    visitor_id = visitor_data.get("unique_id", "")
    if not visitor_id:
        logger.error("UniFi returned no unique_id for new visitor")
        return _redirect(request, "/visitors")

    location_name = ""
    pin_encrypted = None
    name = f"{first_name} {last_name}"
    try:
        if location_id:
            updated = await access.update_visitor(visitor_id, location_id=location_id)
            location_name = updated.get("location_name", "")

        if pin_code:
            await access.update_visitor(visitor_id, pin_code=pin_code)
            if enc_key:
                pin_encrypted = encrypt_value(pin_code, enc_key)

        await db.add_visitor(
            unvr_visitor_id=visitor_id,
            name=name,
            start_time=start_dt.isoformat(),
            end_time=end_dt.isoformat(),
            location_id=location_id,
            location_name=location_name,
            pin_encrypted=pin_encrypted,
            created_by=user,
            notes=notes,
        )
    except Exception:
        logger.exception("Visitor setup failed after UniFi create; attempting cleanup for %s", visitor_id)
        try:
            await access.delete_visitor(visitor_id)
        except Exception:
            logger.exception("Cleanup failed for partially created visitor %s", visitor_id)
        return _redirect(request, "/visitors?error=Visitor+creation+partially+failed")

    await db.log_admin_action(user, "visitor_create", name, f"door={location_name}, expires={end_dt.isoformat()}")
    return _redirect(request, "/visitors")


@router.post("/visitors/{visitor_id}/extend")
async def extend_visitor(
    visitor_id: int,
    request: Request,
    user: str = Depends(require_csrf),
    end_date: str = Form(...),
    end_time: str = Form(default="23:59"),
):
    """Extend a visitor's access window."""
    limited = await _enforce_action_rate_limit(request, user, "visitor_action")
    if limited:
        return limited
    from datetime import datetime as dt
    from zoneinfo import ZoneInfo

    db = request.app.state.db
    access = request.app.state.access_client
    visitor = await db.get_visitor(visitor_id)
    if not visitor:
        return _redirect(request, "/visitors")
    if not access:
        return _redirect(request, "/visitors?error=Access+client+not+available")

    local_tz = ZoneInfo("America/New_York")
    # Defensive parse — same as add_visitor. Audit 2026-05-24, M1.
    try:
        end_dt = dt.strptime(f"{end_date} {end_time}", "%Y-%m-%d %H:%M").replace(tzinfo=local_tz)
    except ValueError:
        return _redirect(request, "/visitors?error=Invalid+date+or+time+format")
    if end_dt <= dt.now(local_tz):
        return _redirect(request, "/visitors")
    end_unix = int(end_dt.timestamp())

    try:
        await access.update_visitor(visitor["unvr_visitor_id"], end_time=end_unix)
    except Exception:
        logger.exception("Failed to extend visitor %s in UniFi", visitor["name"])
        return _redirect(request, "/visitors?error=Failed+to+extend+visitor+in+UniFi")
    await db.update_visitor_end_time(visitor_id, end_dt.isoformat())
    await db.log_admin_action(user, "visitor_extend", visitor["name"], f"new end={end_dt.isoformat()}")
    return _redirect(request, "/visitors")


@router.post("/visitors/{visitor_id}/delete")
async def delete_visitor_route(
    visitor_id: int,
    request: Request,
    user: str = Depends(require_csrf),
):
    """Delete a visitor from UniFi and local DB."""
    limited = await _enforce_action_rate_limit(request, user, "visitor_action")
    if limited:
        return limited
    db = request.app.state.db
    access = request.app.state.access_client
    visitor = await db.get_visitor(visitor_id)
    if not visitor:
        return _redirect(request, "/visitors")

    if not access or not access.connected:
        logger.warning("Cannot delete visitor %s from UniFi — Access client not connected", visitor_id)
        return _redirect(request, "/visitors?error=access_unavailable")

    try:
        await access.delete_visitor(visitor["unvr_visitor_id"])
    except Exception:
        logger.exception("Failed to delete visitor from UniFi")
        return _redirect(request, "/visitors?error=unifi_delete_failed")

    await db.delete_visitor(visitor_id)
    await db.log_admin_action(user, "visitor_delete", visitor["name"])
    return _redirect(request, "/visitors")


# ------------------------------------------------------------------
# User PIN management
# ------------------------------------------------------------------

@router.post("/users/{user_id}/set-pin")
async def set_user_pin(
    user_id: int,
    request: Request,
    user: str = Depends(require_csrf),
    pin_code: str = Form(...),
):
    """Set a PIN code for a user via UniFi API."""
    limited = await _enforce_action_rate_limit(request, user, "user_admin")
    if limited:
        return limited
    if not re.match(r'^[0-9]{4,8}$', pin_code):
        return _redirect(request, f"/users/{user_id}")

    db = request.app.state.db
    access = request.app.state.access_client
    enc_key = getattr(request.app.state, "enc_key", None)

    db_user = await db.get_user(user_id)
    if not db_user or not db_user.get("ulp_id"):
        return _redirect(request, f"/users/{user_id}")

    try:
        await access.set_user_pin(db_user["ulp_id"], pin_code)
    except Exception:
        logger.exception("Failed to set PIN for user %s via UniFi API", db_user.get("name"))
        return _redirect(request, f"/users/{user_id}")

    if enc_key:
        pin_encrypted = encrypt_value(pin_code, enc_key)
        await db.update_user_pin(user_id, pin_encrypted)

    await db.log_admin_action(user, "user_pin_set", db_user.get("name", str(user_id)))
    return _redirect(request, f"/users/{user_id}")


async def _load_settings_context(request: Request, db, enc_key) -> dict:
    """Load all data needed for the settings page template."""
    api_keys = await db.get_all_api_keys()

    unvr_host = await db.get_config("unvr_host") or ""
    unvr_username = ""
    if enc_key:
        raw = await db.get_config("unvr_username")
        if raw:
            try:
                unvr_username = decrypt_value(raw, enc_key)
            except Exception:
                logger.warning("Failed to decrypt UNVR username from config")
    ha_url = await db.get_config("ha_url") or ""

    access_host = await db.get_config("access_host") or ""
    access_username = ""
    if enc_key and access_host:
        raw = await db.get_config("access_username")
        if raw:
            try:
                access_username = decrypt_value(raw, enc_key)
            except Exception as exc:
                # Settings page falls back to a blank field if decryption
                # fails (e.g. after secret_key rotation). Log at warning
                # so a quiet failure mode is at least visible in the log.
                logger.warning("Settings: could not decrypt access_username: %s", exc)

    ha = request.app.state.ha_client
    alarm_panels = await db.get_all_alarm_panels()
    ha_alarms = []
    if ha and ha.connected:
        try:
            ha_alarms = await ha.get_alarm_entities()
            existing_eids = {p["entity_id"] for p in alarm_panels}
            ha_alarms = [a for a in ha_alarms if a["entity_id"] not in existing_eids]
        except Exception as exc:
            # HA may have temporarily dropped or returned an unexpected
            # shape — Settings page renders with an empty alarm dropdown.
            # Log for diagnostics.
            logger.warning("Settings: could not fetch HA alarm entities: %s", exc)

    admin_log = await db.get_admin_log(50)

    reboot_enabled = (await db.get_config("reboot_enabled")) == "1"
    reboot_day = await db.get_config("reboot_day") or "daily"
    reboot_hour_raw = await db.get_config("reboot_hour")
    try:
        reboot_hour = int(reboot_hour_raw) if reboot_hour_raw is not None else 4
    except (TypeError, ValueError):
        reboot_hour = 4

    return {
        "api_keys": api_keys,
        "unvr_host": unvr_host,
        "unvr_username": unvr_username,
        "access_host": access_host,
        "access_username": access_username,
        "ha_url": ha_url,
        "alarm_panels": alarm_panels,
        "ha_alarms": ha_alarms,
        "admin_log": admin_log,
        "reboot_enabled": reboot_enabled,
        "reboot_day": reboot_day,
        "reboot_hour": reboot_hour,
    }


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request, user: str = Depends(require_login)):
    """Settings page with connection and API key management."""
    db = request.app.state.db
    enc_key = getattr(request.app.state, "enc_key", None)
    ctx = await _load_settings_context(request, db, enc_key)
    restarting = request.query_params.get("restarting") == "1"

    return await _render(
        "settings.html",
        request,
        {
            "request": request,
            "user": user,
            "page": "settings",
            **ctx,
            "save_result": None,
            "restarting": restarting,
            "created_api_key": None,
        },
    )


@router.post("/settings/unvr", response_class=HTMLResponse)
async def update_unvr(
    request: Request,
    unvr_host: str = Form(...),
    unvr_username: str = Form(...),
    unvr_password: str = Form(...),
    user: str = Depends(require_csrf),
):
    """Update UNVR connection credentials. Tests before saving."""
    limited = await _enforce_action_rate_limit(request, user, "settings_admin")
    if limited:
        return limited
    db = request.app.state.db
    enc_key = getattr(request.app.state, "enc_key", None)

    # Test the new credentials
    test_client = AccessClient(unvr_host, unvr_username, unvr_password)
    try:
        await test_client.login()
    except AccessClientError as exc:
        # Sanitize the user-facing message; the AccessClient already
        # logs the raw upstream response body at warning level.
        # Audit 2026-05-24, H1.
        logger.warning("UNVR connection test failed during settings update: %s", exc)
        return await _settings_with_result(request, user, db, enc_key, "UNVR connection failed. Check host and credentials.")
    finally:
        await test_client.close()

    # Save encrypted credentials
    await db.set_config("unvr_host", unvr_host)
    await db.set_config("unvr_username", encrypt_value(unvr_username, enc_key))
    await db.set_config("unvr_password", encrypt_value(unvr_password, enc_key))

    # Reconnect the live client + WebSocket + auth engine reference
    old_client = request.app.state.access_client
    if old_client:
        await old_client.close()
    new_client = AccessClient(unvr_host, unvr_username, unvr_password)
    await new_client.login()
    request.app.state.access_client = new_client
    if request.app.state.auth_engine:
        request.app.state.auth_engine._access_client = new_client

    # Keep stashed UNVR creds in sync so the Protect cold-start supervisor
    # and any future use_creds() helpers see the new password if the live
    # client drops and needs re-creation.
    request.app.state.unvr_creds = (unvr_host, unvr_username, unvr_password)

    # Re-register WS callback and start WebSocket on new client
    on_access_event = getattr(request.app.state, "on_access_event", None)
    if on_access_event:
        new_client.register_callback(on_access_event)
    await new_client.start_websocket()
    logger.info("Access WebSocket re-started after credential update")

    # Reconnect the Protect client with the same new UNVR credentials.
    # If Protect was not running before (cold-start failure), the supervisor
    # will pick it up on its next tick now that unvr_creds is updated.
    old_protect = request.app.state.protect_client
    if old_protect:
        await old_protect.close()
    request.app.state.protect_client = None
    starter = getattr(request.app.state, "start_protect_client", None)
    if starter is not None:
        try:
            await starter()
        except Exception:
            logger.exception("Failed to restart Protect client after credential update")

    # Refresh users / native locks / camera_to_location against the new
    # console — otherwise stale until the 15-min topology resync ticks.
    sync = getattr(request.app.state, "sync_users", None)
    if sync is not None:
        try:
            await sync()
        except Exception:
            logger.exception("sync_users after UNVR credential update failed")

    await db.log_admin_action(user, "settings_unvr_update")
    return await _settings_with_result(request, user, db, enc_key, "UNVR connection updated successfully.", success=True)


@router.post("/settings/ha", response_class=HTMLResponse)
async def update_ha(
    request: Request,
    ha_url: str = Form(...),
    ha_token: str = Form(...),
    user: str = Depends(require_csrf),
):
    """Update Home Assistant connection credentials. Tests before saving."""
    limited = await _enforce_action_rate_limit(request, user, "settings_admin")
    if limited:
        return limited
    db = request.app.state.db
    enc_key = getattr(request.app.state, "enc_key", None)

    # Test the new credentials
    test_client = HAClient(ha_url, ha_token)
    try:
        ok = await test_client.test_connection()
        if not ok:
            return await _settings_with_result(request, user, db, enc_key, "HA connection failed. Check URL and token.")
    except Exception as exc:
        # Sanitize: don't surface raw aiohttp / SSL / token-validation
        # exception strings to the dashboard. Audit 2026-05-24, H1.
        logger.warning("HA connection test failed during settings update: %s", exc)
        return await _settings_with_result(request, user, db, enc_key, "HA connection failed. Check URL and token.")
    finally:
        await test_client.close()

    # Save encrypted credentials
    await db.set_config("ha_url", ha_url)
    await db.set_config("ha_token", encrypt_value(ha_token, enc_key))

    # Reconnect the live client + auth engine reference
    old_client = request.app.state.ha_client
    if old_client:
        await old_client.close()
    new_client = HAClient(ha_url, ha_token)
    await new_client.test_connection()
    request.app.state.ha_client = new_client
    if request.app.state.auth_engine:
        request.app.state.auth_engine._ha_client = new_client

    # Re-seed lock_states and re-attempt pending relocks against the new
    # client. The HA recovery loop won't fire on this swap (no
    # disconnected→connected transition was observed), so do it explicitly.
    seed = getattr(request.app.state, "seed_lock_states", None)
    if seed is not None:
        try:
            await seed()
        except Exception:
            logger.exception("Lock-state reseed after HA credential update failed")
    rm = getattr(request.app.state, "relock_manager", None)
    if rm is not None:
        try:
            await rm.rehydrate()
        except Exception:
            logger.exception("Pending-relock rehydrate after HA credential update failed")

    await db.log_admin_action(user, "settings_ha_update")
    return await _settings_with_result(request, user, db, enc_key, "Home Assistant connection updated successfully.", success=True)


@router.post("/settings/access-console", response_class=HTMLResponse)
async def update_access_console(
    request: Request,
    user: str = Depends(require_csrf),
    access_host: str = Form(default=""),
    access_username: str = Form(default=""),
    access_password: str = Form(default=""),
    clear: str = Form(default=""),
):
    """Save separate Access console credentials (or clear to use primary)."""
    limited = await _enforce_action_rate_limit(request, user, "settings_admin")
    if limited:
        return limited
    db = request.app.state.db
    enc_key = getattr(request.app.state, "enc_key", None)

    if clear:
        await db.set_config("access_host", "")
        await db.set_config("access_username", "")
        await db.set_config("access_password", "")
        await db.log_admin_action(user, "settings_access_console_clear")
        return await _settings_with_result(
            request, user, db, enc_key,
            "Access console cleared — using primary console. Restart to apply.",
            success=True,
        )

    if not access_host or not access_username or not access_password:
        return await _settings_with_result(
            request, user, db, enc_key,
            "All fields required for separate Access console.",
        )

    # Test the connection
    test_client = AccessClient(host=access_host, username=access_username, password=access_password)
    try:
        await test_client.login()
    except Exception as exc:
        # Sanitize: don't surface raw upstream errors. Audit 2026-05-24, H1.
        logger.warning("Access console connection test failed during settings update: %s", exc)
        return await _settings_with_result(
            request, user, db, enc_key,
            "Access console connection failed. Check host and credentials.",
        )
    finally:
        await test_client.close()

    await db.set_config("access_host", access_host)
    await db.set_config("access_username", encrypt_value(access_username, enc_key))
    await db.set_config("access_password", encrypt_value(access_password, enc_key))
    await db.log_admin_action(user, "settings_access_console_update", access_host)
    return await _settings_with_result(
        request, user, db, enc_key,
        f"Access console configured at {access_host}. Restart to apply.",
        success=True,
    )


async def _settings_with_result(request, user, db, enc_key, message, success=False):
    """Re-render settings page with a result message."""
    ctx = await _load_settings_context(request, db, enc_key)
    return await _render(
        "settings.html",
        request,
        {
            "request": request,
            "user": user,
            "page": "settings",
            **ctx,
            "save_result": {"message": message, "success": success},
            "restarting": False,
            "created_api_key": None,
        },
    )


@router.post("/settings/api-keys/create", response_class=HTMLResponse)
async def create_api_key(
    request: Request,
    name: str = Form(...),
    scope: str = Form(default="full"),
    user: str = Depends(require_csrf),
):
    """Generate a new API key."""
    limited = await _enforce_action_rate_limit(request, user, "settings_admin")
    if limited:
        return limited
    db = request.app.state.db
    enc_key = getattr(request.app.state, "enc_key", None)
    raw_key = generate_api_key()
    await db.add_api_key(name, hash_api_key(raw_key), scope=scope)
    await db.log_admin_action(user, "api_key_create", name)
    ctx = await _load_settings_context(request, db, enc_key)
    return await _render(
        "settings.html",
        request,
        {
            "request": request,
            "user": user,
            "page": "settings",
            **ctx,
            "save_result": {"message": f"API key '{name}' created. Copy it now; it will not be shown again.", "success": True},
            "restarting": False,
            "created_api_key": raw_key,
        },
    )


@router.post("/settings/api-keys/{key_id}/delete")
async def delete_api_key(
    key_id: int,
    request: Request,
    user: str = Depends(require_csrf),
):
    """Revoke an API key."""
    limited = await _enforce_action_rate_limit(request, user, "settings_admin")
    if limited:
        return limited
    db = request.app.state.db
    await db.delete_api_key(key_id)
    await db.log_admin_action(user, "api_key_revoke", str(key_id))
    return _redirect(request, "/settings")


@router.post("/sync-users")
async def sync_users(request: Request, user: str = Depends(require_csrf)):
    """Trigger a full sync (users, native locks, camera→location map) from UniFi Access API."""
    limited = await _enforce_action_rate_limit(request, user, "service_action")
    if limited:
        return limited
    sync_users_fn = request.app.state.sync_users
    if sync_users_fn is not None:
        try:
            await sync_users_fn()
        except Exception as exc:
            logger.exception("Error during user sync: %s", exc)
    # Allow redirect override (e.g. from locks page)
    form = await request.form()
    redirect_to = form.get("redirect", "/users")
    if redirect_to not in ("/users", "/locks", "/"):
        redirect_to = "/users"
    return _redirect(request, redirect_to)


@router.post("/users/add")
async def add_user_route(
    request: Request,
    user: str = Depends(require_csrf),
    first_name: str = Form(...),
    last_name: str = Form(...),
):
    """Create a new user in UniFi Access and sync."""
    limited = await _enforce_action_rate_limit(request, user, "user_admin")
    if limited:
        return limited
    db = request.app.state.db
    access = request.app.state.access_client

    try:
        user_data = await access.create_user(first_name, last_name)
    except Exception:
        logger.exception("Failed to create user in UniFi")
        return _redirect(request, "/users")
    ulp_id = user_data.get("unique_id", "")
    full_name = user_data.get("full_name", f"{first_name} {last_name}")

    if ulp_id:
        await db.upsert_user(
            ulp_id=ulp_id,
            name=full_name,
            email=user_data.get("email") or None,
            status=user_data.get("status", "ACTIVE"),
        )

    await db.log_admin_action(user, "user_create", full_name)
    return _redirect(request, "/users")


@router.post("/settings/restart")
async def restart_service(request: Request, user: str = Depends(require_csrf)):
    """Restart the access-control systemd service."""
    limited = await _enforce_action_rate_limit(request, user, "service_action")
    if limited:
        return limited
    logger.info("Service restart requested by %s", user)
    db = request.app.state.db
    await db.log_admin_action(user, "service_restart")
    restart_cmd = os.environ.get("RESTART_COMMAND", "systemctl restart access-control")

    async def _do_restart():
        await asyncio.sleep(1.5)
        parts = shlex.split(restart_cmd)
        proc = await asyncio.create_subprocess_exec(
            *parts,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()

    asyncio.create_task(_do_restart(), name="service-restart")
    return _redirect(request, "/settings?restarting=1")


@router.post("/settings/reboot-schedule")
async def update_reboot_schedule(
    request: Request,
    reboot_enabled: str = Form(default=""),
    reboot_day: str = Form(default="daily"),
    reboot_hour: int = Form(default=4),
    user: str = Depends(require_csrf),
):
    """Update the scheduled-reboot configuration."""
    limited = await _enforce_action_rate_limit(request, user, "settings_admin")
    if limited:
        return limited
    db = request.app.state.db

    enabled = "1" if reboot_enabled in ("1", "on", "true", "yes") else "0"
    day = reboot_day if reboot_day in ("daily", "0", "1", "2", "3", "4", "5", "6") else "daily"
    hour = max(0, min(23, int(reboot_hour)))

    await db.set_config("reboot_enabled", enabled)
    await db.set_config("reboot_day", day)
    await db.set_config("reboot_hour", str(hour))
    await db.log_admin_action(
        user, "reboot_schedule_update",
        target=f"enabled={enabled} day={day} hour={hour}",
    )
    return _redirect(request, "/settings")
