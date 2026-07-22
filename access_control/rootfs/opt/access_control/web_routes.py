"""Dashboard HTML routes for the Access Control App."""
from __future__ import annotations

import asyncio
import hashlib
import inspect
import logging
import os
import re
import sqlite3
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone, tzinfo
from pathlib import Path
from urllib.parse import quote_plus

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .access_client import AccessClient, AccessClientError
from .protect_client import ProtectClient
from .config import (
    SECRET_KEY_SOURCE_DATABASE,
    SECRET_KEY_SOURCE_ENVIRONMENT,
    decrypt_value,
    derive_key,
    encrypt_value,
    generate_api_key,
    hash_api_key,
    hash_password,
    secret_key_fingerprint,
    verify_password,
)
from .ha_client import HAClient
from .lock_actions import execute_lock_action
from .service_restart import request_service_restart
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


def _asset_version(name: str) -> str:
    """Short content hash of a bundled static asset, for cache busting.

    Browsers apply heuristic freshness to responses without Cache-Control,
    so after an add-on update a cached stale app.css could be served against
    new templates — rendering the dashboard with no utility styles at all.
    Versioned URLs make every asset change a new URL. Computed once at
    import; the bundle only changes when the container image does.
    """
    try:
        data = (Path(__file__).parent / "static" / name).read_bytes()
    except OSError:
        return "0"
    return hashlib.sha256(data).hexdigest()[:12]


ASSET_VERSIONS = {
    "app.css": _asset_version("app.css"),
    "app.js": _asset_version("app.js"),
}

try:
    templates.env.filters["credential_label"] = _credential_label
    templates.env.globals["asset_v"] = ASSET_VERSIONS
except AttributeError:
    # Test suites that stub fastapi.templating with a minimal class won't
    # have an `env` attribute. Production Jinja2Templates always does.
    pass

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DAY_NAMES = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
_LOCK_ENTITY_ID_RE = re.compile(r"^lock\.[a-z0-9_]+$")
_ALARM_ENTITY_ID_RE = re.compile(r"^alarm_control_panel\.[a-z0-9_]+$")
# 24-hour HH:MM. Validated wherever schedule start/end strings are
# accepted; the auth engine treats malformed values as "always inactive"
# which fails closed, but rejecting at the form layer is friendlier.
_TIME_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
_LOCKS_CACHE_TTL = 30
_VISITORS_CACHE_TTL = 30
# Must exceed the home page's 10s htmx auto-refresh: at the old 5s TTL
# every poll was a guaranteed cache miss — an HA call plus a ui_cache
# write transaction every 10s per open tab (e2e review 2026-07-12).
_ALARM_CACHE_TTL = 15
_ACTION_RATE_LIMIT = {"max_attempts": 20, "window": 60, "lockout": 60}
_LOGIN_RATE_LIMIT = {"max_attempts": 5, "window": 300, "lockout": 60}
# /setup is intentionally CSRF + login exempt (first-run has no session
# yet). Rate-limited harder than /login because every attempt drives a
# live UNVR + HA connection test — attacker brute-forces upstream creds
# through us if we don't cap. Audit 2026-05-24, C2.
_SETUP_RATE_LIMIT = {"max_attempts": 3, "window": 300, "lockout": 300}
_MIN_DIRECT_ADMIN_PASSWORD_LENGTH = 12
_MIN_ENVIRONMENT_SECRET_KEY_LENGTH = 32
_API_KEY_SCOPES = frozenset({"full", "read_only", "locks_only"})
_ENTRY_DEVICE_TYPES = frozenset(
    {"access_reader", "protect_doorbell"}
)


def _log_task_exception(task: asyncio.Task) -> None:
    """Callback for fire-and-forget tasks — log any unhandled exceptions."""
    if task.cancelled():
        return
    exc = task.exception()
    if exc:
        logger.error("Unhandled exception in task %r: %s", task.get_name(), exc, exc_info=exc)


def _ui_cache_refresh_inflight(request: Request) -> dict:
    """Per-app map of UI-cache key → in-flight background refresh task.

    Serves two purposes: it de-duplicates concurrent refreshes of the same
    stale key (a burst of page loads fires one upstream fetch, not several),
    and it keeps a strong reference to each fire-and-forget task so the event
    loop can't garbage-collect it mid-flight.
    """
    inflight = getattr(request.app.state, "_ui_cache_refresh_inflight", None)
    if inflight is None:
        inflight = {}
        request.app.state._ui_cache_refresh_inflight = inflight
    return inflight


def _ui_cache_updated_at(request: Request) -> dict[str, float]:
    """Track when each in-process upstream snapshot was actually fetched."""
    observed = getattr(request.app.state, "_ui_cache_updated_at", None)
    if observed is None:
        observed = {}
        request.app.state._ui_cache_updated_at = observed
    return observed


async def _cached_device_options(request: Request, key: str, ttl: int, fetch):
    """Return cached dashboard data for `key` without blocking on the upstream.

    The per-page device pickers (HA lock entities, Access door locations,
    Protect cameras) come from upstream calls that take hundreds of ms — and
    occasionally seconds — on a cold cache. Paying that on every page render is
    what made tab switches feel slow (e2e review 2026-07-12).

    Stale-while-revalidate: a fresh entry is returned directly; a stale or
    missing one returns the stale value (or ``None``) immediately and schedules
    a single background refresh so the *next* render is fresh. `fetch` is an
    async callable returning the value to cache — the render never awaits it.

    Databases that predate :meth:`peek_ui_cache` (the hand-rolled fakes in the
    test-suite) transparently fall back to the original block-once-on-miss
    behaviour, so existing handler tests keep their exact semantics.
    """
    db = request.app.state.db
    peek = getattr(db, "peek_ui_cache", None)
    if peek is None:
        # Legacy path — block on a miss, exactly as before SWR existed.
        value = await db.get_ui_cache(key)
        if value is not None:
            return value
        try:
            refresh_started_at = time.monotonic()
            value = await fetch()
        except Exception:
            logger.exception("Failed to refresh UI cache %r", key)
            return None
        await db.set_ui_cache(key, value, ttl)
        _ui_cache_updated_at(request)[key] = refresh_started_at
        return value

    value, fresh = await peek(key)
    if fresh:
        return value

    inflight = _ui_cache_refresh_inflight(request)
    if key not in inflight:
        async def _refresh() -> None:
            try:
                refresh_started_at = time.monotonic()
                fresh_value = await fetch()
                await db.set_ui_cache(key, fresh_value, ttl)
                _ui_cache_updated_at(request)[key] = refresh_started_at
            finally:
                inflight.pop(key, None)

        task = asyncio.create_task(_refresh(), name=f"ui-cache-refresh:{key}")
        inflight[key] = task
        tracker = getattr(request.app.state, "track_background_task", None)
        if callable(tracker):
            # The lifespan owns and drains this task before closing clients or
            # SQLite. The tracker also logs unhandled task exceptions.
            tracker(task)
        else:
            # Keep helpers and independently mounted routers backward
            # compatible when no application lifespan installed a tracker.
            task.add_done_callback(_log_task_exception)
    # Serve whatever we have (possibly stale, or None on first-ever load); the
    # background refresh makes the next render fresh.
    return value


def _extract_schedule_days(form) -> str | None:
    """Extract checked day checkboxes from form and return comma-separated day names."""
    selected = [d for d in _DAY_NAMES if form.get(d)]
    return ",".join(selected) if selected else None


def _schedule_validation_error(
    *,
    enabled: bool,
    days: str | None,
    start: str | None,
    end: str | None,
) -> str | None:
    """Validate a schedule at the trust boundary.

    Days-only schedules mean all day on the selected days. Time-only
    schedules mean the window applies every day. An enabled schedule with
    no restriction, or only one time bound, is almost certainly a partial
    form submission and must fail closed.
    """
    if start and not _TIME_RE.fullmatch(start):
        return "Invalid start time format."
    if end and not _TIME_RE.fullmatch(end):
        return "Invalid end time format."
    if bool(start) != bool(end):
        return "Schedule start and end times must be provided together."
    if enabled and not days and not (start and end):
        return "Enabled schedules need at least one day or a time range."
    return None


def _site_timezone(request: Request) -> tzinfo:
    """Return the HA-configured timezone used by the auth engine."""
    engine = getattr(request.app.state, "auth_engine", None)
    configured = getattr(engine, "tz", None)
    if configured is not None:
        return configured
    return datetime.now(timezone.utc).astimezone().tzinfo or timezone.utc


def _timezone_label(value: tzinfo) -> str:
    return getattr(value, "key", None) or str(value)


def _parse_site_datetime(date_value: str, time_value: str, zone: tzinfo) -> datetime:
    """Parse a local wall time and reject DST gaps or ambiguous folds."""
    naive = datetime.strptime(
        f"{date_value} {time_value}", "%Y-%m-%d %H:%M"
    )
    candidates: dict[float, datetime] = {}
    for fold in (0, 1):
        aware = naive.replace(tzinfo=zone, fold=fold)
        timestamp = aware.timestamp()
        round_trip = datetime.fromtimestamp(timestamp, zone)
        if round_trip.replace(tzinfo=None) == naive:
            candidates[timestamp] = aware
    if not candidates:
        raise ValueError("That local time does not exist because of a DST change.")
    if len(candidates) > 1:
        raise ValueError("That local time is ambiguous because of a DST change.")
    return next(iter(candidates.values()))


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


async def _audit_policy_change(
    db, username: str, action: str, target: str, detail: str
) -> None:
    """Best-effort policy audit that cannot hide a committed mutation."""
    try:
        await db.log_admin_action(username, action, target, detail)
    except Exception:
        logger.exception(
            "Failed to persist dashboard policy audit action=%s target=%s",
            action,
            target,
        )


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
    # A background status refresh is not user activity. Refreshing the
    # four-hour cookie on the 10-second poll kept an abandoned dashboard
    # authenticated forever and emitted needless Set-Cookie traffic.
    background_poll = (
        getattr(request, "headers", {}).get("X-Background-Poll") == "true"
    )
    if user and not background_poll:
        refresh_session_cookie(response, request, user)
    return response


def _client_ip(request: Request) -> str:
    # Use getattr so test fixtures with stripped-down Request stand-ins
    # (no `.client` attribute) don't crash this helper.
    client = getattr(request, "client", None)
    return client.host if client else "unknown"


def _same_console_endpoint(left: str | None, right: str | None) -> bool:
    """Compare configured console endpoints conservatively."""
    return (left or "").strip().rstrip("/").casefold() == (
        right or ""
    ).strip().rstrip("/").casefold()


async def _get_access_identity(client) -> str | None:
    getter = getattr(client, "get_console_identity", None)
    if not callable(getter):
        return None
    return await getter()


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


@asynccontextmanager
async def _physical_barrier(request: Request):
    """Serialize client publication with physical lock/alarm commands."""
    command_lock = getattr(request.app.state, "physical_command_lock", None)
    if command_lock is None:
        yield
        return
    async with command_lock:
        yield


async def _quiesce_event_sources(request: Request, *clients) -> None:
    """Stop old WebSockets and drain callbacks before publishing new clients."""
    for client in clients:
        if client is None:
            continue
        stop = getattr(client, "stop_websocket", None)
        if callable(stop):
            result = stop()
            if inspect.isawaitable(result):
                await result
    drain = getattr(request.app.state, "drain_event_tasks", None)
    if callable(drain):
        result = drain()
        if inspect.isawaitable(result):
            await result


def _visitor_operation_lock(request: Request, visitor_id: int) -> asyncio.Lock:
    """Return the stable per-visitor lock for upstream/local transitions."""
    locks = getattr(request.app.state, "visitor_operation_locks", None)
    if locks is None:
        locks = {}
        request.app.state.visitor_operation_locks = locks
    return locks.setdefault(visitor_id, asyncio.Lock())


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
    if not await db.consume_rate_limit(
        "login", client_ip, **_LOGIN_RATE_LIMIT
    ):
        return templates.TemplateResponse(
            request,
            "login.html",
            _inject_ingress_context(request, {"request": request, "error": "Too many failed attempts. Try again in 60 seconds."}),
            status_code=429,
        )

    stored_username = await db.get_config("admin_username")
    stored_password_hash = await db.get_config("admin_password_hash")

    # PBKDF2 at 480k iterations is ~hundreds of ms of pure CPU — run it
    # in a worker thread so a login attempt can't stall the event loop
    # (and with it WS door-event dispatch and relock timers). e2e review
    # 2026-07-12.
    password_ok = False
    if stored_username is not None and stored_password_hash is not None:
        password_ok = await asyncio.to_thread(
            verify_password, password, stored_password_hash
        )

    if stored_username is None or username != stored_username or not password_ok:
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


@router.post("/logout")
async def logout(request: Request, user: str = Depends(require_csrf)):
    """Delete session cookie and redirect to /login.

    State-changing (clears the session), so it is a POST guarded by
    require_csrf like every other mutating route — a bare GET would let a
    third-party page force-logout a signed-in admin via an <img>/<link>
    tag. There is intentionally no GET fallback: without a form-embedded
    CSRF token, GET /logout now 405s. Hardening review 2026-07-12.
    """
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
    access_host: str = Form(""),
    access_username: str = Form(""),
    access_password: str = Form(""),
    ha_url: str = Form(""),
    ha_token: str = Form(""),
    access_api_token: str = Form(""),
):
    """Serialize first-run so concurrent submissions cannot mix key bundles."""
    setup_lock = getattr(request.app.state, "setup_lock", None)
    if setup_lock is None:
        return await _setup_post_impl(
            request,
            admin_username,
            admin_password,
            unvr_host,
            unvr_username,
            unvr_password,
            access_host,
            access_username,
            access_password,
            ha_url,
            ha_token,
            access_api_token,
        )
    async with setup_lock:
        return await _setup_post_impl(
            request,
            admin_username,
            admin_password,
            unvr_host,
            unvr_username,
            unvr_password,
            access_host,
            access_username,
            access_password,
            ha_url,
            ha_token,
            access_api_token,
        )


async def _setup_post_impl(
    request: Request,
    admin_username: str,
    admin_password: str,
    unvr_host: str,
    unvr_username: str,
    unvr_password: str,
    access_host: str,
    access_username: str,
    access_password: str,
    ha_url: str,
    ha_token: str,
    access_api_token: str = "",
):
    """Validate upstream connections and persist first-run configuration.

    Security: this route is intentionally exempt from CSRF + login (no
    session exists during first-run). To prevent re-execution after the
    app is configured — which would overwrite admin credentials, rotate
    the encryption_salt (orphaning previously-encrypted UNVR/HA tokens
    and visitor PINs) — we hard-guard against
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
    if not await db.consume_rate_limit(
        "setup", client_ip, **_SETUP_RATE_LIMIT
    ):
        raise HTTPException(
            status_code=429,
            detail="Too many setup attempts. Try again in a minute.",
        )

    async def _render_error(error: str) -> HTMLResponse:
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
    #
    # Key on the HA user UUID rather than the username — usernames are
    # mutable (admin rename, backup restore against a different HA
    # instance) and would collide; UUIDs are stable per HA user. The
    # display name still surfaces via request.state.ingress_user["name"]
    # on every request, so the UI doesn't show a raw UUID.
    ingress_user = getattr(request.state, "ingress_user", None)
    if ingress_user:
        import secrets as _secrets
        admin_username = (
            ingress_user.get("id")
            or ingress_user.get("name")
            or f"ha-unknown-{_secrets.token_hex(4)}"
        )
        admin_password = _secrets.token_urlsafe(48)
    elif not admin_username.strip() or not admin_password:
        return await _render_error("Admin username and password are required.")
    elif len(admin_password) < _MIN_DIRECT_ADMIN_PASSWORD_LENGTH:
        return await _render_error(
            "Admin password must be at least "
            f"{_MIN_DIRECT_ADMIN_PASSWORD_LENGTH} characters."
        )
    else:
        admin_username = admin_username.strip()

    environment_secret_key = os.environ.get("ACCESS_CONTROL_SECRET_KEY")
    if (
        environment_secret_key
        and len(environment_secret_key) < _MIN_ENVIRONMENT_SECRET_KEY_LENGTH
    ):
        return await _render_error(
            "ACCESS_CONTROL_SECRET_KEY must be at least "
            f"{_MIN_ENVIRONMENT_SECRET_KEY_LENGTH} characters."
        )

    separate_access_values = (access_host, access_username, access_password)
    if any(separate_access_values) and not all(separate_access_values):
        return await _render_error(
            "Provide all three separate Access console fields, or leave all blank."
        )

    # 1. Authenticate the primary Protect console and the Access console.
    # They may be the same UniFi console or two independent appliances.
    protect_client = ProtectClient(unvr_host, unvr_username, unvr_password)
    try:
        await protect_client.login()
    except Exception as exc:
        logger.warning("Setup primary UNVR connection test failed: %s", exc)
        return await _render_error(
            "Failed to authenticate to the primary UNVR. Check host and credentials."
        )
    finally:
        await protect_client.close()

    access_target = (
        separate_access_values
        if all(separate_access_values)
        else (unvr_host, unvr_username, unvr_password)
    )
    # Direct unit calls see FastAPI's ``Form`` default object when the newly
    # added optional field is omitted; HTTP requests always supply a string.
    access_api_token = (
        access_api_token.strip() if isinstance(access_api_token, str) else ""
    )
    access_client = AccessClient(
        *access_target,
        api_token=access_api_token or None,
    )
    access_identity = None
    try:
        await access_client.login()
        access_identity = await _get_access_identity(access_client)
        if access_api_token:
            await access_client.validate_open_api()
    except AccessClientError as exc:
        logger.warning("Setup Access console connection test failed: %s", exc)
        return await _render_error(
            "Failed to connect to UniFi Access or validate its API token. "
            "Check the host, credentials, token, and view:space permission."
        )
    finally:
        await access_client.close()

    # 2. Test HA connection.
    #
    # When the Supervisor proxy is active (default for addon deployments),
    # we ALWAYS test against the Supervisor URL and ignore any form-
    # submitted ha_url/ha_token — the template doesn't render those
    # fields in that mode, but stray values from autofill, a bookmarklet,
    # or a curl resubmission could otherwise persist a long-lived token
    # to the DB. A persisted DB token shadows the Supervisor env var on
    # restart and breaks the addon after the next token rotation.
    if _supervisor_proxy_active():
        if ha_url or ha_token:
            logger.warning(
                "Setup form submitted ha_url/ha_token while Supervisor "
                "proxy is active — ignoring (template should have hidden "
                "those fields)."
            )
        ha_url_for_test = os.environ["ACCESS_CONTROL_HA_URL"]
        ha_token_for_test = os.environ["ACCESS_CONTROL_HA_TOKEN"]
        persist_ha_creds = False
    else:
        if not ha_url or not ha_token:
            return await _render_error(
                "Home Assistant URL and Long-Lived Access Token are required."
            )
        ha_url_for_test = ha_url
        ha_token_for_test = ha_token
        persist_ha_creds = True

    ha_client = HAClient(ha_url_for_test, ha_token_for_test)
    try:
        ok = await ha_client.test_connection()
    except Exception as exc:
        logger.warning("Setup HA connection test failed: %s", exc)
        ok = False
    finally:
        await ha_client.close()
    if not ok:
        # Branch the message on which mode we're in — telling a user who
        # never entered HA creds to "check URL and token" is misleading.
        if persist_ha_creds:
            err = "Failed to connect to Home Assistant. Check URL and token."
        else:
            err = (
                "Failed to reach Home Assistant via the Supervisor proxy "
                "(http://supervisor/core). Verify the addon has "
                "`homeassistant_api: true` in config.yaml, that Supervisor "
                "is healthy, and that ACCESS_CONTROL_HA_URL / _TOKEN are "
                "set (run.sh exports both when use_supervisor_api: true)."
            )
        return await _render_error(err)

    # 3. Select the secret-key source once. Environment-key installations
    # intentionally do not persist the key itself; the fingerprint detects a
    # missing or wrong value on every subsequent boot. Database-key mode is the
    # default and ignores an env var injected later, avoiding silent credential
    # decryption failure.
    import secrets
    if environment_secret_key:
        secret_key = environment_secret_key
        secret_key_source = SECRET_KEY_SOURCE_ENVIRONMENT
    else:
        secret_key = secrets.token_hex(32)
        secret_key_source = SECRET_KEY_SOURCE_DATABASE
    salt = os.urandom(16)
    enc_key = derive_key(secret_key, salt)

    # 4. Save credentials to config. init_runtime() below re-reads these
    # from the DB to bring up the runtime clients (AccessClient, HAClient,
    # etc.), so the writes have to land before init_runtime() runs.
    config_values = {
        "admin_username": admin_username,
        "admin_password_hash": await asyncio.to_thread(
            hash_password, admin_password
        ),
        "secret_key_source": secret_key_source,
        "secret_key_fingerprint": secret_key_fingerprint(secret_key),
        "encryption_salt": salt.hex(),
        "unvr_host": unvr_host,
        "unvr_username": encrypt_value(unvr_username, enc_key),
        "unvr_password": encrypt_value(unvr_password, enc_key),
    }
    if secret_key_source == SECRET_KEY_SOURCE_DATABASE:
        config_values["secret_key"] = secret_key
    if all(separate_access_values):
        config_values.update(
            {
                "access_host": access_host,
                "access_username": encrypt_value(access_username, enc_key),
                "access_password": encrypt_value(access_password, enc_key),
            }
        )
    if persist_ha_creds:
        config_values.update(
            {
                "ha_url": ha_url,
                "ha_token": encrypt_value(ha_token, enc_key),
            }
        )
    if access_identity:
        config_values["access_console_identity"] = access_identity
    if access_api_token:
        config_values["access_api_token"] = encrypt_value(
            access_api_token, enc_key
        )
    await db.set_configs(config_values)

    # 5. Run runtime initialization. If init fails, the addon recovers on the
    # next restart via lifespan(); credentials are already persisted.
    request.app.state.configured = True
    try:
        init_runtime = getattr(request.app.state, "initialize_configured_state", None)
        if init_runtime is None:
            raise RuntimeError("Runtime initializer unavailable")
        await init_runtime()
    except Exception:
        logger.exception("Setup completed but runtime initialization failed")
        request.app.state.configured = False
        return await _render_error(
            "Setup was saved, but runtime initialization failed. "
            "Credentials were persisted — restart the addon to retry "
            "(env-var fallback will pick up Supervisor-proxy creds) and "
            "generate an API key from Settings once it comes up."
        )

    # API keys are created from Settings where the raw value can be shown once.
    # Creating a hash here and then redirecting made the first key unusable.
    await db.clear_rate_limit("setup", client_ip)

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
        rule_id = await db.add_rule(user_id, lock_id)
        await _audit_policy_change(
            db,
            user,
            "access_rule_add",
            str(rule_id),
            f"user_id={user_id} lock_id={lock_id}",
        )

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

    updated_rule = await db.toggle_rule_enabled(rule_id)
    if updated_rule is None:
        return _redirect(request, "/users")

    user_id = updated_rule["user_id"]
    await _audit_policy_change(
        db,
        user,
        "access_rule_toggle",
        str(rule_id),
        f"enabled={bool(updated_rule['enabled'])}",
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
    if rule is not None:
        await _audit_policy_change(
            db,
            user,
            "access_rule_delete",
            str(rule_id),
            f"user_id={rule['user_id']} lock_id={rule['lock_id']}",
        )

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

    schedule_error = _schedule_validation_error(
        enabled=enabled_flag,
        days=days_str,
        start=schedule_start or None,
        end=schedule_end or None,
    )
    if schedule_error:
        return _redirect(
            request, f"/users/{user_id}?error={quote_plus(schedule_error)}"
        )

    updated_rule = await db.update_rule_schedule(
        rule_id,
        schedule_enabled=enabled_flag,
        schedule_days=days_str,
        schedule_start=schedule_start or None,
        schedule_end=schedule_end or None,
    )
    if updated_rule is None:
        return _redirect(request, "/users")
    user_id = updated_rule["user_id"]
    await _audit_policy_change(
        db,
        user,
        "access_rule_schedule_update",
        str(rule_id),
        (
            f"enabled={enabled_flag} days={days_str or '-'} "
            f"start={schedule_start or '-'} end={schedule_end or '-'}"
        ),
    )

    return _redirect(request, f"/users/{user_id}")


@router.get("/locks", response_class=HTMLResponse)
async def locks_list(request: Request, user: str = Depends(require_login)):
    """Locks list with state, actions, and add form."""
    db = request.app.state.db
    ha = request.app.state.ha_client
    locks = await db.get_all_locks(include_hidden=True)
    entry_devices_by_lock = await db.get_entry_devices_for_locks([lock["id"] for lock in locks])

    # Compare observation times: a confirmed command must beat a pre-command
    # /api/states snapshot, while a later snapshot must beat an older command
    # cache and capture external thumb-turn/integration changes.
    lock_states = getattr(request.app.state, "lock_states", {})
    lock_state_updated_at = getattr(
        request.app.state, "lock_state_updated_at", {}
    )
    all_ha_locks = []
    ha_states = {}
    ha_snapshot_updated_at = 0.0
    if ha and ha.connected:
        # get_lock_entities() downloads HA's ENTIRE /api/states payload
        # (1-5 MB on a mid-sized install). Serve it stale-while-revalidate so
        # the render never blocks on it; live lock state still comes from the
        # in-memory lock_states cache below, this is only the fallback + the
        # "add lock" picker (e2e review 2026-07-12).
        all_ha_locks = await _cached_device_options(
            request, "locks_ha_lock_entities", _LOCKS_CACHE_TTL, ha.get_lock_entities
        ) or []
        ha_states = {l["entity_id"]: l["state"] for l in all_ha_locks}
        ha_snapshot_updated_at = _ui_cache_updated_at(request).get(
            "locks_ha_lock_entities", 0.0
        )

    # Per-lock pending/overdue re-lock status for the "re-lock pending/overdue"
    # card badge. One read; annotate each affected lock below.
    relock_manager = getattr(request.app.state, "relock_manager", None)
    relock_status: dict[str, bool] = {}
    if relock_manager is not None:
        relock_status = await relock_manager.pending_relock_status()

    for lock in locks:
        if lock["type"] == "ha_external" and lock.get("entity_id"):
            entity_id = lock["entity_id"]
            command_state = lock_states.get(entity_id)
            snapshot_state = ha_states.get(entity_id)
            command_updated_at = lock_state_updated_at.get(
                entity_id, -1.0
            )
            if (
                command_state is not None
                and (
                    snapshot_state is None
                    or command_updated_at > ha_snapshot_updated_at
                )
            ):
                lock["state"] = command_state
            else:
                lock["state"] = snapshot_state or "unknown"
        elif lock["type"] == "access_native" and lock.get("device_id"):
            lock["state"] = lock_states.get(lock["device_id"], "unknown")
        else:
            lock["state"] = "unknown"
        lock["entry_devices"] = entry_devices_by_lock.get(lock["id"], [])
        eid = lock.get("entity_id")
        if eid in relock_status:
            lock["relock_pending"] = True
            lock["relock_overdue"] = relock_status[eid]

    # Available HA locks for adding (exclude already-added)
    ha_locks = []
    if all_ha_locks:
        existing_eids = {l["entity_id"] for l in locks if l.get("entity_id")}
        ha_locks = [l for l in all_ha_locks if l["entity_id"] not in existing_eids]

    # Fetch Access locations for device association
    access = request.app.state.access_client
    access_locations = []
    if access and access.connected:
        async def _fetch_access_locations():
            return access.parse_door_locations(await access.get_bootstrap())
        access_locations = await _cached_device_options(
            request, "locks_access_locations", _LOCKS_CACHE_TTL, _fetch_access_locations
        ) or []

    # Fetch Protect cameras/doorbells for device association
    protect = request.app.state.protect_client
    protect_doorbells = []
    protect_cameras = []
    if protect and protect.connected:
        async def _fetch_protect_cameras():
            all_cams = await protect.get_cameras()
            doorbells = [c for c in all_cams if c["is_doorbell"] and c["connected"]]
            cameras = [c for c in all_cams if not c["is_doorbell"] and c["connected"]]
            return [doorbells, cameras]
        cached_cameras = await _cached_device_options(
            request, "locks_protect_cameras", _LOCKS_CACHE_TTL, _fetch_protect_cameras
        )
        if cached_cameras:
            protect_doorbells, protect_cameras = cached_cameras

    return await _render(
        "locks.html",
        request,
        {
            "request": request, "user": user, "page": "locks",
            "locks": locks, "ha_locks": ha_locks,
            "access_locations": access_locations,
            "protect_doorbells": protect_doorbells, "protect_cameras": protect_cameras,
            "command_notice": getattr(request, "query_params", {}).get("notice"),
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
    if not _LOCK_ENTITY_ID_RE.fullmatch(entity_id):
        return _redirect(request, "/locks?error=Invalid+entity+ID+format")
    if not 1 <= relock_duration <= 300:
        return _redirect(request, "/locks?error=Relock+duration+must+be+1-300+seconds")
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
    relock_on_remote: str = Form(default=""),
    relock_on_device_auth: str = Form(default=""),
    sync_hub_state: str = Form(default=""),
    relock_on_ha_origin: str = Form(default=""),
    preserve_hold_on_restart: str = Form(default=""),
    user: str = Depends(require_csrf),
):
    limited = await _enforce_action_rate_limit(request, user, "lock_admin")
    if limited:
        return limited
    if not 1 <= relock_duration <= 300:
        return _redirect(request, "/locks?error=Relock+duration+must+be+1-300+seconds")
    db = request.app.state.db
    # access_location_id is intentionally NOT accepted here: the settings
    # form has never rendered it, and passing a blank form default through
    # was silently NULLing legacy hub pairings on every save (e2e review
    # 2026-07-12). update_lock_settings preserves the column when the
    # kwarg is omitted.
    await db.update_lock_settings(
        lock_id,
        buzz_enabled=bool(buzz_enabled),
        relock_duration=relock_duration,
        relock_on_remote=bool(relock_on_remote),
        relock_on_device_auth=bool(relock_on_device_auth),
        sync_hub_state=bool(sync_hub_state),
        relock_on_ha_origin=bool(relock_on_ha_origin),
        preserve_hold_on_restart=bool(preserve_hold_on_restart),
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
    if device_type not in _ENTRY_DEVICE_TYPES or not device_id:
        return _redirect(request, "/locks?error=Invalid+entry+device")
    if await db.get_lock(lock_id) is None:
        return _redirect(request, "/locks?error=Unknown+lock")
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
    devices = await db.get_entry_devices_for_lock(lock_id)
    if not any(device["id"] == ed_id for device in devices):
        return _redirect(request, "/locks?error=Entry+device+does+not+belong+to+lock")
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


@router.post("/locks/{lock_id}/follow-schedule")
async def follow_lock_schedule(
    lock_id: int,
    request: Request,
    user: str = Depends(require_csrf),
):
    """Clear an app-owned native override and resume the Access schedule."""
    limited = await _enforce_action_rate_limit(request, user, "lock_action")
    if limited:
        return limited
    return await _lock_action(lock_id, "restore_schedule", user, request)


async def _lock_action(lock_id: int, action: str, user: str, request):
    """Execute a dashboard action through the shared command service."""
    result = await execute_lock_action(
        request.app.state,
        lock_id,
        action,
        actor=user,
        source="manual",
    )
    if result.outcome == "not_found":
        return _redirect(request, "/locks")
    if result.outcome == "accepted_unconfirmed":
        return _redirect(
            request,
            f"/locks?notice={quote_plus(result.reason or 'Command accepted; state unconfirmed')}",
        )
    if not result.granted:
        return _redirect(
            request,
            f"/locks?error={quote_plus(result.reason or 'Lock action failed')}",
        )
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
    panel = await _get_alarm_panel(db, panel_id)
    ok = False
    reason = "Alarm panel not found"
    if panel:
        try:
            async with _physical_barrier(request):
                ha = request.app.state.ha_client
                if ha is None:
                    reason = "HA client unavailable"
                else:
                    code = _decrypt_panel_code(request, panel)
                    ok = await ha.alarm_arm_away(
                        panel["entity_id"], code=code
                    )
                    reason = "success" if ok else "HA returned failure"
        except Exception as exc:
            reason = f"command raised: {type(exc).__name__}"
            logger.exception("Alarm arm-away raised for %s", panel["entity_id"])
    if not ok:
        logger.error("Alarm arm-away failed for %s: %s", panel_id, reason)
    await db.log_admin_action(
        user,
        "alarm_arm_away",
        panel["entity_id"] if panel else str(panel_id),
        reason,
    )
    return _redirect(request, "/")


@router.post("/alarm/{panel_id}/arm-home")
async def alarm_arm_home(panel_id: int, request: Request, user: str = Depends(require_csrf)):
    limited = await _enforce_action_rate_limit(request, user, "alarm_action")
    if limited:
        return limited
    db = request.app.state.db
    panel = await _get_alarm_panel(db, panel_id)
    ok = False
    reason = "Alarm panel not found"
    if panel:
        try:
            async with _physical_barrier(request):
                ha = request.app.state.ha_client
                if ha is None:
                    reason = "HA client unavailable"
                else:
                    code = _decrypt_panel_code(request, panel)
                    ok = await ha.alarm_arm_home(
                        panel["entity_id"], code=code
                    )
                    reason = "success" if ok else "HA returned failure"
        except Exception as exc:
            reason = f"command raised: {type(exc).__name__}"
            logger.exception("Alarm arm-home raised for %s", panel["entity_id"])
    if not ok:
        logger.error("Alarm arm-home failed for %s: %s", panel_id, reason)
    await db.log_admin_action(
        user,
        "alarm_arm_home",
        panel["entity_id"] if panel else str(panel_id),
        reason,
    )
    return _redirect(request, "/")


@router.post("/alarm/{panel_id}/disarm")
async def alarm_disarm(panel_id: int, request: Request, user: str = Depends(require_csrf)):
    limited = await _enforce_action_rate_limit(request, user, "alarm_action")
    if limited:
        return limited
    db = request.app.state.db
    panel = await _get_alarm_panel(db, panel_id)
    ok = False
    reason = "Alarm panel not found"
    if panel:
        try:
            async with _physical_barrier(request):
                ha = request.app.state.ha_client
                if ha is None:
                    reason = "HA client unavailable"
                else:
                    code = _decrypt_panel_code(request, panel)
                    ok = await ha.alarm_disarm(
                        panel["entity_id"], code=code
                    )
                    reason = "success" if ok else "HA returned failure"
        except Exception as exc:
            reason = f"command raised: {type(exc).__name__}"
            logger.exception("Alarm disarm raised for %s", panel["entity_id"])
    if not ok:
        logger.error("Alarm disarm failed for %s: %s", panel_id, reason)
    await db.log_admin_action(
        user,
        "alarm_disarm",
        panel["entity_id"] if panel else str(panel_id),
        reason,
    )
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
    if not _ALARM_ENTITY_ID_RE.fullmatch(entity_id):
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
    schedule_enabled = bool(form.get("schedule_enabled"))
    schedule_error = _schedule_validation_error(
        enabled=schedule_enabled,
        days=days,
        start=schedule_start,
        end=schedule_end,
    )
    if schedule_error:
        return _redirect(request, f"/groups?error={quote_plus(schedule_error)}")
    try:
        await db.create_group(
            name=name,
            description=form.get("description", ""),
            all_locks=bool(form.get("all_locks")),
            blocked_when_armed_away=bool(form.get("blocked_when_armed_away")),
            blocked_when_armed_home=bool(form.get("blocked_when_armed_home")),
            can_disarm=bool(form.get("can_disarm")),
            schedule_enabled=schedule_enabled,
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
    schedule_enabled = bool(form.get("schedule_enabled"))
    schedule_error = _schedule_validation_error(
        enabled=schedule_enabled,
        days=days,
        start=schedule_start,
        end=schedule_end,
    )
    if schedule_error:
        return _redirect(
            request,
            f"/groups/{group_id}?error={quote_plus(schedule_error)}",
        )
    try:
        await db.update_group(
            group_id,
            name=form.get("name", ""),
            description=form.get("description", ""),
            all_locks=bool(form.get("all_locks")),
            blocked_when_armed_away=bool(form.get("blocked_when_armed_away")),
            blocked_when_armed_home=bool(form.get("blocked_when_armed_home")),
            can_disarm=bool(form.get("can_disarm")),
            schedule_enabled=schedule_enabled,
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
        async def _fetch_visitor_locations():
            return access.parse_door_locations(await access.get_bootstrap())
        access_locations = await _cached_device_options(
            request, "visitors_access_locations", _VISITORS_CACHE_TTL, _fetch_visitor_locations
        ) or []

    error = request.query_params.get("error")
    site_tz = _site_timezone(request)
    return await _render("visitors.html", request, {
        "request": request, "user": user, "page": "visitors",
        "visitors": visitors, "access_locations": access_locations,
        "error": error, "site_timezone": _timezone_label(site_tz),
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
    data_lock = getattr(request.app.state, "access_data_lock", None)
    if data_lock is None:
        return await _add_visitor_impl(
            request, user, first_name, last_name, location_id,
            start_date, start_time, end_date, end_time, pin_code, notes,
        )
    async with data_lock:
        return await _add_visitor_impl(
            request, user, first_name, last_name, location_id,
            start_date, start_time, end_date, end_time, pin_code, notes,
        )


async def _add_visitor_impl(
    request: Request,
    user: str,
    first_name: str,
    last_name: str,
    location_id: str,
    start_date: str,
    start_time: str,
    end_date: str,
    end_time: str,
    pin_code: str,
    notes: str,
):
    """Create a visitor in UniFi and store locally."""
    limited = await _enforce_action_rate_limit(request, user, "visitor_action")
    if limited:
        return limited
    # Validate PIN if provided
    if pin_code and not re.match(r'^[0-9]{4,8}$', pin_code):
        return _redirect(request, "/visitors?error=Invalid+PIN+format")

    db = request.app.state.db
    access = request.app.state.access_client
    enc_key = getattr(request.app.state, "enc_key", None)
    if not access:
        return _redirect(request, "/visitors?error=Access+client+not+available")

    local_tz = _site_timezone(request)
    # Parse in the same HA-configured zone used by group/rule schedules.
    # Strict round-trip validation rejects DST gaps and ambiguous folds.
    try:
        start_dt = _parse_site_datetime(start_date, start_time, local_tz)
        end_dt = _parse_site_datetime(end_date, end_time, local_tz)
    except ValueError as exc:
        return _redirect(
            request, f"/visitors?error={quote_plus(str(exc))}"
        )

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
    data_lock = getattr(request.app.state, "access_data_lock", None)
    if data_lock is None:
        async with _visitor_operation_lock(request, visitor_id):
            return await _extend_visitor_impl(
                visitor_id, request, user, end_date, end_time
            )
    async with data_lock:
        async with _visitor_operation_lock(request, visitor_id):
            return await _extend_visitor_impl(
                visitor_id, request, user, end_date, end_time
            )


async def _extend_visitor_impl(
    visitor_id: int,
    request: Request,
    user: str,
    end_date: str,
    end_time: str,
):
    db = request.app.state.db
    access = request.app.state.access_client
    visitor = await db.get_visitor(visitor_id)
    if not visitor:
        return _redirect(request, "/visitors")
    if int(visitor.get("status") or 0) != 1:
        return _redirect(
            request,
            "/visitors?error=Only+active+visitors+can+be+extended",
        )
    if not access:
        return _redirect(request, "/visitors?error=Access+client+not+available")

    local_tz = _site_timezone(request)
    try:
        end_dt = _parse_site_datetime(end_date, end_time, local_tz)
        stored_start = datetime.fromisoformat(visitor["start_time"])
        if stored_start.tzinfo is None:
            stored_start = stored_start.replace(tzinfo=local_tz)
        else:
            stored_start = stored_start.astimezone(local_tz)
        stored_end = datetime.fromisoformat(visitor["end_time"])
        if stored_end.tzinfo is None:
            stored_end = stored_end.replace(tzinfo=local_tz)
        else:
            stored_end = stored_end.astimezone(local_tz)
    except (TypeError, ValueError) as exc:
        return _redirect(
            request, f"/visitors?error={quote_plus(str(exc))}"
        )
    if end_dt <= datetime.now(local_tz) or end_dt <= stored_start:
        return _redirect(
            request,
            "/visitors?error=End+time+must+be+after+the+visitor+start",
        )
    if stored_end <= datetime.now(local_tz):
        return _redirect(
            request,
            "/visitors?error=Expired+visitors+cannot+be+extended",
        )
    end_unix = int(end_dt.timestamp())

    try:
        await access.update_visitor(visitor["unvr_visitor_id"], end_time=end_unix)
    except Exception:
        logger.exception("Failed to extend visitor %s in UniFi", visitor["name"])
        return _redirect(request, "/visitors?error=Failed+to+extend+visitor+in+UniFi")
    try:
        updated = await db.update_active_visitor_end_time(
            visitor_id,
            end_dt.isoformat(),
            expected_end_time=visitor["end_time"],
        )
        if not updated:
            raise RuntimeError("visitor expired while extension was in flight")
    except Exception:
        # UniFi was already extended. Restore the previous end time so a
        # concurrent local expiry (or SQLite failure) cannot leave active
        # access invisible in the dashboard.
        logger.exception(
            "Local visitor extension failed; restoring UniFi end time for %s",
            visitor["name"],
        )
        try:
            old_end = datetime.fromisoformat(visitor["end_time"])
            if old_end.tzinfo is None:
                old_end = old_end.replace(tzinfo=local_tz)
            await access.update_visitor(
                visitor["unvr_visitor_id"], end_time=int(old_end.timestamp())
            )
        except Exception:
            logger.critical(
                "Failed to compensate UniFi visitor extension for %s; "
                "reconcile this visitor manually",
                visitor["name"],
                exc_info=True,
            )
        return _redirect(
            request,
            "/visitors?error=Visitor+changed+while+being+extended;+please+refresh",
        )
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
    data_lock = getattr(request.app.state, "access_data_lock", None)
    if data_lock is None:
        async with _visitor_operation_lock(request, visitor_id):
            return await _delete_visitor_impl(visitor_id, request, user)
    async with data_lock:
        async with _visitor_operation_lock(request, visitor_id):
            return await _delete_visitor_impl(visitor_id, request, user)


async def _delete_visitor_impl(
    visitor_id: int, request: Request, user: str
):
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

    data_lock = getattr(request.app.state, "access_data_lock", None)
    if data_lock is None:
        return await _set_user_pin_impl(user_id, request, user, pin_code)
    async with data_lock:
        return await _set_user_pin_impl(user_id, request, user, pin_code)


async def _set_user_pin_impl(
    user_id: int, request: Request, user: str, pin_code: str
):

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
    access_api_token_configured = bool(
        os.environ.get("ACCESS_CONTROL_ACCESS_API_TOKEN")
        or await db.get_config("access_api_token")
    )
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
            # Same full-/api/states download as the locks page — cache
            # the filtered list rather than re-downloading per render.
            ha_alarms = await db.get_ui_cache("settings_ha_alarm_entities")
            if ha_alarms is None:
                ha_alarms = await ha.get_alarm_entities()
                await db.set_ui_cache(
                    "settings_ha_alarm_entities", ha_alarms, _LOCKS_CACHE_TTL
                )
            existing_eids = {p["entity_id"] for p in alarm_panels}
            ha_alarms = [a for a in ha_alarms if a["entity_id"] not in existing_eids]
        except Exception as exc:
            # HA may have temporarily dropped or returned an unexpected
            # shape — Settings page renders with an empty alarm dropdown.
            # Log for diagnostics. (ha_alarms may be None here if the
            # cache missed and the fetch raised.)
            logger.warning("Settings: could not fetch HA alarm entities: %s", exc)
            ha_alarms = []

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
        "access_api_token_configured": access_api_token_configured,
        "ha_url": ha_url,
        "alarm_panels": alarm_panels,
        "ha_alarms": ha_alarms,
        "admin_log": admin_log,
        "reboot_enabled": reboot_enabled,
        "reboot_day": reboot_day,
        "reboot_hour": reboot_hour,
        "restart_available": bool(
            os.environ.get("SUPERVISOR_TOKEN")
            or os.environ.get("RESTART_COMMAND")
        ),
        "restart_error": getattr(
            request.app.state, "restart_request_error", None
        ),
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
    lock = getattr(request.app.state, "settings_update_lock", None)
    if lock is None:
        return await _update_unvr_impl(
            request, unvr_host, unvr_username, unvr_password, user
        )
    async with lock:
        protect_lock = getattr(request.app.state, "protect_start_lock", None)
        access_lock = getattr(request.app.state, "access_start_lock", None)
        data_lock = getattr(request.app.state, "access_data_lock", None)
        if (
            protect_lock is not None
            and access_lock is not None
            and data_lock is not None
        ):
            async with protect_lock, access_lock, data_lock:
                return await _update_unvr_impl(
                    request, unvr_host, unvr_username, unvr_password, user
                )
        return await _update_unvr_impl(
            request, unvr_host, unvr_username, unvr_password, user
        )


async def _update_unvr_impl(
    request: Request,
    unvr_host: str,
    unvr_username: str,
    unvr_password: str,
    user: str,
):
    limited = await _enforce_action_rate_limit(request, user, "settings_admin")
    if limited:
        return limited
    db = request.app.state.db
    enc_key = getattr(request.app.state, "enc_key", None)

    # Build replacement clients before touching persisted or live state. The
    # primary console always supplies Protect; it supplies Access only when no
    # separate Access console is configured.
    separate_access = all(
        (
            await db.get_config("access_host"),
            await db.get_config("access_username"),
            await db.get_config("access_password"),
        )
    )
    candidate_protect = ProtectClient(unvr_host, unvr_username, unvr_password)
    candidate_access = None
    expected_identity = await db.get_config("access_console_identity")
    try:
        await candidate_protect.login()
        if not separate_access:
            candidate_access = AccessClient(
                unvr_host,
                unvr_username,
                unvr_password,
                expected_identity=expected_identity,
                api_token=getattr(
                    request.app.state, "access_api_token", None
                ),
            )
            await candidate_access.login()
            if getattr(candidate_access, "open_api_configured", False):
                await candidate_access.validate_open_api()
    except Exception as exc:
        logger.warning("UNVR connection test failed during settings update: %s", exc)
        await candidate_protect.close()
        if candidate_access is not None:
            await candidate_access.close()
        return await _settings_with_result(
            request,
            user,
            db,
            enc_key,
            "UNVR connection failed. Check host, Protect service, and credentials.",
        )

    if candidate_access is not None:
        observed_identity = await _get_access_identity(candidate_access)
        if (
            expected_identity
            and expected_identity != observed_identity
        ):
            await candidate_protect.close()
            await candidate_access.close()
            return await _settings_with_result(
                request,
                user,
                db,
                enc_key,
                "The Access site identity changed. In-place "
                "site replacement is blocked to protect existing grants.",
            )
        current_access_creds = getattr(
            request.app.state, "access_creds", None
        )
        if (
            current_access_creds
            and not _same_console_endpoint(
                current_access_creds[0], unvr_host
            )
            and (
                not expected_identity
                or not observed_identity
                or expected_identity != observed_identity
            )
        ):
            await candidate_protect.close()
            await candidate_access.close()
            return await _settings_with_result(
                request,
                user,
                db,
                enc_key,
                "A host change requires the same verified Access site "
                "identity. Reinitialize for a different site.",
            )

    try:
        unvr_values = {
                "unvr_host": unvr_host,
                "unvr_username": encrypt_value(unvr_username, enc_key),
                "unvr_password": encrypt_value(unvr_password, enc_key),
        }
        if candidate_access is not None and observed_identity:
            unvr_values["access_console_identity"] = observed_identity
        await db.set_configs(unvr_values)
    except Exception:
        await candidate_protect.close()
        if candidate_access is not None:
            await candidate_access.close()
        raise

    old_protect = request.app.state.protect_client
    old_access = (
        request.app.state.access_client
        if candidate_access is not None
        else None
    )
    # Critical post-event safety work may itself need the physical barrier.
    # Stop intake and drain it before acquiring publication ownership.
    await _quiesce_event_sources(request, old_protect, old_access)

    async with _physical_barrier(request):

        if candidate_access is not None:
            # Both new WebSockets must remain fail-closed until the matching
            # Access snapshot commits. Set this before starting Protect: a
            # fast credential event from that source otherwise sees the old
            # camera map while publication is still in progress.
            request.app.state.event_topology_ready = False

        request.app.state.protect_client = candidate_protect
        request.app.state.unvr_creds = (
            unvr_host,
            unvr_username,
            unvr_password,
        )
        on_protect_event = getattr(request.app.state, "on_protect_event", None)
        if on_protect_event:
            candidate_protect.register_callback(on_protect_event)
        await candidate_protect.start_websocket()

        # In split-console mode the Access client and credentials are
        # deliberately untouched. Unified mode publishes before WS intake.
        if candidate_access is not None:
            request.app.state.access_generation = (
                getattr(request.app.state, "access_generation", 0) + 1
            )
            request.app.state.access_client = candidate_access
            request.app.state.access_started_client = candidate_access
            request.app.state.access_creds = (
                unvr_host,
                unvr_username,
                unvr_password,
            )
            request.app.state.access_open_api_ready = bool(
                getattr(request.app.state, "access_api_token", None)
            )
            request.app.state.access_open_api_error = None
            request.app.state.access_console_identity = observed_identity
            if request.app.state.auth_engine:
                request.app.state.auth_engine._access_client = candidate_access
            on_access_event = getattr(request.app.state, "on_access_event", None)
            if on_access_event:
                candidate_access.register_callback(on_access_event)
            await candidate_access.start_websocket()

        if old_protect and old_protect is not candidate_protect:
            await old_protect.close()
        if old_access and old_access is not candidate_access:
            await old_access.close()

    # Refresh topology against whichever Access console is active.
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
    lock = getattr(request.app.state, "settings_update_lock", None)
    if lock is None:
        return await _update_ha_impl(request, ha_url, ha_token, user)
    async with lock:
        return await _update_ha_impl(request, ha_url, ha_token, user)


async def _update_ha_impl(
    request: Request, ha_url: str, ha_token: str, user: str
):
    limited = await _enforce_action_rate_limit(request, user, "settings_admin")
    if limited:
        return limited
    db = request.app.state.db
    enc_key = getattr(request.app.state, "enc_key", None)

    if _supervisor_proxy_active():
        logger.warning(
            "Rejected HA credential update while Supervisor proxy is active"
        )
        return await _settings_with_result(
            request,
            user,
            db,
            enc_key,
            "Home Assistant credentials are managed by Supervisor in this mode.",
        )

    # Test once, then promote this exact connected client. The former path
    # closed the tested client, disconnected the known-good live client, and
    # performed a second unguarded connection that could fail mid-swap.
    test_client = HAClient(ha_url, ha_token)
    new_timezone = None
    try:
        ok = await test_client.test_connection()
        if not ok:
            await test_client.close()
            return await _settings_with_result(request, user, db, enc_key, "HA connection failed. Check URL and token.")
        new_timezone = await test_client.get_timezone()
    except Exception as exc:
        # Sanitize: don't surface raw aiohttp / SSL / token-validation
        # exception strings to the dashboard. Audit 2026-05-24, H1.
        logger.warning("HA connection test failed during settings update: %s", exc)
        await test_client.close()
        return await _settings_with_result(request, user, db, enc_key, "HA connection failed. Check URL and token.")

    try:
        await db.set_configs(
            {
                "ha_url": ha_url,
                "ha_token": encrypt_value(ha_token, enc_key),
            }
        )
    except Exception:
        await test_client.close()
        raise

    # Atomically publish the already-tested client before retiring the old one.
    async with _physical_barrier(request):
        old_client = request.app.state.ha_client
        request.app.state.ha_client = test_client
        if request.app.state.auth_engine:
            request.app.state.auth_engine._ha_client = test_client
            if new_timezone:
                request.app.state.auth_engine.set_timezone(new_timezone)
    if old_client and old_client is not test_client:
        # The old client may still own an accepted write's exact-state
        # confirmation lease. Publication is already atomic; drain/close the
        # retired client outside the global write barrier so an unrelated door
        # can begin using the new client while that readback finishes.
        await old_client.close()

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
    lock = getattr(request.app.state, "settings_update_lock", None)
    if lock is None:
        return await _update_access_console_impl(
            request,
            user,
            access_host,
            access_username,
            access_password,
            clear,
        )
    async with lock:
        start_lock = getattr(request.app.state, "access_start_lock", None)
        data_lock = getattr(request.app.state, "access_data_lock", None)
        if start_lock is not None and data_lock is not None:
            async with start_lock, data_lock:
                return await _update_access_console_impl(
                    request,
                    user,
                    access_host,
                    access_username,
                    access_password,
                    clear,
                )
        return await _update_access_console_impl(
            request,
            user,
            access_host,
            access_username,
            access_password,
            clear,
        )


async def _update_access_console_impl(
    request: Request,
    user: str,
    access_host: str,
    access_username: str,
    access_password: str,
    clear: str,
):
    limited = await _enforce_action_rate_limit(request, user, "settings_admin")
    if limited:
        return limited
    db = request.app.state.db
    enc_key = getattr(request.app.state, "enc_key", None)

    if clear:
        primary_creds = getattr(request.app.state, "unvr_creds", None)
        if not primary_creds:
            return await _settings_with_result(
                request,
                user,
                db,
                enc_key,
                "Primary-console credentials are unavailable; restart and try again.",
            )
        target_host, target_username, target_password = primary_creds
        action = "settings_access_console_clear"
        success_message = "Access console cleared — now using primary console."
    else:
        if not access_host or not access_username or not access_password:
            return await _settings_with_result(
                request,
                user,
                db,
                enc_key,
                "All fields required for separate Access console.",
            )
        target_host, target_username, target_password = (
            access_host,
            access_username,
            access_password,
        )
        action = "settings_access_console_update"
        success_message = f"Access console configured at {access_host}."

    # Authenticate a candidate without attaching production event callbacks.
    test_client = AccessClient(
        host=target_host,
        username=target_username,
        password=target_password,
        expected_identity=await db.get_config("access_console_identity"),
        api_token=getattr(request.app.state, "access_api_token", None),
    )
    try:
        await test_client.login()
        if getattr(test_client, "open_api_configured", False):
            await test_client.validate_open_api()
    except Exception as exc:
        # Sanitize: don't surface raw upstream errors. Audit 2026-05-24, H1.
        logger.warning("Access console connection test failed during settings update: %s", exc)
        await test_client.close()
        return await _settings_with_result(
            request, user, db, enc_key,
            "Access console connection failed. Check host and credentials.",
        )

    expected_identity = await db.get_config("access_console_identity")
    observed_identity = await _get_access_identity(test_client)
    if (
        expected_identity
        and expected_identity != observed_identity
    ):
        await test_client.close()
        return await _settings_with_result(
            request,
            user,
            db,
            enc_key,
            "The Access site identity changed. In-place site "
            "replacement is blocked to protect existing grants.",
        )
    current_access_creds = getattr(request.app.state, "access_creds", None)
    if (
        current_access_creds
        and not _same_console_endpoint(
            current_access_creds[0], target_host
        )
        and (
            not expected_identity
            or not observed_identity
            or expected_identity != observed_identity
        )
    ):
        await test_client.close()
        return await _settings_with_result(
            request,
            user,
            db,
            enc_key,
            "A host change requires the same verified Access site identity. "
            "Reinitialize for a different site.",
        )

    try:
        if clear:
            access_values = {
                "access_host": "",
                "access_username": "",
                "access_password": "",
            }
        else:
            access_values = {
                "access_host": access_host,
                "access_username": encrypt_value(access_username, enc_key),
                "access_password": encrypt_value(access_password, enc_key),
            }
        if observed_identity:
            access_values["access_console_identity"] = observed_identity
        await db.set_configs(access_values)
    except Exception:
        await test_client.close()
        raise

    old_client = request.app.state.access_client
    await _quiesce_event_sources(request, old_client)
    async with _physical_barrier(request):
        request.app.state.event_topology_ready = False
        request.app.state.access_generation = (
            getattr(request.app.state, "access_generation", 0) + 1
        )
        request.app.state.access_client = test_client
        request.app.state.access_started_client = test_client
        request.app.state.access_creds = (
            target_host,
            target_username,
            target_password,
        )
        request.app.state.access_open_api_ready = bool(
            getattr(request.app.state, "access_api_token", None)
        )
        request.app.state.access_open_api_error = None
        request.app.state.access_console_identity = observed_identity
        if request.app.state.auth_engine:
            request.app.state.auth_engine._access_client = test_client
        on_access_event = getattr(request.app.state, "on_access_event", None)
        if on_access_event:
            test_client.register_callback(on_access_event)
        await test_client.start_websocket()
        if old_client and old_client is not test_client:
            await old_client.close()

    sync = getattr(request.app.state, "sync_users", None)
    if sync is not None:
        try:
            await sync()
        except Exception:
            logger.exception("Topology refresh after Access console update failed")

    await db.log_admin_action(user, action, target_host)
    return await _settings_with_result(
        request, user, db, enc_key,
        success_message,
        success=True,
    )


@router.post("/settings/access-api-token", response_class=HTMLResponse)
async def update_access_api_token(
    request: Request,
    user: str = Depends(require_csrf),
    access_api_token: str = Form(default=""),
    clear: str = Form(default=""),
):
    """Validate, persist, and hot-swap the official Access API token."""
    settings_lock = getattr(request.app.state, "settings_update_lock", None)
    if settings_lock is None:
        return await _update_access_api_token_impl(
            request, user, access_api_token, clear
        )
    async with settings_lock:
        start_lock = getattr(request.app.state, "access_start_lock", None)
        data_lock = getattr(request.app.state, "access_data_lock", None)
        if start_lock is not None and data_lock is not None:
            async with start_lock, data_lock:
                return await _update_access_api_token_impl(
                    request, user, access_api_token, clear
                )
        return await _update_access_api_token_impl(
            request, user, access_api_token, clear
        )


async def _update_access_api_token_impl(
    request: Request,
    user: str,
    access_api_token: str,
    clear: str,
):
    limited = await _enforce_action_rate_limit(
        request, user, "settings_admin"
    )
    if limited:
        return limited

    db = request.app.state.db
    enc_key = getattr(request.app.state, "enc_key", None)
    if os.environ.get("ACCESS_CONTROL_ACCESS_API_TOKEN"):
        return await _settings_with_result(
            request,
            user,
            db,
            enc_key,
            "The Access API token is controlled by "
            "ACCESS_CONTROL_ACCESS_API_TOKEN; update or remove that environment "
            "override and restart the service.",
        )

    token = None if clear else access_api_token.strip()
    if not clear and not token:
        return await _settings_with_result(
            request,
            user,
            db,
            enc_key,
            "Enter an Access API token or choose Clear Token.",
        )

    creds = getattr(request.app.state, "access_creds", None)
    if not creds:
        return await _settings_with_result(
            request,
            user,
            db,
            enc_key,
            "Access console credentials are unavailable; restart and try again.",
        )

    candidate = AccessClient(
        *creds,
        expected_identity=await db.get_config("access_console_identity"),
        api_token=token,
    )
    try:
        await candidate.login()
        observed_identity = await _get_access_identity(candidate)
        expected_identity = await db.get_config("access_console_identity")
        if expected_identity and observed_identity != expected_identity:
            raise AccessClientError(
                "Access site identity changed during token validation"
            )
        if token:
            await candidate.validate_open_api()
    except Exception as exc:
        logger.warning(
            "Access API token validation failed: %s", type(exc).__name__
        )
        await candidate.close()
        return await _settings_with_result(
            request,
            user,
            db,
            enc_key,
            "Access API token validation failed. Verify port 12445 is reachable "
            "and the token has view:space permission.",
        )

    try:
        await db.set_config(
            "access_api_token",
            encrypt_value(token, enc_key) if token else "",
        )
    except Exception:
        await candidate.close()
        raise

    old_client = request.app.state.access_client
    await _quiesce_event_sources(request, old_client)
    async with _physical_barrier(request):
        request.app.state.event_topology_ready = False
        request.app.state.access_generation = (
            getattr(request.app.state, "access_generation", 0) + 1
        )
        request.app.state.access_client = candidate
        request.app.state.access_started_client = candidate
        request.app.state.access_api_token = token
        request.app.state.access_open_api_ready = bool(token)
        request.app.state.access_open_api_error = None
        request.app.state.access_console_identity = observed_identity
        if request.app.state.auth_engine:
            request.app.state.auth_engine._access_client = candidate
        on_access_event = getattr(request.app.state, "on_access_event", None)
        if on_access_event:
            candidate.register_callback(on_access_event)
        await candidate.start_websocket()
        if old_client and old_client is not candidate:
            await old_client.close()

    sync = getattr(request.app.state, "sync_users", None)
    if sync is not None:
        try:
            await sync()
        except Exception:
            logger.exception("Topology refresh after Access API token update failed")

    await db.log_admin_action(
        user,
        "settings_access_api_token_clear"
        if clear
        else "settings_access_api_token_update",
    )
    return await _settings_with_result(
        request,
        user,
        db,
        enc_key,
        "Access API token cleared; compatibility mode is active."
        if clear
        else "Access API token validated and activated.",
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
    name = name.strip()
    if not name or len(name) > 100:
        return await _settings_with_result(
            request,
            user,
            db,
            enc_key,
            "API key name must be between 1 and 100 characters.",
        )
    if scope not in _API_KEY_SCOPES:
        logger.warning("Rejected unsupported API key scope %r", scope)
        return await _settings_with_result(
            request,
            user,
            db,
            enc_key,
            "Invalid API key scope.",
        )
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
    data_lock = getattr(request.app.state, "access_data_lock", None)
    if data_lock is None:
        return await _add_user_impl(request, user, first_name, last_name)
    async with data_lock:
        return await _add_user_impl(request, user, first_name, last_name)


async def _add_user_impl(
    request: Request, user: str, first_name: str, last_name: str
):
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
    """Request a Supervisor (or explicitly configured host) restart."""
    limited = await _enforce_action_rate_limit(request, user, "service_action")
    if limited:
        return limited
    logger.info("Service restart requested by %s", user)
    request.app.state.restart_request_error = None
    db = request.app.state.db
    await db.log_admin_action(user, "service_restart")
    if not os.environ.get("SUPERVISOR_TOKEN") and not os.environ.get(
        "RESTART_COMMAND"
    ):
        raise HTTPException(status_code=503, detail="Service restart is unavailable")

    async def _do_restart():
        try:
            await request_service_restart(delay=1.5)
        except Exception:
            logger.exception("Service restart request failed")
            request.app.state.restart_request_error = (
                "The restart request failed. Check the application log and "
                "restart the service from its host/Supervisor UI."
            )

    task = asyncio.create_task(_do_restart(), name="service-restart")
    tracker = getattr(request.app.state, "track_background_task", None)
    if callable(tracker):
        tracker(task)
    else:
        task.add_done_callback(
            lambda done: done.exception() if not done.cancelled() else None
        )
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
    if enabled == "1" and not (
        os.environ.get("SUPERVISOR_TOKEN") or os.environ.get("RESTART_COMMAND")
    ):
        raise HTTPException(
            status_code=503, detail="Scheduled restart is unavailable"
        )
    day = reboot_day if reboot_day in ("daily", "0", "1", "2", "3", "4", "5", "6") else "daily"
    hour = max(0, min(23, int(reboot_hour)))

    await db.set_configs(
        {
            "reboot_enabled": enabled,
            "reboot_day": day,
            "reboot_hour": str(hour),
        }
    )
    await db.log_admin_action(
        user, "reboot_schedule_update",
        target=f"enabled={enabled} day={day} hour={hour}",
    )
    return _redirect(request, "/settings")
