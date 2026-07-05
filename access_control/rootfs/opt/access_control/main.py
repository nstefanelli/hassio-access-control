"""FastAPI entry point for the Access Control App."""
from __future__ import annotations

import asyncio
import logging
import os
import sys
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

# Ensure app-level loggers propagate to stdout (uvicorn suppresses by default)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    stream=sys.stdout,
)

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from .access_client import AccessClient
from .api_routes import router as api_router
from .auth_engine import AuthEngine
from .config import decrypt_value, derive_key
from .database import Database
from .ha_creds import resolve_ha_creds as _resolve_ha_creds
from .protect_client import ProtectClient
from .ha_client import HAClient
from .relock_manager import RelockManager
from .web_routes import router as web_router
from . import web_auth

logger = logging.getLogger(__name__)

_HERE = Path(__file__).parent

# `_resolve_ha_creds` lives in `ha_creds.py` so the env-vs-DB precedence
# logic can be unit-tested without dragging FastAPI (and main.py's whole
# import surface) into the test process. Re-exported here under the same
# name so the call site below reads naturally.


def _log_task_exception(task: asyncio.Task) -> None:
    """Callback for fire-and-forget tasks — log any unhandled exceptions."""
    if task.cancelled():
        return
    exc = task.exception()
    if exc:
        logger.error("Unhandled exception in task %r: %s", task.get_name(), exc, exc_info=exc)


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown logic wired via the lifespan context manager."""

    # --- Startup ---

    db = Database()
    await db.connect()
    app.state.db = db

    # Determine whether the app is configured
    admin_username = await db.get_config("admin_username")
    configured = bool(admin_username)
    app.state.configured = configured

    # Initialise remaining state as None — populated below if configured
    app.state.access_client = None
    app.state.ha_client = None
    app.state.protect_client = None
    app.state.auth_engine = None
    app.state.ws_last_event = {"access": None, "protect": None}
    app.state.lock_states = {}
    app.state.relock_tasks = {}
    app.state.relock_manager: RelockManager | None = None
    app.state.camera_to_location = {}
    app.state.sync_users = None
    app.state.on_access_event = None
    app.state.on_protect_event = None
    app.state.initialize_configured_state = None
    # HA health flag — None until initialize_configured_state() runs; then
    # True/False from the boot-time test_connection(). Supervisor loops and
    # /api/health may read this to surface a degraded state.
    app.state.ha_unhealthy = None
    # Stash creds + ws restart helpers so the supervisor loops can use them after
    # initial bring-up failures or platform reboots.
    app.state.unvr_creds = None  # (host, user, pass)
    app.state.start_protect_client = None
    app.state.seed_lock_states = None

    # Track recently processed events to deduplicate between Protect fast-path and Access WS
    _recent_events: dict[str, float] = {}

    def _is_duplicate(ulp_id: str, location_id: str, event_id: str = "") -> bool:
        """
        Check if this access event was already processed in the last 10s.

        Tracks two keys so that the *cross-path* duplicate (Protect fast-path
        + Access standard-path firing for the same physical tap) is caught
        even though only the Access path carries an event_id:

        - ``ulp_id:location_id`` — set on every event; matches across paths
        - ``event_id`` — set only when the Access log payload carries it;
          protects against the same Access log being delivered twice
        """
        now = time.time()
        # Prune entries older than 10 seconds
        for k in list(_recent_events):
            if now - _recent_events[k] > 10:
                del _recent_events[k]

        key_loc = f"{ulp_id}:{location_id}"
        if key_loc in _recent_events:
            return True
        if event_id and event_id in _recent_events:
            return True

        _recent_events[key_loc] = now
        if event_id:
            _recent_events[event_id] = now
        return False

    async def sync_users() -> None:
        """Fetch users, native locks, and camera map from the current Access client."""
        access_client = app.state.access_client
        if not access_client:
            logger.warning("sync_users() skipped — Access client not initialized")
            return

        logger.info("Starting user/lock sync…")
        try:
            users = await access_client.fetch_users()
            active_ulp_ids: list[str] = []
            for u in users:
                ulp_id = u.get("ulp_id", "")
                if not ulp_id:
                    continue
                await db.upsert_user(
                    ulp_id=ulp_id,
                    name=u.get("name", ""),
                    email=u.get("email") or None,
                    status=u.get("status", "active"),
                )
                active_ulp_ids.append(ulp_id)
            await db.mark_deleted_users(active_ulp_ids)
            logger.info("Synced %d users", len(active_ulp_ids))

            bootstrap = await access_client.get_bootstrap()
            doors = access_client.parse_doors_and_devices(bootstrap)
            hub_devices = [d for d in doors if not d.get("is_camera")]
            for door in hub_devices:
                await db.upsert_native_lock(
                    device_id=door["device_id"],
                    location_id=door["location_id"],
                    name=door["name"],
                    door_name=door.get("door_name"),
                )
            logger.info("Synced %d native lock(s)", len(hub_devices))

            new_map: dict[str, str] = {}
            raw = bootstrap if isinstance(bootstrap, list) else bootstrap.get("data", [])
            for building in raw:
                for floor in building.get("floors", []):
                    for door in floor.get("doors", []):
                        door_id = door.get("unique_id", "")
                        for dg in door.get("device_groups", []):
                            for dev in dg:
                                if dev.get("is_camera"):
                                    new_map[dev.get("unique_id", "")] = door_id
            app.state.camera_to_location = new_map
            logger.info("Camera→location map: %d entries", len(new_map))

        except Exception:
            logger.exception("sync_users() failed")

    # Semaphore to cap concurrent process_event invocations during event floods
    _event_semaphore = asyncio.Semaphore(5)

    # Register WebSocket event callback
    def on_access_event(message: dict) -> None:
        """Dispatch relevant Access events to the auth engine."""
        app.state.ws_last_event["access"] = datetime.now(timezone.utc).isoformat()
        event_type: str = message.get("event", "") or message.get("type", "")
        if not event_type:
            return

        auth_engine = app.state.auth_engine
        if not auth_engine:
            logger.warning("Received Access event before auth engine was ready")
            return

        ulp_id = ""
        location_id = ""
        method = "nfc"
        event_id = ""

        # G6 Entry Pro / newer Access devices: structured log events
        if event_type in ("access.logs.add", "access.logs.insights.add"):
            if event_type == "access.logs.insights.add":
                return
            data = message.get("data", {})
            event_id = data.get("_id", "")
            if "_source" in data:
                source = data["_source"]
                meta = {
                    "actor": source.get("actor", {}),
                    "authentication": source.get("authentication", {}),
                    "door": source.get("door", {}),
                    "event": source.get("event", {}),
                }
            else:
                meta = data.get("metadata", {})

            evt = meta.get("event", {}) if "_source" in data else data
            evt_type = evt.get("event_type", "") or evt.get("type", "")
            result = data.get("result", "") or evt.get("result", "")
            if "unlock" not in evt_type and result != "ACCESS":
                return

            actor = meta.get("actor", {})
            ulp_id = actor.get("id", "")
            door = meta.get("door", {})
            location_id = door.get("id", "")

            auth_info = meta.get("authentication", {})
            provider = auth_info.get("credential_provider", "").lower()
            if provider == "face":
                method = "face"
            elif provider == "pin_code":
                method = "pin"
            elif "nfc" in provider or "pass" in provider:
                method = "nfc"
            elif provider == "fingerprint":
                method = "fingerprint"
            elif "remote" in provider or "uah" in provider:
                method = "remote_through_uah"
            else:
                method = provider or "unknown"

            display_name = actor.get("display_name", ulp_id)
            logger.info(
                "Access event: %s for %s at %s (method=%s)",
                data.get("message", evt_type), display_name, door.get("display_name", location_id), method,
            )

        elif "remote_unlock" in event_type or "entry" in event_type:
            data = message.get("data", {})
            ulp_id = data.get("ulp_id") or data.get("user_id") or ""
            location_id = data.get("location_id") or data.get("door_id") or ""
            if "remote_unlock" in event_type:
                method = "remote_through_uah"
        else:
            return

        if not ulp_id or not location_id:
            return

        if method == "remote_through_uah":
            async def _schedule_remote_relock(loc_id: str) -> None:
                rm = app.state.relock_manager
                if rm is None:
                    return
                locks = await db.get_locks_for_location(loc_id)
                for lock in locks:
                    if not lock.get("relock_on_remote") or lock["type"] != "ha_external":
                        continue
                    eid = lock.get("entity_id")
                    if not eid:
                        continue
                    await rm.schedule(
                        entity_id=eid,
                        duration=lock.get("relock_duration", 30),
                        lock_id=lock.get("id"),
                        lock_name=lock.get("name", eid),
                        source="remote",
                    )

            task = asyncio.create_task(
                _schedule_remote_relock(location_id),
                name=f"remote-relock-{location_id}",
            )
            task.add_done_callback(_log_task_exception)
            return

        if _is_duplicate(ulp_id, location_id, event_id=event_id):
            logger.debug("Skipping duplicate Access WS event for %s (already handled by fast-path)", ulp_id)
            return

        async def _gated():
            async with _event_semaphore:
                return await auth_engine.process_event(ulp_id=ulp_id, location_id=location_id, method=method)

        task = asyncio.create_task(_gated(), name=f"process-event-{ulp_id}")
        task.add_done_callback(_log_task_exception)

    def on_protect_event(message: dict) -> None:
        """Handle ring, NFC, fingerprint, and doorAccess events from Protect."""
        app.state.ws_last_event["protect"] = datetime.now(timezone.utc).isoformat()
        event = message.get("event", "")
        camera_id = message.get("camera_id", "")
        if not camera_id:
            return

        auth_engine = app.state.auth_engine
        if not auth_engine:
            logger.warning("Received Protect event before auth engine was ready")
            return

        if event == "door_access":
            ulp_id = message.get("ulp_id", "")
            if not ulp_id:
                return
            location_id = app.state.camera_to_location.get(camera_id, "")
            if not location_id:
                logger.warning("doorAccess from unknown camera %s — no location mapping", camera_id)
                return
            if _is_duplicate(ulp_id, location_id):
                return
            logger.info("Fast-path doorAccess: %s at %s", message.get("display_name", ulp_id), message.get("door_name", ""))

            async def _gated_protect():
                async with _event_semaphore:
                    return await auth_engine.process_event(ulp_id=ulp_id, location_id=location_id, method="access_device")

            task = asyncio.create_task(_gated_protect(), name=f"door-access-{ulp_id}")
            task.add_done_callback(_log_task_exception)
            return

        if event == "ring":
            task = asyncio.create_task(
                _handle_doorbell_ring(db, app.state.ha_client, camera_id),
                name=f"doorbell-ring-{camera_id}",
            )
            task.add_done_callback(_log_task_exception)
        elif event in ("nfc", "fingerprint"):
            ulp_id = message.get("ulp_id", "")
            if not ulp_id:
                logger.info("Protect %s event with no ulp_id — unregistered credential", event)
                return
            task = asyncio.create_task(
                _handle_protect_access(auth_engine, camera_id, ulp_id, event),
                name=f"protect-{event}-{camera_id}",
            )
            task.add_done_callback(_log_task_exception)

    app.state.sync_users = sync_users
    app.state.on_access_event = on_access_event
    app.state.on_protect_event = on_protect_event

    async def initialize_configured_state() -> None:
        """Load configured clients/state so the app can operate immediately."""
        salt_hex = await db.get_config("encryption_salt")
        if not salt_hex:
            raise RuntimeError("Config key 'encryption_salt' is missing from the database.")
        salt = bytes.fromhex(salt_hex)

        admin_password_hash = await db.get_config("admin_password_hash")
        if not admin_password_hash:
            raise RuntimeError("Config key 'admin_password_hash' is missing from the database.")

        secret_key = await db.get_config("secret_key")
        if not secret_key:
            raise RuntimeError("Config key 'secret_key' is missing from the database.")

        if os.environ.get("ACCESS_CONTROL_SECRET_KEY"):
            secret_key = os.environ["ACCESS_CONTROL_SECRET_KEY"]

        web_auth.SECRET_KEY = secret_key
        enc_key = derive_key(secret_key, salt)
        app.state.enc_key = enc_key

        unvr_host = await db.get_config("unvr_host")
        unvr_username_enc = await db.get_config("unvr_username")
        unvr_password_enc = await db.get_config("unvr_password")
        if not all([unvr_host, unvr_username_enc, unvr_password_enc]):
            raise RuntimeError("UNVR credentials are incomplete in the database.")

        unvr_username = decrypt_value(unvr_username_enc, enc_key)
        unvr_password = decrypt_value(unvr_password_enc, enc_key)

        unvr_host = os.environ.get("ACCESS_CONTROL_UNVR_HOST") or unvr_host
        if os.environ.get("ACCESS_CONTROL_UNVR_USERNAME"):
            unvr_username = os.environ["ACCESS_CONTROL_UNVR_USERNAME"]
        if os.environ.get("ACCESS_CONTROL_UNVR_PASSWORD"):
            unvr_password = os.environ["ACCESS_CONTROL_UNVR_PASSWORD"]

        access_host_db = await db.get_config("access_host")
        access_username_enc = await db.get_config("access_username")
        access_password_enc = await db.get_config("access_password")

        if access_host_db and access_username_enc and access_password_enc:
            a_host = os.environ.get("ACCESS_CONTROL_ACCESS_HOST") or access_host_db
            a_user = os.environ.get("ACCESS_CONTROL_ACCESS_USERNAME") or decrypt_value(access_username_enc, enc_key)
            a_pass = os.environ.get("ACCESS_CONTROL_ACCESS_PASSWORD") or decrypt_value(access_password_enc, enc_key)
            logger.info("Using separate Access console at %s", a_host)
        else:
            a_host = unvr_host
            a_user = unvr_username
            a_pass = unvr_password

        # Resolve HA creds via the module-level helper — see
        # _resolve_ha_creds() above for the env-vs-DB precedence rules.
        ha_url, ha_token, creds_source = _resolve_ha_creds(
            env_url=os.environ.get("ACCESS_CONTROL_HA_URL"),
            env_token=os.environ.get("ACCESS_CONTROL_HA_TOKEN"),
            db_url=await db.get_config("ha_url"),
            db_token_enc=await db.get_config("ha_token"),
            decrypt=lambda enc: decrypt_value(enc, enc_key),
            log=logger,
        )
        logger.info("HA credentials resolved from: %s", creds_source)

        # Stash UNVR creds — the supervisor loops use these to recover
        # if Access or Protect was unreachable at boot.
        app.state.unvr_creds = (unvr_host, unvr_username, unvr_password)

        access_client = AccessClient(host=a_host, username=a_user, password=a_pass)
        try:
            await access_client.login()
            logger.info("AccessClient authenticated at %s", a_host)
        except Exception:
            logger.exception("AccessClient startup failed — proceeding without Access integration")
            access_client = None
        app.state.access_client = access_client

        ha_client = HAClient(url=ha_url, token=ha_token)
        ha_ok = await ha_client.test_connection()
        if not ha_ok:
            logger.warning(
                "HA connection test failed — proceeding anyway "
                "(creds_source=%s). app.state.ha_unhealthy is now True; "
                "health endpoints and supervisor loops should react.",
                creds_source,
            )
            app.state.ha_unhealthy = True
        else:
            logger.info("HAClient connected to %s", ha_url)
            app.state.ha_unhealthy = False
        app.state.ha_client = ha_client

        # RelockManager wraps the relock-task dict and persists pending relocks
        # to the DB. ha_client is fetched lazily via the getter so credential
        # updates from Settings transparently use the new client. The
        # on_locked callback keeps the in-memory lock_states cache fresh
        # after a relock timer fires.
        def _mark_locked(entity_id: str) -> None:
            app.state.lock_states[entity_id] = "locked"

        app.state.relock_manager = RelockManager(
            db=db,
            ha_client_getter=lambda: app.state.ha_client,
            on_locked=_mark_locked,
        )

        app.state.auth_engine = AuthEngine(
            db=db,
            access_client=access_client,
            ha_client=ha_client,
            relock_tasks=app.state.relock_tasks,
            enc_key=enc_key,
            relock_manager=app.state.relock_manager,
        )

        # Restore lockdown mode persisted before a restart (incident control
        # must survive a reboot). Fail-safe: stays disabled if unreadable.
        await app.state.auth_engine.load_persisted_lockdown()

        await sync_users()

        # Lock-state seeding — also used by the HA recovery loop when HA
        # comes back online after a reboot.
        async def seed_lock_states() -> int:
            ha = app.state.ha_client
            if ha is None or not ha.connected:
                return 0
            all_locks = await db.get_all_locks()
            ha_locks = [
                lock for lock in all_locks
                if lock["type"] == "ha_external" and lock.get("entity_id")
            ]
            if not ha_locks:
                return 0
            results = await asyncio.gather(
                *(ha.get_entity_state(lock["entity_id"]) for lock in ha_locks),
                return_exceptions=True,
            )
            fresh: dict[str, str] = {}
            for lock, state in zip(ha_locks, results):
                if isinstance(state, str) and state:
                    fresh[lock["entity_id"]] = state
            app.state.lock_states = fresh
            return len(fresh)

        app.state.seed_lock_states = seed_lock_states
        app.state.lock_states = {}
        await seed_lock_states()

        # Rehydrate any pending relocks the previous run left in the DB.
        try:
            await app.state.relock_manager.rehydrate()
        except Exception:
            logger.exception("Failed to rehydrate pending relocks")

        if access_client is not None:
            access_client.register_callback(on_access_event)
            await access_client.start_websocket()
            logger.info("Access WebSocket listener started")

        # Protect cold-start is wrapped so the supervisor loop can keep
        # retrying if UNVR Protect was warming up at boot. If login fails
        # here, app.state.protect_client stays None and the supervisor
        # picks up the next attempt.
        async def start_protect_client() -> bool:
            creds = app.state.unvr_creds
            if not creds:
                return False
            host, user, pwd = creds
            try:
                protect_client = ProtectClient(host, user, pwd)
                await protect_client.login()
                protect_client.register_callback(on_protect_event)
                await protect_client.start_websocket()
            except Exception:
                logger.exception("Protect client bring-up failed")
                return False
            app.state.protect_client = protect_client
            logger.info("Protect WebSocket listener started")
            return True

        app.state.start_protect_client = start_protect_client
        await start_protect_client()

    app.state.initialize_configured_state = initialize_configured_state

    if not configured:
        logger.warning(
            "No admin_username found in config — running in setup mode. "
            "Only /setup is accessible."
        )
    else:
        await initialize_configured_state()

    async def _supervised(coro_factory, *, name: str, restart_delay: float = 15.0) -> None:
        """Restart coro_factory if it exits or crashes unexpectedly."""
        while True:
            try:
                await coro_factory()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Background task %r crashed — restarting in %ds", name, restart_delay)
                await asyncio.sleep(restart_delay)
            else:
                logger.warning("Background task %r exited unexpectedly — restarting", name)
                await asyncio.sleep(restart_delay)

    async def _prune_rate_limiters():
        while True:
            await asyncio.sleep(60)
            try:
                await db.prune_runtime_state()
            except Exception:
                logger.exception("Runtime state prune failed")

    prune_task = asyncio.create_task(
        _supervised(_prune_rate_limiters, name="rate-limiter-prune"),
        name="rate-limiter-prune",
    )
    prune_task.add_done_callback(_log_task_exception)

    visitor_sync_task = None
    if configured:
        async def _sync_visitors():
            """Periodically sync visitor status from UniFi."""
            while True:
                await asyncio.sleep(60)
                try:
                    access_client = app.state.access_client
                    if not access_client:
                        continue
                    unvr_visitors = await access_client.list_visitors()
                    unvr_map = {v["unique_id"]: v for v in unvr_visitors}
                    local_visitors = await db.get_all_visitors()
                    for lv in local_visitors:
                        uvid = lv["unvr_visitor_id"]
                        uv = unvr_map.get(uvid)
                        if uv and uv.get("status") != lv["status"]:
                            await db.update_visitor_status(lv["id"], uv["status"])
                            if uv.get("status") == 4 and lv["status"] != 4:
                                await db.log_access(
                                    method="system", result="info",
                                    lock_name=lv.get("location_name"),
                                    reason=f"Visitor '{lv['name']}' expired/deleted",
                                )
                except Exception:
                    logger.exception("Visitor sync failed")

        visitor_sync_task = asyncio.create_task(
            _supervised(_sync_visitors, name="visitor-sync"),
            name="visitor-sync",
        )
        visitor_sync_task.add_done_callback(_log_task_exception)

    # ------------------------------------------------------------------
    # Resilience loops (only run when the app is configured)
    # ------------------------------------------------------------------

    resilience_tasks: list[asyncio.Task] = []

    if configured:
        # HA health loop — polls test_connection() every 30s. On transition
        # from disconnected → connected, reseed lock_states so post-reboot
        # cached values are fresh.
        async def _ha_health_loop():
            previous_connected = bool(getattr(app.state.ha_client, "connected", False))
            while True:
                await asyncio.sleep(30)
                ha = app.state.ha_client
                if ha is None:
                    previous_connected = False
                    continue
                try:
                    now_connected = await ha.test_connection()
                except Exception:
                    logger.exception("HA health check raised")
                    now_connected = False
                if now_connected and not previous_connected:
                    logger.info("HA recovered — reseeding lock states")
                    seed = app.state.seed_lock_states
                    if seed is not None:
                        try:
                            count = await seed()
                            logger.info("Reseeded %d lock state(s) after HA recovery", count)
                        except Exception:
                            logger.exception("Lock state reseed failed after HA recovery")
                    # Also re-attempt any pending relocks that we couldn't
                    # fire while HA was down — rehydrate is idempotent for
                    # active tasks (they're cancelled and replaced).
                    rm = app.state.relock_manager
                    if rm is not None:
                        try:
                            await rm.rehydrate()
                        except Exception:
                            logger.exception("Relock rehydrate after HA recovery failed")
                elif previous_connected and not now_connected:
                    logger.warning("HA connection lost — %s", ha.last_error)
                elif now_connected:
                    # Steady-state while connected: sweep any overdue relocks
                    # that exhausted their retries so a door doesn't stay
                    # unlocked until the next reconnect/restart. (The recovery
                    # branch above already runs rehydrate(), which covers the
                    # transition tick.)
                    rm = app.state.relock_manager
                    if rm is not None:
                        try:
                            swept = await rm.sweep_overdue()
                            if swept:
                                logger.info("Swept %d overdue relock(s)", swept)
                        except Exception:
                            logger.exception("Overdue relock sweep failed")
                previous_connected = now_connected

        resilience_tasks.append(asyncio.create_task(
            _supervised(_ha_health_loop, name="ha-health"),
            name="ha-health",
        ))

        # Protect cold-start supervisor — keeps retrying if UNVR Protect
        # wasn't reachable at boot. Stops polling cheaply once connected.
        async def _protect_init_loop():
            while True:
                await asyncio.sleep(60)
                if app.state.protect_client is not None:
                    continue
                starter = app.state.start_protect_client
                if starter is None:
                    continue
                logger.info("Protect client missing — attempting bring-up")
                ok = await starter()
                if not ok:
                    # Lengthen the wait on repeated failure (max 5 min)
                    await asyncio.sleep(240)

        resilience_tasks.append(asyncio.create_task(
            _supervised(_protect_init_loop, name="protect-init"),
            name="protect-init",
        ))

        # Topology resync — UniFi may add/move doors and cameras; without
        # this, camera_to_location goes stale until a manual restart.
        async def _topology_resync_loop():
            while True:
                await asyncio.sleep(900)  # 15 min
                sync = app.state.sync_users
                if sync is None:
                    continue
                logger.debug("Periodic topology resync starting")
                try:
                    await sync()
                except Exception:
                    logger.exception("Periodic topology resync failed")

        resilience_tasks.append(asyncio.create_task(
            _supervised(_topology_resync_loop, name="topology-resync"),
            name="topology-resync",
        ))

        # WebSocket zombie watchdog — if last event timestamp is too stale
        # for an otherwise-healthy client, force a reconnect. UNVR has been
        # observed to keep TCP open while silently dropping events.
        async def _ws_watchdog_loop():
            # Don't trip on quiet doors — only escalate after a long silence
            stale_threshold = 4 * 3600  # 4 hours
            while True:
                await asyncio.sleep(300)  # check every 5 min
                loop_time = asyncio.get_running_loop().time()
                for label, client in (
                    ("access", app.state.access_client),
                    ("protect", app.state.protect_client),
                ):
                    if client is None or not getattr(client, "ws_connected", False):
                        continue
                    last = getattr(client, "last_event_at", 0.0)
                    if last <= 0:
                        # Haven't seen the first event yet — give it time
                        continue
                    silence = loop_time - last
                    if silence > stale_threshold:
                        logger.warning(
                            "WS %s silent for %.1fs (>%ds) — forcing reconnect",
                            label, silence, stale_threshold,
                        )
                        try:
                            await client.stop_websocket()
                            await client.start_websocket()
                        except Exception:
                            logger.exception("WS %s forced reconnect failed", label)

        resilience_tasks.append(asyncio.create_task(
            _supervised(_ws_watchdog_loop, name="ws-watchdog"),
            name="ws-watchdog",
        ))

        # Daily log retention — keep 90 days of access_log and admin_log
        async def _log_retention_loop():
            while True:
                await asyncio.sleep(86400)  # 24h
                try:
                    counts = await db.prune_logs(retain_days=90)
                    if counts["access_log"] or counts["admin_log"]:
                        logger.info(
                            "Log prune: deleted %d access_log + %d admin_log rows",
                            counts["access_log"], counts["admin_log"],
                        )
                except Exception:
                    logger.exception("Log retention prune failed")

        resilience_tasks.append(asyncio.create_task(
            _supervised(_log_retention_loop, name="log-retention"),
            name="log-retention",
        ))

        # Scheduled reboot — configurable via Settings. Reads three keys
        # from the config table: reboot_enabled (0/1), reboot_day (0=Mon..6=Sun
        # or 'daily'), reboot_hour (0-23). Defaults: disabled.
        # `last_reboot_fire_date` is persisted so a manual restart inside the
        # target hour can't accidentally trigger a second reboot.
        async def _scheduled_reboot_loop():
            from datetime import datetime as _dt
            from zoneinfo import ZoneInfo as _ZI
            import shlex as _shlex
            tz = _ZI("America/New_York")
            while True:
                await asyncio.sleep(60)
                try:
                    enabled = (await db.get_config("reboot_enabled")) == "1"
                    if not enabled:
                        continue
                    raw_day = await db.get_config("reboot_day") or "daily"
                    raw_hour = await db.get_config("reboot_hour") or "4"
                    try:
                        target_hour = max(0, min(23, int(raw_hour)))
                    except (TypeError, ValueError):
                        target_hour = 4
                    now = _dt.now(tz)
                    today_key = now.date().isoformat()
                    if raw_day != "daily":
                        try:
                            if now.weekday() != int(raw_day):
                                continue
                        except (TypeError, ValueError):
                            continue
                    if now.hour != target_hour:
                        continue
                    last_fire = await db.get_config("last_reboot_fire_date")
                    if last_fire == today_key:
                        continue
                    # Active-event guard — don't reboot if someone may be
                    # standing at the door right now.
                    ws_last = app.state.ws_last_event or {}
                    busy = False
                    for src in ("access", "protect"):
                        ts = ws_last.get(src)
                        if not ts:
                            continue
                        try:
                            evt_time = _dt.fromisoformat(ts)
                            age = (_dt.now(timezone.utc) - evt_time).total_seconds()
                            if age < 300:
                                busy = True
                                break
                        except (TypeError, ValueError):
                            continue
                    if busy:
                        logger.info(
                            "Scheduled reboot skipped — recent WS event (<5 min ago)"
                        )
                        # Don't persist last_fire — retry next minute
                        continue
                    await db.set_config("last_reboot_fire_date", today_key)
                    await db.log_admin_action(
                        "scheduler", "scheduled_restart",
                        target=f"hour={target_hour} day={raw_day}",
                    )
                    restart_cmd = os.environ.get(
                        "RESTART_COMMAND", "systemctl restart access-control"
                    )
                    logger.warning(
                        "Scheduled reboot firing now (%s) — cmd=%s",
                        now.isoformat(timespec="seconds"), restart_cmd,
                    )
                    parts = _shlex.split(restart_cmd)
                    proc = await asyncio.create_subprocess_exec(
                        *parts,
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL,
                    )
                    # systemctl restart kills this process — if it returns,
                    # the restart didn't take, but last_reboot_fire_date is
                    # set so we won't loop on it today.
                    await proc.wait()
                except Exception:
                    logger.exception("Scheduled reboot loop iteration failed")

        resilience_tasks.append(asyncio.create_task(
            _supervised(_scheduled_reboot_loop, name="scheduled-reboot"),
            name="scheduled-reboot",
        ))

        for t in resilience_tasks:
            t.add_done_callback(_log_task_exception)

    # --- Hand control to FastAPI ---
    yield

    # --- Shutdown ---
    background_tasks: list[asyncio.Task] = list(resilience_tasks)
    if visitor_sync_task is not None:
        background_tasks.append(visitor_sync_task)
    background_tasks.append(prune_task)
    for t in background_tasks:
        t.cancel()
    for t in background_tasks:
        try:
            await t
        except asyncio.CancelledError:
            pass
        except Exception:
            logger.exception("Background task shutdown raised")

    if app.state.protect_client is not None:
        await app.state.protect_client.close()
        logger.info("ProtectClient closed")

    if app.state.access_client is not None:
        await app.state.access_client.close()
        logger.info("AccessClient closed")

    if app.state.ha_client is not None:
        await app.state.ha_client.close()
        logger.info("HAClient closed")

    await db.close()
    logger.info("Database closed")


async def _handle_doorbell_ring(db, ha_client, camera_id: str) -> None:
    """Log a doorbell ring event. Locks linked to this doorbell can be controlled from the UI."""
    locks = await db.get_locks_by_entry_device("protect_doorbell", device_id=camera_id)
    lock_names = [l.get("name", "?") for l in locks]
    if lock_names:
        logger.info("Doorbell ring → associated locks: %s", ", ".join(lock_names))
    # Log one row per associated lock so per-lock history shows the ring;
    # if no locks are linked, still record a single row at camera level.
    if locks:
        reason = f"Doorbell ring (camera {camera_id[:12]})"
        for lock in locks:
            try:
                await db.log_access(
                    method="doorbell_ring", result="info",
                    lock_id=lock["id"], lock_name=lock.get("name"),
                    user_name=None, reason=reason,
                )
            except Exception:
                logger.exception("Failed to log doorbell ring for lock %s", lock.get("id"))
    else:
        try:
            await db.log_access(
                method="doorbell_ring", result="info",
                lock_id=None, lock_name=None, user_name=None,
                reason=f"Doorbell ring (camera {camera_id[:12]}) — no linked locks",
            )
        except Exception:
            logger.exception("Failed to log doorbell ring for camera %s", camera_id)
    # Fire HA event for automations
    if ha_client:
        try:
            await ha_client.fire_event("access_control_doorbell_ring", {
                "camera_id": camera_id,
                "locks": lock_names,
            })
        except Exception:
            logger.exception("Failed to fire doorbell ring HA event")


async def _handle_protect_access(auth_engine, camera_id: str, ulp_id: str, method: str) -> None:
    """Handle NFC/fingerprint access event from a Protect doorbell.

    Finds locks linked to this camera via entry_devices, then runs them
    through the auth engine for rule evaluation and unlock.
    """
    # process_event resolves locks from camera_id via entry_devices internally
    result = await auth_engine.process_event(
        ulp_id=ulp_id,
        location_id=camera_id,
        method=method,
    )
    user_name = result.get("user_name", ulp_id)
    if result.get("granted"):
        logger.info("Protect %s access GRANTED for %s (locks: %s)",
                     method, user_name, ", ".join(result.get("locks", [])))
    else:
        logger.info("Protect %s access DENIED for %s: %s",
                     method, user_name, result.get("reason"))


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

app = FastAPI(title="Access Control", lifespan=lifespan)


@app.get("/health/live")
async def health_live():
    """Unauthenticated liveness probe for container/load balancer health checks."""
    return {"status": "ok"}


# Static files
app.mount("/static", StaticFiles(directory=str(_HERE / "static")), name="static")

# Routers
app.include_router(api_router)
app.include_router(web_router)


# ---------------------------------------------------------------------------
# HTTP middleware stack
# ---------------------------------------------------------------------------
#
# Starlette wraps middlewares LIFO — the LAST `@app.middleware("http")`
# registered runs FIRST. The ingress middleware (registered at the very
# bottom of this file) must execute before setup_guard so that:
#
#   • `request.scope["root_path"]` is set before any redirect helper
#     builds a Location header
#   • non-admin HA users get a 403 before being bounced to /setup
#
# DO NOT add new `@app.middleware("http")` decorators after the ingress
# middleware registration — they would run BEFORE ingress and break the
# invariant. New middleware goes here, between security_headers and the
# ingress block at the end of the file.

@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Add security headers to all responses.

    Header values depend on whether the request came through HA Ingress
    (so the addon is iframed by HA at same-origin) vs. direct port (so
    the addon must refuse all framing). See `security_headers_for()` in
    ingress.py for the rationale; we just apply its output here.

    The ingress middleware sets `request.state.ingress_active` before
    this runs (LIFO order — ingress is outermost, security_headers is
    inner). Reading that flag here is safe.
    """
    response = await call_next(request)
    from .ingress import security_headers_for

    ingress_active = bool(getattr(request.state, "ingress_active", False))
    for name, value in security_headers_for(ingress_active=ingress_active).items():
        response.headers[name] = value
    return response


@app.middleware("http")
async def setup_guard(request: Request, call_next):
    """
    Redirect all non-setup traffic to /setup when the app is not configured.

    Exempt paths:
    - /setup  (the setup wizard itself)
    - /static (CSS, JS, etc.)
    """
    path = request.url.path
    configured = getattr(request.app.state, "configured", False)

    if not configured:
        exempt = path.startswith("/setup") or path.startswith("/static") or path == "/health/live"
        if not exempt:
            root = request.scope.get("root_path", "")
            return RedirectResponse(url=f"{root}/setup", status_code=302)

    return await call_next(request)


# Hard cap on POST body size at the middleware level. None of the form
# endpoints submit > 1 MB; reading bigger bodies into memory would let an
# authenticated user (or a future-introduced unauthenticated POST) OOM
# the container by streaming a huge body. Audit 2026-05-24, M2.
_MAX_FORM_BODY = 1_048_576  # 1 MiB


@app.middleware("http")
async def csrf_protection(request: Request, call_next):
    """
    Validate CSRF token on all POST requests except:
    - /api/* (uses Bearer token auth)
    - /login and /setup (no session yet)

    Under HA Ingress SSO there is no session cookie — the user identity
    comes from request.state.ingress_user. We bind the CSRF token to
    that identity too (using the same `ha:<name>` actor string
    `require_login` returns) so SSO POSTs are still protected.
    Audit 2026-05-24, M1.
    """
    if request.method == "POST":
        path = request.url.path
        exempt = (
            path.startswith("/api/")
            or path.startswith("/login")
            or path.startswith("/setup")
        )
        if not exempt:
            from .web_auth import get_session_user, validate_csrf_token

            ingress_user = getattr(request.state, "ingress_user", None)
            cookie_user = get_session_user(request)
            user = (
                f"ha:{ingress_user['name']}" if ingress_user else cookie_user
            )
            if user:
                # Reject oversize bodies early so reading them doesn't
                # OOM the container. We also reject chunked Transfer-
                # Encoding without Content-Length, which would otherwise
                # bypass the size cap (the body would still be buffered
                # in full by `await request.body()`). Audit 2026-05-24
                # (codebase review), CSRF middleware finding.
                content_length = int(request.headers.get("content-length") or 0)
                transfer_encoding = request.headers.get("transfer-encoding", "").lower()
                if "chunked" in transfer_encoding and content_length == 0:
                    from fastapi.responses import HTMLResponse
                    return HTMLResponse(
                        "<h1>411 Length Required</h1>"
                        "<p>Chunked transfer-encoding is not accepted for form POSTs; "
                        "include a Content-Length header.</p>",
                        status_code=411,
                    )
                if content_length > _MAX_FORM_BODY:
                    from fastapi.responses import HTMLResponse
                    return HTMLResponse(
                        "<h1>413 Payload Too Large</h1>"
                        "<p>Request body exceeds the form-submission size limit.</p>",
                        status_code=413,
                    )

                # Read body and cache it so downstream handlers can re-read it
                body = await request.body()
                from urllib.parse import parse_qs
                parsed = parse_qs(body.decode(), keep_blank_values=True)
                token = parsed.get("_csrf_token", [""])[0]
                if not validate_csrf_token(token, user):
                    from fastapi.responses import HTMLResponse
                    return HTMLResponse(
                        "<h1>403 Forbidden</h1><p>Invalid CSRF token. "
                        '<a href="javascript:history.back()">Go back</a></p>',
                        status_code=403,
                    )
                # Cache the body for downstream form parsing
                async def receive():
                    return {"type": "http.request", "body": body, "more_body": False}
                request._receive = receive

    response = await call_next(request)
    return response


# ---------------------------------------------------------------------------
# HA Ingress middleware  (REGISTERED LAST — RUNS FIRST)
# ---------------------------------------------------------------------------
# Must run before security_headers/setup_guard/csrf_protection so that
# request.scope["root_path"] is populated before any of those build a
# Location header or read auth state. See the note above security_headers
# for the LIFO ordering rationale.
from .ingress import ingress_middleware as _ingress_middleware  # noqa: E402

app.middleware("http")(_ingress_middleware)


# Runtime guard: detect a future regression where someone adds a new
# `@app.middleware("http")` *below* this block, which would silently
# demote the ingress middleware from outermost (runs-first) to inner
# (runs-later). FastAPI's `add_middleware` (which `@app.middleware`
# calls under the hood) prepends to `app.user_middleware`, and
# Starlette's stack builder iterates that list in reverse — so the
# LAST registered middleware ends up at index 0 and runs OUTERMOST.
# Verified by inspecting Starlette's `build_middleware_stack`. If this
# invariant ever breaks, fail loudly at import time rather than letting
# an auth-bypass slip through to production.
def _assert_ingress_outermost() -> None:
    if not app.user_middleware:
        raise RuntimeError("No user middleware registered; ingress wiring lost")
    outermost = app.user_middleware[0]
    dispatch = (
        getattr(outermost, "kwargs", {}).get("dispatch")
        or getattr(outermost, "options", {}).get("dispatch")
    )
    if dispatch is not _ingress_middleware:
        raise RuntimeError(
            "HA Ingress middleware is no longer the outermost wrapper. "
            "A later `@app.middleware('http')` call has demoted it, which "
            "would let other middleware run with root_path unset and SSO "
            "headers untrusted. Move the new middleware ABOVE the ingress "
            "block in main.py."
        )


_assert_ingress_outermost()
