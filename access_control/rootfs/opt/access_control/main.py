"""FastAPI entry point for the Access Control App."""
from __future__ import annotations

import asyncio
import inspect
import logging
import mimetypes
import os
import sys
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

# Ensure app-level loggers propagate to stdout (uvicorn suppresses by default).
# Honor the add-on's log_level option (exported by run.sh as APP_LOG_LEVEL):
# previously this was pinned to INFO, so selecting `debug` in the add-on
# config changed uvicorn's chatter but never enabled the app's own debug
# logs (e2e review 2026-07-12). HA levels that Python lacks map to the
# nearest Python level.
_HA_TO_PY_LEVEL = {
    "trace": logging.DEBUG,
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "notice": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "fatal": logging.CRITICAL,
}
logging.basicConfig(
    level=_HA_TO_PY_LEVEL.get(
        os.environ.get("APP_LOG_LEVEL", "info").strip().lower(), logging.INFO
    ),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    stream=sys.stdout,
)

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from .access_client import AccessClient
from .api_routes import router as api_router
from .auth_engine import AuthEngine
from .config import (
    SECRET_KEY_SOURCE_DATABASE,
    decrypt_value,
    derive_key,
    resolve_secret_key,
    secret_key_fingerprint,
)
from .database import Database
from .ha_creds import (
    MissingHACredentialsError,
    resolve_ha_creds as _resolve_ha_creds,
)
from .hub_sync import HubSyncManager
from .protect_client import ProtectClient
from .ha_client import HAClient
from .relock_manager import RelockManager
from .service_restart import request_service_restart
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
async def _lifespan_inner(app: FastAPI):
    """Startup and shutdown logic wired via the lifespan context manager."""

    # --- Startup ---

    app.state.lifecycle_cleanup_complete = False
    db = Database()
    app.state.db = db
    await db.connect()

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
    app.state.hub_sync_manager: HubSyncManager | None = None
    app.state.camera_to_location = {}
    app.state.event_topology_ready = False
    app.state.access_generation = 0
    app.state.restart_request_error = None
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
    app.state.access_creds = None  # (host, user, pass)
    app.state.access_api_token = None
    app.state.access_open_api_ready = False
    app.state.access_open_api_error = None
    app.state.access_console_identity = None
    app.state.start_access_client = None
    app.state.start_protect_client = None
    app.state.access_started_client = None
    app.state.protect_started_client = None
    app.state.seed_lock_states = None
    app.state.physical_command_lock = asyncio.Lock()
    app.state.setup_lock = asyncio.Lock()
    app.state.settings_update_lock = asyncio.Lock()
    app.state.access_start_lock = asyncio.Lock()
    app.state.protect_start_lock = asyncio.Lock()
    app.state.topology_sync_lock = asyncio.Lock()
    app.state.visitor_operation_locks = {}
    app.state.access_data_lock = asyncio.Lock()

    # Door-event work is deliberately fire-and-forget during normal
    # operation, but it still needs an owner so shutdown can cancel and await
    # it before clients and SQLite are closed underneath an in-flight task.
    event_tasks: set[asyncio.Task] = set()

    def _track_event_task(
        task: asyncio.Task, *, critical: bool = False
    ) -> None:
        if critical:
            setattr(task, "_access_control_critical", True)
        event_tasks.add(task)

        def _done(completed: asyncio.Task) -> None:
            event_tasks.discard(completed)
            _log_task_exception(completed)

        task.add_done_callback(_done)

    async def _drain_event_tasks() -> None:
        """Cancel queued source events before a live-client publication swap."""
        current = asyncio.current_task()
        pending = [task for task in event_tasks if task is not current]
        for task in pending:
            if (
                not task.done()
                and not getattr(task, "_access_control_critical", False)
            ):
                task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    app.state.drain_event_tasks = _drain_event_tasks
    app.state.track_background_task = _track_event_task

    # Track recently processed events to deduplicate between Protect fast-path and Access WS
    _recent_events: dict[str, float] = {}

    def _is_duplicate(ulp_id: str, location_id: str, event_id: str = "") -> bool:
        """
        Check if this access event was already processed in the last 3s.

        Tracks two keys so that the *cross-path* duplicate (Protect fast-path
        + Access standard-path firing for the same physical tap) is caught
        even though only the Access path carries an event_id:

        - ``ulp_id:location_id`` — set on every event; matches across paths
        - ``event_id`` — set only when the Access log payload carries it;
          protects against the same Access log being delivered twice
        """
        now = time.monotonic()
        # Cross-client copies arrive almost together. Keep the window short so
        # a genuine retry after a failed first attempt is not suppressed.
        dedup_window = 3.0
        for k in list(_recent_events):
            if now - _recent_events[k] > dedup_window:
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
        async with app.state.topology_sync_lock:
            access_client = app.state.access_client
            generation = app.state.access_generation
            if not access_client:
                logger.warning("sync_users() skipped — Access client not initialized")
                return

            logger.info("Starting user/lock sync…")
            # Do not apply user/door identifiers from a cached session until
            # its authenticated Access namespace has been revalidated. This
            # complements per-login and per-WebSocket-upgrade verification.
            await access_client.verify_console_identity()
            # Fetch independent snapshots concurrently, then apply both on a
            # dedicated SQLite connection in one transaction.  The former
            # commit=False batch shared the request connection, so an unrelated
            # request could commit a half-finished topology snapshot (or have
            # its own writes rolled back when this function failed).
            users, bootstrap = await asyncio.gather(
                access_client.fetch_users(), access_client.get_bootstrap()
            )
            if (
                access_client is not app.state.access_client
                or generation != app.state.access_generation
            ):
                logger.warning(
                    "Discarding topology snapshot from a retired Access client"
                )
                return
            doors = access_client.parse_doors_and_devices(bootstrap)
            hub_devices = [
                door for door in doors
                if isinstance(door, dict) and not door.get("is_camera")
            ]
            valid_users = [
                user for user in users
                if isinstance(user, dict) and user.get("ulp_id")
            ]
            valid_hubs = [
                door for door in hub_devices
                if door.get("device_id") and door.get("location_id")
            ]
            if not valid_users and await db.get_user_count():
                raise RuntimeError(
                    "Access returned no valid users while local users exist; "
                    "refusing an untrusted topology snapshot"
                )
            if not valid_hubs:
                existing_locks = await db.get_all_locks(include_hidden=True)
                if any(
                    lock.get("type") == "access_native"
                    and lock.get("upstream_present", 1)
                    for lock in existing_locks
                ):
                    raise RuntimeError(
                        "Access returned no valid doors while native locks "
                        "exist; refusing an untrusted topology snapshot"
                    )
            stats = await db.sync_topology(users, hub_devices)
            if (
                access_client is not app.state.access_client
                or generation != app.state.access_generation
            ):
                # The old snapshot may have committed, but event intake was
                # marked unready by the swap. Never publish its camera map or
                # re-enable authorization; the queued current-client sync is
                # the only generation allowed to do that.
                logger.warning(
                    "Topology changed clients during database apply; keeping "
                    "event intake fail-closed"
                )
                return
            logger.info(
                "Topology sync: users=%d (+%d/~%d/deleted=%d/unchanged=%d), "
                "locks=%d (+%d/~%d/unchanged=%d)",
                stats["users_seen"],
                stats["users_inserted"],
                stats["users_updated"],
                stats["users_marked_deleted"],
                stats["users_unchanged"],
                stats["locks_seen"],
                stats["locks_inserted"],
                stats["locks_updated"],
                stats["locks_unchanged"],
            )

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
            app.state.event_topology_ready = True
            logger.info("Camera→location map: %d entries", len(new_map))

    # Semaphore to cap concurrent process_event invocations during event floods
    _event_semaphore = asyncio.Semaphore(5)

    # Register WebSocket event callback
    def on_access_event(message: dict) -> None:
        """Dispatch relevant Access events to the auth engine."""
        app.state.ws_last_event["access"] = datetime.now(timezone.utc).isoformat()
        if not app.state.event_topology_ready:
            logger.warning(
                "Dropping Access event while topology is being refreshed"
            )
            return
        event_type: str = message.get("event", "") or message.get("type", "")
        if not event_type:
            return

        def _queue_access_state_reconcile(
            location: str, access_event_type: str
        ) -> bool:
            manager = app.state.hub_sync_manager
            if (
                manager is None
                or not manager.is_access_state_event(access_event_type)
                or not location
            ):
                return False
            task = asyncio.create_task(
                manager.reconcile_location(location, access_event_type),
                name=f"access-state-{access_event_type}-{location}",
            )
            # A schedule transition changes physical desired state. Drain it
            # across a client swap/shutdown just like durable relock work.
            _track_event_task(task, critical=True)
            return True

        # Newer Access versions can emit schedule/temporary-rule events
        # directly rather than wrapping them in access.logs.add. They often
        # have no actor, so dispatch before credential identity filtering.
        if HubSyncManager.is_access_state_event(event_type):
            data = message.get("data", {})
            if not isinstance(data, dict):
                return
            location_id = (
                data.get("location_id")
                or data.get("door_id")
                or data.get("unique_id")
                or message.get("event_object_id")
                or ""
            )
            _queue_access_state_reconcile(location_id, event_type)
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
            door = meta.get("door", {})
            if HubSyncManager.is_access_state_event(evt_type):
                location_id = (
                    door.get("id")
                    or data.get("location_id")
                    or data.get("door_id")
                    or ""
                )
                _queue_access_state_reconcile(location_id, evt_type)
                return
            result = data.get("result", "") or evt.get("result", "")
            if "unlock" not in evt_type and result != "ACCESS":
                return

            actor = meta.get("actor", {})
            ulp_id = actor.get("id", "")
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

        if not location_id:
            return
        if not ulp_id:
            if method == "remote_through_uah":
                # Remote/API/automation unlock logs do not consistently carry
                # a person actor. Relock is a door-safety reaction and must not
                # depend on that optional identity; use a stable dedup subject.
                ulp_id = "remote"
            else:
                return

        # Apply dedup before the remote-unlock early return too. Re-delivered
        # remote events used to replace the durable relock row and extend the
        # deadline indefinitely.
        if _is_duplicate(ulp_id, location_id, event_id=event_id):
            logger.debug(
                "Skipping duplicate Access WS event for %s (already handled)",
                ulp_id,
            )
            return

        if method == "remote_through_uah":
            async def _schedule_remote_relock(loc_id: str) -> None:
                rm = app.state.relock_manager
                if rm is None:
                    return
                # Resolve through the auth engine so entry-device-paired
                # locks are included — the bare DB column lookup missed
                # them, so a remote unlock never scheduled a relock and
                # the door stayed open (e2e review 2026-07-12).
                engine = app.state.auth_engine
                if engine is not None:
                    locks = await engine.get_locks_for_location(loc_id)
                else:
                    locks = await db.get_locks_for_location(loc_id)
                for lock in locks:
                    if not lock.get("relock_on_remote") or lock["type"] != "ha_external":
                        continue
                    eid = lock.get("entity_id")
                    if not eid:
                        continue
                    lock_name = lock.get("name", eid)
                    try:
                        relock_intent = await rm.schedule(
                            entity_id=eid,
                            duration=lock.get("relock_duration", 30),
                            lock_id=lock.get("id"),
                            lock_name=lock_name,
                            source="remote",
                        )
                        # For bidirectionally synced pairs, the Access remote
                        # unlock must also operate the HA lock. Persisting the
                        # relock above comes first so a timeout/crash cannot
                        # strand HA open. The momentary marker prevents the hub
                        # poller from echoing this temporary HA state back as a
                        # persistent Access keep-unlock rule.
                        if lock.get("sync_hub_state"):
                            duration = float(lock.get("relock_duration", 30))
                            hub_sync = app.state.hub_sync_manager
                            if hub_sync is not None:
                                hub_sync.mark_access_momentary(eid, duration)
                            accepted = False
                            confirmed = False
                            command_ha = None
                            try:
                                async with app.state.physical_command_lock:
                                    current_engine = app.state.auth_engine
                                    if current_engine and current_engine.lockdown:
                                        logger.warning(
                                            "Remote unlock for %s not mirrored to "
                                            "HA during lockdown",
                                            lock_name,
                                        )
                                    else:
                                        command_ha = app.state.ha_client
                                        accepted = bool(
                                            command_ha
                                            and await command_ha.unlock(eid)
                                        )
                                if accepted and command_ha is not None:
                                    for attempt in range(3):
                                        if (
                                            await command_ha.get_entity_state(eid)
                                            == "unlocked"
                                        ):
                                            confirmed = True
                                            break
                                        if attempt < 2:
                                            await asyncio.sleep(0.25)
                                if confirmed:
                                    app.state.lock_states[eid] = "unlocked"
                                    try:
                                        await rm.extend_after_success(
                                            relock_intent, duration
                                        )
                                    except Exception:
                                        logger.exception(
                                            "Could not extend remote relock for %s; "
                                            "earlier write-ahead deadline retained",
                                            lock_name,
                                        )
                                else:
                                    await rm.retain_after_uncertain_unlock(
                                        relock_intent
                                    )
                                    logger.error(
                                        "Remote Access unlock was not confirmed "
                                        "on HA lock %s",
                                        lock_name,
                                    )
                            except asyncio.CancelledError:
                                await rm.retain_after_uncertain_unlock(
                                    relock_intent
                                )
                                raise
                            except Exception:
                                logger.exception(
                                    "Remote Access unlock mirroring raised for %s",
                                    lock_name,
                                )
                                await rm.retain_after_uncertain_unlock(
                                    relock_intent
                                )
                    except BaseException as exc:
                        # The remote event arrives after the door was already
                        # opened. If write-ahead persistence fails, immediately
                        # try the safe direction rather than aborting the loop
                        # and leaving this/all later locks without protection.
                        logger.critical(
                            "Could not persist remote relock for %s; issuing "
                            "immediate fail-safe lock",
                            lock_name,
                            exc_info=True,
                        )
                        confirmed = False
                        try:
                            async with app.state.physical_command_lock:
                                ha = app.state.ha_client
                                accepted = bool(ha and await ha.lock(eid))
                            if accepted:
                                ha = app.state.ha_client
                                confirmed = bool(
                                    ha
                                    and await ha.get_entity_state(eid) == "locked"
                                )
                        except Exception:
                            logger.exception(
                                "Immediate fail-safe lock raised for %s", lock_name
                            )
                        try:
                            await db.log_access(
                                method="remote_relock",
                                result="granted" if confirmed else "error",
                                lock_id=lock.get("id"),
                                lock_name=lock_name,
                                reason=(
                                    "Immediate lock recovered from relock "
                                    "persistence failure"
                                    if confirmed
                                    else f"Relock persistence failed: {type(exc).__name__}"
                                ),
                            )
                        except Exception:
                            logger.exception(
                                "Failed to audit remote relock persistence error"
                            )
                        if not confirmed:
                            ha = app.state.ha_client
                            if ha is not None:
                                try:
                                    await ha.fire_event(
                                        "access_control_relock_failed",
                                        {
                                            "entity_id": eid,
                                            "lock_name": lock_name,
                                            "reason": "persistence_failed",
                                        },
                                    )
                                except Exception:
                                    logger.exception(
                                        "Failed to emit remote relock alert for %s",
                                        lock_name,
                                    )
                        if isinstance(exc, asyncio.CancelledError):
                            raise

            task = asyncio.create_task(
                _schedule_remote_relock(location_id),
                name=f"remote-relock-{location_id}",
            )
            _track_event_task(task, critical=True)
            return

        async def _gated():
            async with _event_semaphore:
                return await auth_engine.process_event(ulp_id=ulp_id, location_id=location_id, method=method)

        task = asyncio.create_task(_gated(), name=f"process-event-{ulp_id}")
        _track_event_task(task)

    def on_protect_event(message: dict) -> None:
        """Handle ring, NFC, fingerprint, and doorAccess events from Protect."""
        app.state.ws_last_event["protect"] = datetime.now(timezone.utc).isoformat()
        if not app.state.event_topology_ready:
            logger.warning(
                "Dropping Protect event while topology is being refreshed"
            )
            return
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
            _track_event_task(task)
            return

        if event == "ring":
            async def _gated_ring() -> None:
                # Logging and HA event emission are non-physical. Keeping them
                # off the global command barrier prevents repeated rings (or
                # an offline HA notification timeout) from delaying lockdown
                # and legitimate door commands.
                await _handle_doorbell_ring(
                    db, app.state.ha_client, camera_id
                )

            task = asyncio.create_task(
                _gated_ring(),
                name=f"doorbell-ring-{camera_id}",
            )
            _track_event_task(task)
        elif event in ("nfc", "fingerprint"):
            ulp_id = message.get("ulp_id", "")
            if not ulp_id:
                logger.info("Protect %s event with no ulp_id — unregistered credential", event)
                return
            # The same physical tap also arrives via the Access WS log
            # path. Dedup on the camera's mapped door location so both
            # paths share a key — without this, one tap unlocked (and
            # auto-disarmed) twice (e2e review 2026-07-12). Falls back to
            # camera_id when no mapping exists, which still suppresses
            # Protect-side re-deliveries.
            dedup_location = app.state.camera_to_location.get(camera_id, "") or camera_id
            if _is_duplicate(ulp_id, dedup_location):
                logger.debug(
                    "Skipping duplicate Protect %s event for %s", event, ulp_id
                )
                return

            async def _gated_protect_cred():
                async with _event_semaphore:
                    return await _handle_protect_access(auth_engine, camera_id, ulp_id, event)

            task = asyncio.create_task(
                _gated_protect_cred(),
                name=f"protect-{event}-{camera_id}",
            )
            _track_event_task(task)

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

        stored_secret_key = await db.get_config("secret_key")
        secret_key_source = await db.get_config("secret_key_source")
        secret_key, normalized_key_source = resolve_secret_key(
            stored_key=stored_secret_key,
            source=secret_key_source,
            stored_fingerprint=await db.get_config("secret_key_fingerprint"),
            environment_key=os.environ.get("ACCESS_CONTROL_SECRET_KEY"),
        )
        if secret_key_source is None:
            # One-time, backward-compatible migration.  Legacy installations
            # always encrypted with the database key, even if an env override
            # was later added (that override was the source of the old
            # undecryptable-credentials bug).
            await db.set_config("secret_key_source", normalized_key_source)
            await db.set_config(
                "secret_key_fingerprint", secret_key_fingerprint(secret_key)
            )
        if (
            normalized_key_source == SECRET_KEY_SOURCE_DATABASE
            and os.environ.get("ACCESS_CONTROL_SECRET_KEY")
        ):
            logger.warning(
                "Ignoring ACCESS_CONTROL_SECRET_KEY: this installation was "
                "initialized with a database-managed key"
            )

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

        access_api_token = os.environ.get(
            "ACCESS_CONTROL_ACCESS_API_TOKEN"
        )
        if not access_api_token:
            access_api_token_enc = await db.get_config("access_api_token")
            if access_api_token_enc:
                access_api_token = decrypt_value(
                    access_api_token_enc, enc_key
                )
        access_api_token = access_api_token or None
        app.state.access_api_token = access_api_token

        # Resolve HA creds via the module-level helper — see
        # _resolve_ha_creds() above for the env-vs-DB precedence rules.
        try:
            ha_url, ha_token, creds_source = _resolve_ha_creds(
                env_url=os.environ.get("ACCESS_CONTROL_HA_URL"),
                env_token=os.environ.get("ACCESS_CONTROL_HA_TOKEN"),
                db_url=await db.get_config("ha_url"),
                db_token_enc=await db.get_config("ha_token"),
                decrypt=lambda enc: decrypt_value(enc, enc_key),
                log=logger,
            )
            logger.info("HA credentials resolved from: %s", creds_source)
        except MissingHACredentialsError:
            # A default Supervisor install intentionally stores no fallback HA
            # token. If the operator later disables use_supervisor_api, keep
            # the authenticated dashboard/Settings available so they can enter
            # a manual pair instead of crash-looping before the UI loads.
            logger.exception(
                "No complete HA credentials; starting degraded so Settings "
                "can repair the connection"
            )
            ha_url = ha_token = creds_source = None

        # Stash UNVR creds — the supervisor loops use these to recover
        # if Access or Protect was unreachable at boot.
        app.state.unvr_creds = (unvr_host, unvr_username, unvr_password)
        app.state.access_creds = (a_host, a_user, a_pass)

        expected_access_identity = await db.get_config(
            "access_console_identity"
        )
        app.state.access_console_identity = expected_access_identity
        access_client = AccessClient(
            host=a_host,
            username=a_user,
            password=a_pass,
            expected_identity=expected_access_identity,
            api_token=access_api_token,
        )
        try:
            await access_client.login()
            expected_access_identity = await db.get_config(
                "access_console_identity"
            )
            observed_access_identity = await access_client.get_console_identity()
            if (
                expected_access_identity
                and expected_access_identity != observed_access_identity
            ):
                raise RuntimeError(
                    "Access site identity changed; refusing to apply "
                    "site-scoped user/door IDs"
                )
            if not expected_access_identity and observed_access_identity:
                await db.set_config(
                    "access_console_identity",
                    observed_access_identity,
                )
                app.state.access_console_identity = observed_access_identity
            logger.info("AccessClient authenticated at %s", a_host)
            if access_api_token:
                try:
                    await access_client.validate_open_api()
                    app.state.access_open_api_ready = True
                    app.state.access_open_api_error = None
                    logger.info(
                        "Official UniFi Access API validated on port 12445"
                    )
                except Exception as exc:
                    # Keep topology/event intake available, but commands remain
                    # pinned to the configured official token and therefore fail
                    # closed instead of silently falling back to the private API.
                    app.state.access_open_api_ready = False
                    app.state.access_open_api_error = type(exc).__name__
                    logger.error(
                        "Official UniFi Access API validation failed: %s",
                        type(exc).__name__,
                    )
        except Exception:
            logger.exception("AccessClient startup failed — proceeding without Access integration")
            try:
                await access_client.close()
            except Exception:
                logger.exception("Failed to close unsuccessful Access client")
            access_client = None
        app.state.access_client = access_client

        ha_client = HAClient(url=ha_url, token=ha_token) if ha_url and ha_token else None
        ha_ok = bool(ha_client and await ha_client.test_connection())
        if not ha_ok:
            logger.warning(
                "HA connection test failed — proceeding anyway "
                "(creds_source=%s). app.state.ha_unhealthy is now True; "
                "health endpoints and supervisor loops should react.",
                creds_source or "missing",
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
            command_lock=app.state.physical_command_lock,
        )

        # HubSyncManager mirrors opted-in third-party HA lock states onto
        # their paired Access hubs (per-lock sync_hub_state setting, off by
        # default). Clients are fetched lazily via getters — same rationale
        # as RelockManager. on_hub_state keeps the lock_states cache fresh
        # so the Locks page shows the hub's new state.
        def _mark_hub_state(device_id: str, state: str) -> None:
            app.state.lock_states[device_id] = state

        app.state.hub_sync_manager = HubSyncManager(
            db=db,
            ha_client_getter=lambda: app.state.ha_client,
            access_client_getter=lambda: app.state.access_client,
            on_hub_state=_mark_hub_state,
            # HA entity state is writable by any HA token/integration, so
            # hub sync must not be able to hold a door open during an
            # incident lockdown — the manager suppresses unlock
            # transitions while this returns True.
            lockdown_getter=lambda: bool(
                app.state.auth_engine and app.state.auth_engine.lockdown
            ),
            # Live camera→location map so locks paired to their door via a
            # Protect doorbell entry device (G6 Entry) resolve their hub.
            camera_map_getter=lambda: app.state.camera_to_location,
            command_lock=app.state.physical_command_lock,
            # Opt-in relock_on_ha_origin schedules a durable re-lock through the
            # RelockManager (constructed just above) when an external HA unlock
            # is observed on a synced lock.
            relock_manager_getter=lambda: app.state.relock_manager,
        )

        async def _enforce_hub_lockdown() -> None:
            manager = app.state.hub_sync_manager
            if manager is not None:
                await manager.enforce_lockdown()

        app.state.auth_engine = AuthEngine(
            db=db,
            access_client=access_client,
            ha_client=ha_client,
            relock_tasks=app.state.relock_tasks,
            enc_key=enc_key,
            relock_manager=app.state.relock_manager,
            camera_map_getter=lambda: app.state.camera_to_location,
            command_lock=app.state.physical_command_lock,
            on_lockdown_enabled=_enforce_hub_lockdown,
            # Lazily fetched so a device-auth timed unlock can lease a momentary
            # Access hold on a bidirectionally synced lock.
            hub_sync_getter=lambda: app.state.hub_sync_manager,
        )

        # Restore lockdown mode persisted before a restart (incident control
        # must survive a reboot). An unreadable value is ambiguous and fails
        # closed as enabled until an operator can explicitly clear it.
        await app.state.auth_engine.load_persisted_lockdown()

        # Align schedule evaluation with the site's local timezone. HA's
        # configured time_zone is authoritative; until it's available the
        # engine falls back to TZ env / container-local time (see
        # auth_engine._default_timezone). The HA health loop retries this
        # on recovery if HA was down at boot.
        if ha_ok:
            try:
                tz_name = await ha_client.get_timezone()
                if tz_name:
                    app.state.auth_engine.set_timezone(tz_name)
            except Exception:
                logger.exception("Failed to fetch HA timezone — schedules use %s",
                                 app.state.auth_engine.tz)

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

        async def start_access_client() -> bool:
            """Bring up Access fully, closing failed candidates before retry."""
            async with app.state.access_start_lock:
                candidate = app.state.access_client
                if (
                    candidate is not None
                    and candidate is app.state.access_started_client
                ):
                    ws_task = getattr(candidate, "_ws_task", "unobservable")
                    if ws_task == "unobservable" or (
                        ws_task is not None and not ws_task.done()
                    ):
                        return True
                if candidate is None:
                    creds = app.state.access_creds
                    if not creds:
                        return False
                    candidate = AccessClient(
                        *creds,
                        expected_identity=app.state.access_console_identity,
                        api_token=app.state.access_api_token,
                    )
                    try:
                        await candidate.login()
                        recovered_identity = await candidate.get_console_identity()
                        if not recovered_identity:
                            raise RuntimeError(
                                "Recovered Access client has no site identity"
                            )
                        if app.state.access_console_identity is None:
                            # Persist before publication/event intake. If this
                            # fails, do not leave a legacy install in TOFU on
                            # every restart.
                            await db.set_config(
                                "access_console_identity", recovered_identity
                            )
                            app.state.access_console_identity = recovered_identity
                        if candidate.open_api_configured:
                            try:
                                await candidate.validate_open_api()
                                app.state.access_open_api_ready = True
                                app.state.access_open_api_error = None
                            except Exception as exc:
                                app.state.access_open_api_ready = False
                                app.state.access_open_api_error = type(exc).__name__
                                logger.error(
                                    "Recovered Access Open API validation "
                                    "failed: %s",
                                    type(exc).__name__,
                                )
                    except Exception:
                        logger.exception("Access client bring-up failed")
                        try:
                            await candidate.close()
                        except Exception:
                            logger.exception("Failed to close unsuccessful Access client")
                        return False
                try:
                    app.state.access_client = candidate
                    if app.state.auth_engine is not None:
                        app.state.auth_engine._access_client = candidate

                    # Reset every crash-persisted hold before accepting fresh
                    # door events. This requires Access only, not HA, and also
                    # fail-safes all opted-in hubs when lockdown was restored.
                    manager = app.state.hub_sync_manager
                    if manager is not None:
                        try:
                            await manager.recover()
                        except Exception:
                            logger.exception(
                                "Hub hold recovery failed; durable rows retained"
                            )

                    try:
                        await sync_users()
                    except Exception:
                        # Keep event intake fail-closed until the periodic sync
                        # succeeds and marks event_topology_ready.
                        app.state.event_topology_ready = False
                        logger.exception(
                            "Topology refresh failed during Access bring-up"
                        )

                    candidate.register_callback(on_access_event)
                    await candidate.start_websocket()
                except Exception:
                    logger.exception("Access WebSocket bring-up failed")
                    try:
                        await candidate.close()
                    except Exception:
                        logger.exception("Failed to close unsuccessful Access client")
                    if app.state.access_client is candidate:
                        app.state.access_client = None
                    return False
                app.state.access_started_client = candidate
                logger.info("Access WebSocket listener started")
                return True

        app.state.start_access_client = start_access_client
        if access_client is not None:
            await start_access_client()

        # Protect cold-start is wrapped so the supervisor loop can keep
        # retrying if UNVR Protect was warming up at boot. If login fails
        # here, app.state.protect_client stays None and the supervisor
        # picks up the next attempt.
        async def start_protect_client() -> bool:
            async with app.state.protect_start_lock:
                existing = app.state.protect_client
                if (
                    existing is not None
                    and existing is app.state.protect_started_client
                ):
                    ws_task = getattr(existing, "_ws_task", "unobservable")
                    if ws_task == "unobservable" or (
                        ws_task is not None and not ws_task.done()
                    ):
                        return True
                if existing is not None and getattr(existing, "connected", False):
                    existing.register_callback(on_protect_event)
                    await existing.start_websocket()
                    app.state.protect_started_client = existing
                    return True
                creds = app.state.unvr_creds
                if not creds:
                    return False
                host, user, pwd = creds
                protect_client = ProtectClient(host, user, pwd)
                try:
                    await protect_client.login()
                    protect_client.register_callback(on_protect_event)
                    await protect_client.start_websocket()
                except Exception:
                    logger.exception("Protect client bring-up failed")
                    try:
                        await protect_client.close()
                    except Exception:
                        logger.exception("Failed to close unsuccessful Protect client")
                    return False
                app.state.protect_client = protect_client
                app.state.protect_started_client = protect_client
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
            await asyncio.sleep(300)
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
    # Start supervisors even in first-run mode. They are cheap no-ops until
    # setup populates app.state; this means a successful setup becomes fully
    # operational without requiring an undocumented restart.
    if app.state.initialize_configured_state is not None:
        async def _sync_visitors():
            """Periodically sync visitor status from UniFi."""
            while True:
                await asyncio.sleep(300)
                try:
                    access_client = app.state.access_client
                    if not access_client:
                        continue
                    # Check the (cheap, local) visitor table BEFORE the
                    # TLS round-trip to the console — with no visitors
                    # this loop was still making 1,440 UNVR requests/day
                    # forever (e2e review 2026-07-12).
                    local_visitors = await db.get_active_visitors()
                    if not local_visitors:
                        continue
                    remaining_visitors: list[dict] = []
                    now_utc = datetime.now(timezone.utc)
                    for visitor in local_visitors:
                        try:
                            end_at = datetime.fromisoformat(visitor["end_time"])
                            if end_at.tzinfo is None:
                                engine = app.state.auth_engine
                                local_zone = (
                                    engine.tz
                                    if engine is not None
                                    else now_utc.astimezone().tzinfo
                                )
                                end_at = end_at.replace(tzinfo=local_zone)
                            if end_at.astimezone(timezone.utc) <= now_utc:
                                expired = await db.expire_active_visitor(
                                    visitor["id"], visitor["end_time"]
                                )
                                if expired:
                                    await db.log_access(
                                        method="system",
                                        result="info",
                                        lock_name=visitor.get("location_name"),
                                        reason=f"Visitor '{visitor['name']}' expired locally",
                                    )
                                continue
                        except (KeyError, TypeError, ValueError):
                            logger.warning(
                                "Visitor %s has invalid end_time %r; retaining for "
                                "upstream reconciliation",
                                visitor.get("id"),
                                visitor.get("end_time"),
                            )
                        remaining_visitors.append(visitor)
                    if not remaining_visitors:
                        continue
                    async with app.state.access_data_lock:
                        access_client = app.state.access_client
                        if access_client is None:
                            continue
                        unvr_visitors = await access_client.list_visitors()
                    unvr_map = {v["unique_id"]: v for v in unvr_visitors}
                    for lv in remaining_visitors:
                        uvid = lv["unvr_visitor_id"]
                        uv = unvr_map.get(uvid)
                        if uv and uv.get("status") != lv["status"]:
                            changed = await db.update_visitor_status_if_snapshot(
                                lv["id"],
                                expected_status=lv["status"],
                                expected_end_time=lv["end_time"],
                                status=uv["status"],
                            )
                            if (
                                changed
                                and uv.get("status") == 4
                                and lv["status"] != 4
                            ):
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
    # Resilience loops (idle cheaply until the app is configured)
    # ------------------------------------------------------------------

    resilience_tasks: list[asyncio.Task] = []

    if app.state.initialize_configured_state is not None:
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
                    # Refresh the schedule timezone — covers HA being down
                    # at boot (the engine would still be on its TZ-env /
                    # container-local fallback).
                    engine = app.state.auth_engine
                    if engine is not None:
                        try:
                            tz_name = await ha.get_timezone()
                            if tz_name:
                                engine.set_timezone(tz_name)
                        except Exception:
                            logger.exception("Timezone refresh after HA recovery failed")
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

        # Hub sync — bidirectionally reconciles opted-in HA locks and paired
        # Access doors. Access events wake it early; polling authenticated HA
        # state plus Access rule/relay readback catches missed events, bounds
        # drift, and confirms physical convergence.
        async def _hub_sync_loop():
            while True:
                await asyncio.sleep(HubSyncManager.POLL_INTERVAL)
                mgr = app.state.hub_sync_manager
                if mgr is None:
                    continue
                try:
                    await mgr.poll_once()
                except Exception:
                    logger.exception("Hub sync poll failed")

        resilience_tasks.append(asyncio.create_task(
            _supervised(_hub_sync_loop, name="hub-sync"),
            name="hub-sync",
        ))

        # Access cold-start supervisor. A console may still be booting when
        # this add-on starts; retry without leaking the failed aiohttp session.
        async def _access_init_loop():
            while True:
                await asyncio.sleep(60)
                client = app.state.access_client
                ws_task = getattr(client, "_ws_task", None)
                if client is not None and ws_task is not None and not ws_task.done():
                    continue
                starter = app.state.start_access_client
                if starter is None:
                    continue
                logger.info("Access client missing — attempting bring-up")
                if not await starter():
                    await asyncio.sleep(240)

        resilience_tasks.append(asyncio.create_task(
            _supervised(_access_init_loop, name="access-init"),
            name="access-init",
        ))

        # Protect cold-start supervisor — keeps retrying if UNVR Protect
        # wasn't reachable at boot. Stops polling cheaply once connected.
        async def _protect_init_loop():
            while True:
                await asyncio.sleep(60)
                client = app.state.protect_client
                ws_task = getattr(client, "_ws_task", None)
                if client is not None and ws_task is not None and not ws_task.done():
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
            while True:
                await asyncio.sleep(60)
                try:
                    enabled = (await db.get_config("reboot_enabled")) == "1"
                    if not enabled:
                        continue
                    # "Reboot at 04:00" means 04:00 in the site's timezone
                    # (was hardcoded America/New_York). The auth engine's
                    # zone tracks HA's time_zone; read it per-tick so a
                    # late HA recovery is picked up.
                    engine = app.state.auth_engine
                    tz = engine.tz if engine is not None else (
                        _dt.now(timezone.utc).astimezone().tzinfo
                    )
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
                    try:
                        await db.log_admin_action(
                            "scheduler", "scheduled_restart",
                            target=f"hour={target_hour} day={raw_day}",
                        )
                        logger.warning(
                            "Scheduled restart firing now (%s)",
                            now.isoformat(timespec="seconds"),
                        )
                        await request_service_restart()
                    except Exception:
                        # Allow a retry next minute when Supervisor rejected or
                        # was temporarily unavailable. Persist-before-request
                        # prevents a successful restart from looping again in
                        # the same target hour if the process dies immediately.
                        await db.set_config("last_reboot_fire_date", "")
                        raise
                except Exception:
                    logger.exception("Scheduled reboot loop iteration failed")

        resilience_tasks.append(asyncio.create_task(
            _supervised(_scheduled_reboot_loop, name="scheduled-reboot"),
            name="scheduled-reboot",
        ))

        for t in resilience_tasks:
            t.add_done_callback(_log_task_exception)

    # --- Hand control to FastAPI ---
    try:
        yield
    finally:
        # --- Shutdown ---
        background_tasks: list[asyncio.Task] = list(resilience_tasks)
        if visitor_sync_task is not None:
            background_tasks.append(visitor_sync_task)
        background_tasks.append(prune_task)
        for task in background_tasks:
            task.cancel()
        await asyncio.gather(*background_tasks, return_exceptions=True)

        # Stop event intake before snapshotting fire-and-forget work. Otherwise
        # a final WS callback can enqueue a physical command after the gather
        # and run against clients/SQLite while they are being closed.
        for label, client in (
            ("Protect", app.state.protect_client),
            ("Access", app.state.access_client),
        ):
            if client is None:
                continue
            stop = getattr(client, "stop_websocket", None)
            if callable(stop):
                try:
                    stop_result = stop()
                    if inspect.isawaitable(stop_result):
                        await stop_result
                except Exception:
                    logger.exception("%s WebSocket shutdown failed", label)

        # Routine door work is cancelled; critical post-event durability work
        # (remote relock persistence/fail-safe fallback) is awaited to safety.
        await _drain_event_tasks()

        # Resolve every app-owned persistent Access rule before shutting down
        # relock timers or the Access REST session. Non-lockdown shutdown
        # returns native schedule ownership; lockdown retains keep_lock.
        hub_manager = app.state.hub_sync_manager
        hub_shutdown = getattr(hub_manager, "shutdown", None)
        if callable(hub_shutdown):
            try:
                shutdown_result = hub_shutdown()
                if inspect.isawaitable(shutdown_result):
                    await shutdown_result
            except Exception:
                logger.exception("Hub sync shutdown failed; durable hold rows retained")

        relock_manager = app.state.relock_manager
        relock_shutdown = getattr(relock_manager, "shutdown", None)
        if callable(relock_shutdown):
            try:
                shutdown_result = relock_shutdown()
                if inspect.isawaitable(shutdown_result):
                    await shutdown_result
            except Exception:
                logger.exception("Relock manager shutdown failed")

        for label, client in (
            ("ProtectClient", app.state.protect_client),
            ("AccessClient", app.state.access_client),
            ("HAClient", app.state.ha_client),
        ):
            if client is None:
                continue
            try:
                close_result = client.close()
                if inspect.isawaitable(close_result):
                    await close_result
                logger.info("%s closed", label)
            except Exception:
                logger.exception("%s close failed", label)

        await db.close()
        app.state.lifecycle_cleanup_complete = True
        logger.info("Database closed")


async def _cleanup_failed_startup(app: FastAPI) -> None:
    """Best-effort cleanup when startup raises before the inner yield."""
    drain = getattr(app.state, "drain_event_tasks", None)
    if callable(drain):
        try:
            result = drain()
            if inspect.isawaitable(result):
                await result
        except Exception:
            logger.exception("Failed to drain event tasks after startup error")

    for manager_name in ("hub_sync_manager", "relock_manager"):
        manager = getattr(app.state, manager_name, None)
        shutdown = getattr(manager, "shutdown", None)
        if callable(shutdown):
            try:
                result = shutdown()
                if inspect.isawaitable(result):
                    await result
            except Exception:
                logger.exception("%s cleanup failed after startup error", manager_name)

    for label, client in (
        ("ProtectClient", getattr(app.state, "protect_client", None)),
        ("AccessClient", getattr(app.state, "access_client", None)),
        ("HAClient", getattr(app.state, "ha_client", None)),
    ):
        close = getattr(client, "close", None)
        if not callable(close):
            continue
        try:
            result = close()
            if inspect.isawaitable(result):
                await result
        except Exception:
            logger.exception("%s cleanup failed after startup error", label)

    db = getattr(app.state, "db", None)
    close_db = getattr(db, "close", None)
    if callable(close_db):
        try:
            result = close_db()
            if inspect.isawaitable(result):
                await result
        except Exception:
            logger.exception("Database cleanup failed after startup error")
    app.state.lifecycle_cleanup_complete = True


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Run startup with cleanup even when failure occurs before app yield."""
    try:
        async with _lifespan_inner(app):
            yield
    except BaseException:
        if not getattr(app.state, "lifecycle_cleanup_complete", False):
            await _cleanup_failed_startup(app)
        raise


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


@app.exception_handler(Exception)
async def _unhandled_exception_response(request: Request, exc: Exception):
    """Return a sanitized 500 with the same security headers as normal paths."""
    logger.exception("Unhandled request error", exc_info=exc)
    response = PlainTextResponse("Internal Server Error", status_code=500)
    from .ingress import _finalize_response

    return _finalize_response(request, response)


@app.get("/health/live")
async def health_live():
    """Unauthenticated liveness probe for container/load balancer health checks."""
    return {"status": "ok"}


class _IngressStaticFiles(StaticFiles):
    """StaticFiles that resolves files from the raw /static request path.

    Supervisor's ingress proxy strips the ``/api/hassio_ingress/<token>``
    prefix from the forwarded path while the ingress middleware still sets
    ``scope["root_path"]`` to that prefix so redirects and the template
    ``<base href>`` generate Ingress-safe URLs. That breaks the ASGI
    expectation that ``root_path`` is a prefix of ``path``: Starlette's
    Mount then computes a child ``root_path`` of ``<ingress>/static`` which
    strips nothing from ``/static/app.css``, so upstream ``get_path``
    resolved files as ``static/app.css`` *inside* the static directory and
    404'd every asset under Ingress (fastapi 0.139 / starlette 1.3
    exposed this; plain routes tolerate the mismatch). Compute the file
    path from the mount-relative portion of the raw path instead —
    identical to upstream normalization, immune to root_path arithmetic.
    """

    def get_path(self, scope) -> str:
        route_path = scope["path"]
        if route_path.startswith("/static"):
            route_path = route_path[len("/static"):] or "/"
        return os.path.normpath(os.path.join(*route_path.split("/")))


# Static files. Alpine's mimetypes table has no woff2 entry, so register it
# before the mount guesses content types — fonts otherwise serve as
# application/octet-stream.
mimetypes.add_type("font/woff2", ".woff2")
app.mount(
    "/static", _IngressStaticFiles(directory=str(_HERE / "static")), name="static"
)

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
# invariant. The ingress boundary also finalizes security/cache headers so
# even setup redirects and auth rejections receive them.


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
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        # Enforce the boundary for every write endpoint, including unauthenticated
        # /login and /setup and Bearer-authenticated /api routes. Stream until
        # the cap rather than trusting Content-Length, which also safely handles
        # chunked requests without buffering an unbounded body.
        raw_content_length = request.headers.get("content-length")
        if raw_content_length:
            try:
                content_length = int(raw_content_length)
            except ValueError:
                from fastapi.responses import HTMLResponse

                return HTMLResponse("<h1>400 Bad Request</h1>", status_code=400)
            if content_length < 0:
                from fastapi.responses import HTMLResponse

                return HTMLResponse("<h1>400 Bad Request</h1>", status_code=400)
            if content_length > _MAX_FORM_BODY:
                from fastapi.responses import HTMLResponse

                return HTMLResponse(
                    "<h1>413 Payload Too Large</h1>"
                    "<p>Request body exceeds the submission size limit.</p>",
                    status_code=413,
                )

        chunks: list[bytes] = []
        size = 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > _MAX_FORM_BODY:
                from fastapi.responses import HTMLResponse

                return HTMLResponse(
                    "<h1>413 Payload Too Large</h1>"
                    "<p>Request body exceeds the submission size limit.</p>",
                    status_code=413,
                )
            chunks.append(chunk)
        body = b"".join(chunks)
        request._body = body

        async def receive_body():
            return {"type": "http.request", "body": body, "more_body": False}

        request._receive = receive_body

    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
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
                from urllib.parse import parse_qs
                try:
                    parsed = parse_qs(body.decode(), keep_blank_values=True)
                except UnicodeDecodeError:
                    from fastapi.responses import HTMLResponse

                    return HTMLResponse("<h1>400 Bad Request</h1>", status_code=400)
                token = parsed.get("_csrf_token", [""])[0]
                if not validate_csrf_token(token, user):
                    from fastapi.responses import HTMLResponse
                    return HTMLResponse(
                        "<h1>403 Forbidden</h1><p>Invalid CSRF token. "
                        '<a href="javascript:history.back()">Go back</a></p>',
                        status_code=403,
                    )
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
