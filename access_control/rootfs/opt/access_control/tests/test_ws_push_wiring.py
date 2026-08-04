"""HA state_changed push wiring in main.py (review recommendation CLI-6).

Covers the small, testable seams main.py exposes for the push feature:

- ``_hub_sync_poll_interval`` — the hub-sync loop relaxes to the 60s
  backstop cadence only while BOTH ``ha.ws_connected`` (push feed) and
  ``ha.connected`` (REST — the manager's HA-outage fail-safe keys on it)
  are healthy AND the manager reports no pending deferred/backoff work;
  it degrades to full 5s polling for absent clients, a down websocket OR
  a down REST client, older/fake clients that expose neither attribute,
  and whenever ``manager.has_pending_work()`` is truthy.
- ``_make_ha_state_changed_callback`` — the state_changed callback filters
  to the ``lock.`` domain only (alarm panels are deliberately NOT push
  wired), resolves the hub sync manager lazily off ``app.state``, and is
  safe when the manager is absent (unconfigured / not yet brought up).
- ``_register_ha_websocket`` — best-effort, getattr-guarded registration
  that never propagates client failures into startup or the health loop.

The HA client is always faked here: the real websocket implementation
lives in ha_client.py and is exercised by its own tests. These tests rely
only on the documented contract (sync idempotent ``start_websocket``,
``ws_connected`` bool).
"""
from __future__ import annotations

import asyncio
import importlib
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

ROOT = Path(__file__).resolve().parents[1]


def _load_package() -> None:
    if "access_control" in sys.modules:
        return
    spec = importlib.util.spec_from_file_location(
        "access_control",
        ROOT / "__init__.py",
        submodule_search_locations=[str(ROOT)],
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["access_control"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)


def _deps_available() -> bool:
    """main.py imports fastapi/aiohttp/aiosqlite — skip when unimportable."""
    for name in ("fastapi", "aiohttp", "aiosqlite"):
        try:
            if importlib.util.find_spec(name) is None:
                return False
        except ValueError:
            return False
    return True


def _reload_main():
    """(Re)load access_control.main against a scratch DATA_DIR.

    Mirrors test_event_dispatch: only database.py captures DATA_DIR at
    import and main.py owns the app singleton built around it, so those two
    are reloaded; everything else is imported normally to keep exception
    class identities stable across the collected suite.
    """
    _load_package()
    for name in ("access_control.database", "access_control.main"):
        if name in sys.modules:
            importlib.reload(sys.modules[name])
        else:
            importlib.import_module(name)
    return sys.modules["access_control.main"]


@unittest.skipIf(
    not _deps_available(),
    "fastapi/aiohttp/aiosqlite not importable in this environment",
)
class WsPushWiringTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self._old_data_dir = os.environ.get("DATA_DIR")
        os.environ["DATA_DIR"] = self.tempdir.name
        self.main = _reload_main()
        self.HubSyncManager = importlib.import_module(
            "access_control.hub_sync"
        ).HubSyncManager

    def tearDown(self) -> None:
        if self._old_data_dir is None:
            os.environ.pop("DATA_DIR", None)
        else:
            os.environ["DATA_DIR"] = self._old_data_dir
        self.tempdir.cleanup()

    # ------------------------------------------------------------------
    # _hub_sync_poll_interval
    # ------------------------------------------------------------------

    def test_interval_is_backstop_only_while_ws_and_rest_healthy(self) -> None:
        interval = self.main._hub_sync_poll_interval
        self.assertEqual(
            interval(SimpleNamespace(ws_connected=True, connected=True)),
            self.HubSyncManager.BACKSTOP_POLL_INTERVAL,
        )
        self.assertEqual(
            interval(SimpleNamespace(ws_connected=False, connected=True)),
            self.HubSyncManager.POLL_INTERVAL,
        )

    def test_interval_stays_fast_when_rest_is_down(self) -> None:
        # WIR-2c: the manager's HA-outage fail-safe keys on REST
        # ``connected`` — a 401/circuit-open flips REST down while the
        # authenticated WS stays up. Held-open doors must then fail safe
        # on the fast cadence, never once a minute.
        interval = self.main._hub_sync_poll_interval
        self.assertEqual(
            interval(SimpleNamespace(ws_connected=True, connected=False)),
            self.HubSyncManager.POLL_INTERVAL,
        )
        self.assertEqual(
            interval(SimpleNamespace(ws_connected=True, connected=None)),
            self.HubSyncManager.POLL_INTERVAL,
        )
        # WS present but no REST attribute at all: fail fast, not slow.
        self.assertEqual(
            interval(SimpleNamespace(ws_connected=True)),
            self.HubSyncManager.POLL_INTERVAL,
        )

    def test_interval_values_are_60_and_5(self) -> None:
        interval = self.main._hub_sync_poll_interval
        self.assertEqual(
            interval(SimpleNamespace(ws_connected=True, connected=True)), 60.0
        )
        self.assertEqual(
            interval(SimpleNamespace(ws_connected=False, connected=True)), 5.0
        )

    def test_interval_defaults_to_fast_poll_without_client(self) -> None:
        self.assertEqual(
            self.main._hub_sync_poll_interval(None),
            self.HubSyncManager.POLL_INTERVAL,
        )

    def test_interval_degrades_for_client_without_ws_attribute(self) -> None:
        # Older/fake clients (plain object exposes no ws_connected) must
        # keep the full 5s polling cadence.
        self.assertEqual(
            self.main._hub_sync_poll_interval(object()),
            self.HubSyncManager.POLL_INTERVAL,
        )

    def test_interval_treats_truthy_falsy_ws_connected_correctly(self) -> None:
        interval = self.main._hub_sync_poll_interval
        self.assertEqual(
            interval(SimpleNamespace(ws_connected=None, connected=True)),
            self.HubSyncManager.POLL_INTERVAL,
        )

    def _healthy_ha(self):
        return SimpleNamespace(ws_connected=True, connected=True)

    def test_interval_stays_fast_while_manager_has_pending_work(self) -> None:
        # WIR-2b/2d: deferred/backoff work resumes only on a pass and
        # produces no push event — the backstop may engage only when the
        # manager is idle.
        interval = self.main._hub_sync_poll_interval
        manager = SimpleNamespace(has_pending_work=lambda: True)
        self.assertEqual(
            interval(self._healthy_ha(), manager),
            self.HubSyncManager.POLL_INTERVAL,
        )
        manager = SimpleNamespace(has_pending_work=lambda: False)
        self.assertEqual(
            interval(self._healthy_ha(), manager),
            self.HubSyncManager.BACKSTOP_POLL_INTERVAL,
        )

    def test_interval_backstop_when_manager_absent_or_legacy(self) -> None:
        # No manager yet (pre-lifespan) or an injected manager without
        # has_pending_work: nothing to consult, healthy client → backstop.
        interval = self.main._hub_sync_poll_interval
        self.assertEqual(
            interval(self._healthy_ha(), None),
            self.HubSyncManager.BACKSTOP_POLL_INTERVAL,
        )
        self.assertEqual(
            interval(self._healthy_ha(), object()),
            self.HubSyncManager.BACKSTOP_POLL_INTERVAL,
        )

    def test_interval_fails_fast_when_has_pending_work_raises(self) -> None:
        def boom():
            raise RuntimeError("broken manager")

        self.assertEqual(
            self.main._hub_sync_poll_interval(
                self._healthy_ha(), SimpleNamespace(has_pending_work=boom)
            ),
            self.HubSyncManager.POLL_INTERVAL,
        )

    def test_interval_with_real_manager_pending_work(self) -> None:
        """End-to-end with a REAL HubSyncManager: idle → backstop; pending
        deferred work (a queued hub release) → fast cadence."""
        mgr = self.HubSyncManager(
            db=MagicMock(),
            ha_client_getter=lambda: None,
            access_client_getter=lambda: None,
        )
        self.assertEqual(
            self.main._hub_sync_poll_interval(self._healthy_ha(), mgr),
            self.HubSyncManager.BACKSTOP_POLL_INTERVAL,
        )
        mgr._pending_release["lock.front"] = [{"device_id": "dev-hub-1"}]
        self.assertEqual(
            self.main._hub_sync_poll_interval(self._healthy_ha(), mgr),
            self.HubSyncManager.POLL_INTERVAL,
        )

    # ------------------------------------------------------------------
    # _make_ha_state_changed_callback
    # ------------------------------------------------------------------

    def _app_with_manager(self, manager):
        return SimpleNamespace(state=SimpleNamespace(hub_sync_manager=manager))

    def test_callback_notifies_manager_for_lock_entities(self) -> None:
        manager = MagicMock()
        app = self._app_with_manager(manager)
        cb = self.main._make_ha_state_changed_callback(app)
        asyncio.run(cb("lock.front", "locked", "unlocked"))
        manager.notify_ha_state_change.assert_called_once_with(
            "lock.front", "unlocked"
        )

    def test_callback_ignores_non_lock_domains(self) -> None:
        manager = MagicMock()
        app = self._app_with_manager(manager)
        cb = self.main._make_ha_state_changed_callback(app)

        async def go():
            # Alarm panels are read by the auth engine via DB-configured
            # panels — deliberately NOT push-wired (locks only).
            await cb("alarm_control_panel.home", "armed_away", "disarmed")
            await cb("binary_sensor.front_door", "off", "on")
            await cb("sensor.lock_battery", "90", "89")
            await cb("locker.not_a_lock", "a", "b")
            await cb("", None, None)
            await cb(None, None, "unlocked")

        asyncio.run(go())
        manager.notify_ha_state_change.assert_not_called()

    def test_callback_safe_when_manager_absent(self) -> None:
        # Manager still None (feature disabled / not yet initialized).
        cb = self.main._make_ha_state_changed_callback(
            self._app_with_manager(None)
        )
        asyncio.run(cb("lock.front", "locked", "unlocked"))
        # app.state without the attribute at all (pre-lifespan) is also safe.
        bare = SimpleNamespace(state=SimpleNamespace())
        cb2 = self.main._make_ha_state_changed_callback(bare)
        asyncio.run(cb2("lock.front", "locked", "unlocked"))

    def test_callback_reaches_real_manager_notify(self) -> None:
        """End-to-end through a REAL HubSyncManager: a tracked lock's push
        event schedules a coalesced poll pass; an untracked one does not."""
        async def go():
            db = MagicMock()
            mgr = self.HubSyncManager(
                db=db,
                ha_client_getter=lambda: None,
                access_client_getter=lambda: None,
            )
            polls = []

            async def fake_poll():
                polls.append(1)
                return 0

            mgr.poll_once = fake_poll
            mgr._applied["lock.front"] = "locked"
            app = self._app_with_manager(mgr)
            cb = self.main._make_ha_state_changed_callback(app)

            await cb("lock.unknown", "locked", "unlocked")
            self.assertIsNone(mgr._push_reconcile_task)

            await cb("lock.front", "locked", "unlocked")
            task = mgr._push_reconcile_task
            self.assertIsNotNone(task)
            await task
            self.assertEqual(len(polls), 1)
        asyncio.run(go())

    # ------------------------------------------------------------------
    # Lock-settings save → request_reconcile (WIR-3)
    # ------------------------------------------------------------------

    def _settings_request(self, app_state_kwargs):
        db = SimpleNamespace(
            consume_rate_limit=AsyncMock(return_value=True),
            update_lock_settings=AsyncMock(),
        )
        request = SimpleNamespace(
            headers={},
            scope={},
            state=SimpleNamespace(ingress_user=None, ingress_active=False),
            client=SimpleNamespace(host="127.0.0.1"),
            app=SimpleNamespace(
                state=SimpleNamespace(db=db, **app_state_kwargs)
            ),
        )
        return request, db

    def test_lock_settings_save_kicks_coalesced_reconcile(self) -> None:
        # A runtime sync_hub_state toggle produces no HA push event; with
        # the WS-healthy backstop at 60s the save path itself must wake a
        # coalesced reconcile so the change converges within ~one pass.
        web_routes = importlib.import_module("access_control.web_routes")
        manager = MagicMock()
        request, db = self._settings_request({"hub_sync_manager": manager})
        response = asyncio.run(
            web_routes.update_lock_settings(
                5,
                request,
                buzz_enabled="",
                relock_duration=30,
                relock_on_remote="",
                relock_on_device_auth="",
                sync_hub_state="on",
                relock_on_ha_origin="",
                preserve_hold_on_restart="",
                user="admin",
            )
        )
        self.assertEqual(response.status_code, 303)
        db.update_lock_settings.assert_awaited_once()
        manager.request_reconcile.assert_called_once_with()
        # The wake happens strictly AFTER the settings row is persisted.

    def test_lock_settings_save_safe_without_manager(self) -> None:
        web_routes = importlib.import_module("access_control.web_routes")
        # Manager still None (feature not brought up).
        request, db = self._settings_request({"hub_sync_manager": None})
        response = asyncio.run(
            web_routes.update_lock_settings(
                5,
                request,
                buzz_enabled="",
                relock_duration=30,
                relock_on_remote="",
                relock_on_device_auth="",
                sync_hub_state="on",
                relock_on_ha_origin="",
                preserve_hold_on_restart="",
                user="admin",
            )
        )
        self.assertEqual(response.status_code, 303)
        db.update_lock_settings.assert_awaited_once()
        # app.state without the attribute at all (pre-lifespan) is safe too.
        request, db = self._settings_request({})
        response = asyncio.run(
            web_routes.update_lock_settings(
                5,
                request,
                buzz_enabled="",
                relock_duration=30,
                relock_on_remote="",
                relock_on_device_auth="",
                sync_hub_state="",
                relock_on_ha_origin="",
                preserve_hold_on_restart="",
                user="admin",
            )
        )
        self.assertEqual(response.status_code, 303)
        db.update_lock_settings.assert_awaited_once()

    # ------------------------------------------------------------------
    # _register_ha_websocket
    # ------------------------------------------------------------------

    def test_register_passes_callback_and_is_best_effort(self) -> None:
        register = self.main._register_ha_websocket

        async def cb(entity_id, old_state, new_state):
            return None

        client = MagicMock()
        register(client, cb)
        client.start_websocket.assert_called_once_with(cb)

        # No client / no callback / no start_websocket support: no-ops.
        register(None, cb)
        register(client, None)
        client.start_websocket.assert_called_once()
        register(object(), cb)  # older client without websocket support

        # A raising client must never propagate into startup/health loop.
        failing = MagicMock()
        failing.start_websocket.side_effect = RuntimeError("ws down")
        register(failing, cb)


if __name__ == "__main__":
    unittest.main()
