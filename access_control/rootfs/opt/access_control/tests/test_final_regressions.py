"""Focused regressions for the final end-to-end review pass.

These tests intentionally exercise safety boundaries rather than internal
implementation details: hidden authorization targets, durable pre-unlock
relocks, visitor lifecycle checks, alarm auditability, atomic configuration,
and startup wiring shared by the physical-command managers.
"""
from __future__ import annotations

import asyncio
import time
import tempfile
import unittest
from contextlib import asynccontextmanager
from datetime import timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from access_control import api_routes, lock_actions, main as main_module, web_routes
from access_control.auth_engine import AuthEngine
from access_control.config import derive_key, encrypt_value
from access_control.database import Database
from access_control.hub_sync import HubSyncManager


def _request(
    *,
    db,
    access=None,
    ha=None,
    auth_engine=None,
    relock_manager=None,
    enc_key=None,
    **state_values,
):
    state_data = dict(
        db=db,
        access_client=access,
        ha_client=ha,
        auth_engine=auth_engine,
        relock_manager=relock_manager,
        enc_key=enc_key,
        lock_states={},
        physical_command_lock=None,
    )
    state_data.update(state_values)
    state = SimpleNamespace(**state_data)
    return SimpleNamespace(
        app=SimpleNamespace(state=state),
        state=SimpleNamespace(ingress_user=None, ingress_active=False),
        scope={},
        headers={},
        client=SimpleNamespace(host="127.0.0.1"),
    )


class HiddenLockResolutionTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def _hidden_lock() -> dict:
        return {
            "id": 91,
            "type": "ha_external",
            "entity_id": "lock.hidden_side_door",
            "name": "Hidden side door",
            "hidden": 1,
        }

    async def test_hidden_ha_lock_is_excluded_from_access_reader_mapping(self) -> None:
        hidden = self._hidden_lock()
        db = SimpleNamespace(
            get_locks_for_location=AsyncMock(return_value=[]),
            get_locks_by_entry_device=AsyncMock(
                side_effect=lambda kind, **kwargs: [hidden]
                if kind == "access_reader"
                else []
            ),
        )
        engine = AuthEngine(
            db=db,
            access_client=None,
            ha_client=None,
            relock_tasks={},
        )

        self.assertEqual(await engine.get_locks_for_location("door-side"), [])

    async def test_hidden_ha_lock_is_excluded_from_doorbell_mapping(self) -> None:
        hidden = self._hidden_lock()

        async def paired(kind, **kwargs):
            if kind == "protect_doorbell" and kwargs.get("device_id") == "cam-side":
                return [hidden]
            return []

        db = SimpleNamespace(
            get_locks_for_location=AsyncMock(return_value=[]),
            get_locks_by_entry_device=AsyncMock(side_effect=paired),
        )
        engine = AuthEngine(
            db=db,
            access_client=None,
            ha_client=None,
            relock_tasks={},
            camera_map_getter=lambda: {"cam-side": "door-side"},
        )

        self.assertEqual(await engine.get_locks_for_location("door-side"), [])

    async def test_hub_pairing_may_include_hidden_native_hub(self) -> None:
        native = {
            "id": 22,
            "type": "access_native",
            "device_id": "hub-22",
            "location_id": "door-side",
            "name": "Hidden native hub",
            "hidden": 1,
        }
        db = SimpleNamespace(
            get_entry_devices_for_locks=AsyncMock(
                return_value={7: [{
                    "type": "access_reader",
                    "device_id": "door-side",
                }]}
            ),
            get_locks_for_location=AsyncMock(return_value=[native]),
        )
        manager = HubSyncManager(
            db=db,
            ha_client_getter=lambda: None,
            access_client_getter=lambda: None,
        )

        hubs = await manager._resolve_hub_locks({"id": 7})

        self.assertEqual(hubs, [native])
        db.get_locks_for_location.assert_awaited_once_with(
            "door-side", include_hidden=True
        )


class HubFailSafeDirectionTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def _fixtures():
        external = {
            "id": 7,
            "type": "ha_external",
            "entity_id": "lock.front",
            "name": "Front deadbolt",
            "access_location_id": "door-front",
            "sync_hub_state": 1,
            "hidden": 0,
        }
        hub = {
            "id": 8,
            "type": "access_native",
            "device_id": "hub-front",
            "location_id": "door-front",
            "name": "Front hub",
            "hidden": 0,
        }
        db = SimpleNamespace(
            get_all_locks=AsyncMock(return_value=[external, hub]),
            get_locks_for_location=AsyncMock(return_value=[hub]),
            get_entry_devices_for_locks=AsyncMock(return_value={}),
            record_hub_sync_hold=AsyncMock(),
            clear_hub_sync_hold=AsyncMock(),
            get_hub_sync_holds=AsyncMock(return_value=[]),
            log_access=AsyncMock(),
        )
        states = {"lock.front": "unlocked"}
        ha = SimpleNamespace(
            connected=True,
            get_entity_state=AsyncMock(
                side_effect=lambda entity_id: states.get(entity_id)
            ),
            fire_event=AsyncMock(return_value=True),
        )
        access = SimpleNamespace(
            connected=True,
            unlock_persistent=AsyncMock(),
            lock=AsyncMock(),
        )
        manager = HubSyncManager(
            db=db,
            ha_client_getter=lambda: ha,
            access_client_getter=lambda: access,
        )
        return manager, db, ha, access, states

    async def test_disconnect_or_unknown_state_resets_owned_hold(self) -> None:
        for mode in ("disconnected", "unknown"):
            with self.subTest(mode=mode):
                manager, db, ha, access, states = self._fixtures()
                await manager.poll_once()
                access.unlock_persistent.assert_awaited_once_with("hub-front")

                if mode == "disconnected":
                    ha.connected = False
                else:
                    states["lock.front"] = "unknown"

                await manager.poll_once()

                access.lock.assert_awaited_once_with("hub-front")
                self.assertFalse(manager._held_open.get("lock.front"))
                self.assertTrue(manager._held_locked.get("lock.front"))
                db.record_hub_sync_hold.assert_awaited_with(
                    "lock.front",
                    "hub-front",
                    8,
                    "Front hub",
                    hub_location_id="door-front",
                    override_type="keep_lock",
                )
                db.clear_hub_sync_hold.assert_not_awaited()

    async def test_locked_transition_bypasses_unsafe_backoff_and_damping(self) -> None:
        manager, _db, _ha, access, states = self._fixtures()
        await manager.poll_once()
        states["lock.front"] = "locked"

        # Every normal hold-open throttle is active. None may delay the safe
        # close direction once HA authoritatively reports locked.
        future = time.monotonic() + 3_600
        manager._backoff_until["lock.front"] = future
        manager._suspended_until["lock.front"] = future
        manager._last_applied_at["lock.front"] = time.monotonic()
        manager._apply_times["lock.front"] = [time.monotonic()] * 100

        self.assertEqual(await manager.poll_once(), 1)
        access.lock.assert_awaited_once_with("hub-front")
        self.assertFalse(manager._held_open.get("lock.front"))


class VisitorLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def _extend(self, visitor: dict):
        db = SimpleNamespace(
            consume_rate_limit=AsyncMock(return_value=True),
            get_visitor=AsyncMock(return_value=visitor),
            update_visitor_end_time=AsyncMock(),
            update_active_visitor_end_time=AsyncMock(return_value=True),
            log_admin_action=AsyncMock(),
        )
        access = SimpleNamespace(update_visitor=AsyncMock())
        response = await web_routes.extend_visitor(
            visitor["id"],
            _request(db=db, access=access),
            user="admin",
            end_date="2999-12-31",
            end_time="23:59",
        )
        return response, db, access

    async def test_non_active_visitor_is_rejected_before_upstream_update(self) -> None:
        response, db, access = await self._extend({
            "id": 7,
            "name": "Deleted visitor",
            "unvr_visitor_id": "visitor-7",
            "status": 4,
            "start_time": "2026-01-01T10:00:00+00:00",
            "end_time": "2999-01-01T10:00:00+00:00",
        })

        self.assertEqual(response.status_code, 303)
        access.update_visitor.assert_not_awaited()
        db.update_visitor_end_time.assert_not_awaited()

    async def test_locally_expired_visitor_is_rejected_before_upstream_update(self) -> None:
        response, db, access = await self._extend({
            "id": 8,
            "name": "Expired visitor",
            "unvr_visitor_id": "visitor-8",
            "status": 1,
            "start_time": "2020-01-01T10:00:00+00:00",
            "end_time": "2020-01-02T10:00:00+00:00",
        })

        self.assertEqual(response.status_code, 303)
        access.update_visitor.assert_not_awaited()
        db.update_visitor_end_time.assert_not_awaited()


class VisitorSnapshotCasTests(unittest.IsolatedAsyncioTestCase):
    async def test_stale_sync_snapshot_cannot_overwrite_extended_visitor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(path=Path(tmp) / "visitor-cas.db")
            await db.connect()
            try:
                old_end = "2026-07-12T12:00:00+00:00"
                new_end = "2026-07-13T12:00:00+00:00"
                visitor_id = await db.add_visitor(
                    "visitor-cas",
                    "CAS Visitor",
                    "2026-07-12T10:00:00+00:00",
                    old_end,
                    status=1,
                )

                # A user extension lands after the sync loop took its old
                # status/end-time snapshot.
                self.assertTrue(
                    await db.update_active_visitor_end_time(
                        visitor_id,
                        new_end,
                        expected_end_time=old_end,
                    )
                )
                upstream_change = await db.update_visitor_status_if_snapshot(
                    visitor_id,
                    expected_status=1,
                    expected_end_time=old_end,
                    status=4,
                )
                local_expiry = await db.expire_active_visitor(
                    visitor_id, old_end
                )

                self.assertFalse(upstream_change)
                self.assertFalse(local_expiry)
                current = await db.get_visitor(visitor_id)
                self.assertEqual(current["status"], 1)
                self.assertEqual(current["end_time"], new_end)
            finally:
                await db.close()


class IsolatedSafetyWriteTests(unittest.IsolatedAsyncioTestCase):
    async def test_primary_rollback_cannot_erase_concurrent_safety_ownership(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(path=Path(tmp) / "isolated-safety.db")
            await db.connect()
            try:
                # Hold an unrelated write open on the shared request
                # connection. Durable safety writes should wait, then commit
                # on connections whose transaction ownership is independent
                # of this rollback.
                await db._db.execute(
                    "INSERT INTO config(key, value) VALUES (?, ?)",
                    ("uncommitted-request", "discard-me"),
                )
                relock_write = asyncio.create_task(
                    db.add_pending_relock(
                        "lock.front",
                        4,
                        "Front",
                        "buzz",
                        deadline=1234.0,
                        now=1200.0,
                    )
                )
                hold_write = asyncio.create_task(
                    db.record_hub_sync_hold(
                        "lock.front",
                        "hub-front",
                        5,
                        "Front hub",
                        now=1200.0,
                    )
                )
                await asyncio.sleep(0.05)
                await db.rollback()
                await asyncio.gather(relock_write, hold_write)

                # The shared connection is intentionally autocommit: a
                # rollback in another coroutine cannot capture this write.
                self.assertEqual(
                    await db.get_config("uncommitted-request"), "discard-me"
                )
                relock = await db.get_pending_relock("lock.front")
                self.assertEqual(relock["deadline"], 1234.0)
                holds = await db.get_hub_sync_holds()
                self.assertEqual(
                    [(row["entity_id"], row["hub_device_id"]) for row in holds],
                    [("lock.front", "hub-front")],
                )
            finally:
                await db.close()

class ManualAlarmActionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.enc_key = derive_key("alarm-test-secret", b"0123456789abcdef")
        self.panel = {
            "id": 3,
            "entity_id": "alarm_control_panel.house",
            "name": "House",
            "disarm_code_encrypted": encrypt_value("2468", self.enc_key),
        }

    @staticmethod
    def _audit_text(mock: AsyncMock) -> str:
        call = mock.await_args
        return " ".join(
            str(value)
            for value in (*call.args, *call.kwargs.values())
            if value is not None
        ).lower()

    async def test_arm_and_disarm_actions_pass_code_and_write_success_audit(self) -> None:
        routes = (
            ("arm_away", web_routes.alarm_arm_away, "alarm_arm_away"),
            ("arm_home", web_routes.alarm_arm_home, "alarm_arm_home"),
            ("disarm", web_routes.alarm_disarm, "alarm_disarm"),
        )
        for label, route, method_name in routes:
            with self.subTest(action=label):
                db = SimpleNamespace(
                    consume_rate_limit=AsyncMock(return_value=True),
                    get_all_alarm_panels=AsyncMock(return_value=[self.panel]),
                    log_admin_action=AsyncMock(),
                )
                action = AsyncMock(return_value=True)
                ha = SimpleNamespace(**{method_name: action})

                await route(
                    3,
                    _request(db=db, ha=ha, enc_key=self.enc_key),
                    user="admin",
                )

                action.assert_awaited_once_with(
                    "alarm_control_panel.house", code="2468"
                )
                db.log_admin_action.assert_awaited_once()
                audit = self._audit_text(db.log_admin_action)
                self.assertIn("admin", audit)
                self.assertIn(label, audit)
                self.assertIn("alarm_control_panel.house", audit)
                self.assertIn("success", audit)

    async def test_failed_alarm_action_is_audited_as_failure(self) -> None:
        db = SimpleNamespace(
            consume_rate_limit=AsyncMock(return_value=True),
            get_all_alarm_panels=AsyncMock(return_value=[self.panel]),
            log_admin_action=AsyncMock(),
        )
        ha = SimpleNamespace(alarm_arm_home=AsyncMock(return_value=False))

        await web_routes.alarm_arm_home(
            3,
            _request(db=db, ha=ha, enc_key=self.enc_key),
            user="admin",
        )

        db.log_admin_action.assert_awaited_once()
        audit = self._audit_text(db.log_admin_action)
        self.assertIn("arm_home", audit)
        self.assertIn("fail", audit)

    async def test_failed_manual_auto_disarm_is_not_logged_as_success(self) -> None:
        lock = {
            "id": 4,
            "type": "ha_external",
            "entity_id": "lock.front",
            "name": "Front Door",
            "buzz_enabled": 1,
        }
        db = SimpleNamespace(
            get_lock=AsyncMock(return_value=lock),
            get_all_alarm_panels=AsyncMock(return_value=[self.panel]),
            log_access=AsyncMock(),
        )
        ha = SimpleNamespace(
            unlock=AsyncMock(return_value=True),
            get_entity_state=AsyncMock(return_value="unlocked"),
            alarm_disarm=AsyncMock(return_value=False),
        )

        with self.assertLogs(lock_actions.logger, level="INFO") as captured:
            await web_routes._lock_action(
                4,
                "unlock",
                "admin",
                _request(db=db, ha=ha, enc_key=self.enc_key),
            )

        messages = "\n".join(captured.output).lower()
        self.assertIn("failure", messages)
        self.assertNotIn("auto-disarmed alarm_control_panel.house", messages)


class DurablePreUnlockIntentTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def _manager(intent):
        return SimpleNamespace(
            schedule=AsyncMock(return_value=intent),
            retain_after_uncertain_unlock=AsyncMock(return_value=True),
            pause=AsyncMock(return_value=None),
            resume=AsyncMock(),
            cancel=AsyncMock(),
        )

    async def test_auth_engine_persists_intent_before_false_unlock_and_retains(self) -> None:
        intent = object()
        manager = self._manager(intent)

        async def failed_unlock(_entity_id):
            self.assertEqual(manager.schedule.await_count, 1)
            return False

        ha = SimpleNamespace(unlock=AsyncMock(side_effect=failed_unlock))
        engine = AuthEngine(
            db=SimpleNamespace(),
            access_client=None,
            ha_client=ha,
            relock_manager=manager,
        )
        lock = {
            "id": 10,
            "type": "ha_external",
            "entity_id": "lock.front",
            "name": "Front",
            "relock_on_device_auth": 1,
            "relock_duration": 30,
        }

        with self.assertRaises(RuntimeError):
            await engine._unlock(lock)

        manager.schedule.assert_awaited_once_with(
            entity_id="lock.front",
            duration=30,
            lock_id=10,
            lock_name="Front",
            source="device_auth",
        )
        manager.retain_after_uncertain_unlock.assert_awaited_once_with(intent)

    async def test_auth_engine_retains_intent_when_unlock_raises(self) -> None:
        intent = object()
        manager = self._manager(intent)

        async def raised_unlock(_entity_id):
            self.assertEqual(manager.schedule.await_count, 1)
            raise OSError("HA transport failed")

        engine = AuthEngine(
            db=SimpleNamespace(),
            access_client=None,
            ha_client=SimpleNamespace(unlock=AsyncMock(side_effect=raised_unlock)),
            relock_manager=manager,
        )
        lock = {
            "id": 11,
            "type": "ha_external",
            "entity_id": "lock.back",
            "name": "Back",
            "relock_on_device_auth": 1,
            "relock_duration": 45,
        }

        with self.assertRaises(OSError):
            await engine._unlock(lock)

        manager.retain_after_uncertain_unlock.assert_awaited_once_with(intent)

    async def _manual_buzz(self, unlock_side_effect):
        intent = object()
        manager = self._manager(intent)

        async def guarded_unlock(entity_id):
            self.assertEqual(manager.schedule.await_count, 1)
            return await unlock_side_effect(entity_id)

        lock = {
            "id": 12,
            "type": "ha_external",
            "entity_id": "lock.side",
            "name": "Side",
            "buzz_enabled": 1,
            "relock_duration": 20,
        }
        db = SimpleNamespace(
            get_lock=AsyncMock(return_value=lock),
            get_all_alarm_panels=AsyncMock(return_value=[]),
            log_access=AsyncMock(),
        )
        ha = SimpleNamespace(
            unlock=AsyncMock(side_effect=guarded_unlock),
            alarm_disarm=AsyncMock(return_value=True),
        )
        await web_routes._lock_action(
            12,
            "buzz",
            "admin",
            _request(db=db, ha=ha, relock_manager=manager),
        )
        return manager, intent

    async def test_manual_buzz_retains_prepared_intent_on_false_unlock(self) -> None:
        async def failed(_entity_id):
            return False

        manager, intent = await self._manual_buzz(failed)

        manager.schedule.assert_awaited_once()
        manager.retain_after_uncertain_unlock.assert_awaited_once_with(intent)

    async def test_manual_buzz_retains_prepared_intent_when_unlock_raises(self) -> None:
        async def raised(_entity_id):
            raise OSError("HA transport failed")

        manager, intent = await self._manual_buzz(raised)

        manager.schedule.assert_awaited_once()
        manager.retain_after_uncertain_unlock.assert_awaited_once_with(intent)


class ExplicitLockdownApiTests(unittest.TestCase):
    def test_lockdown_requires_and_repeats_explicit_desired_state(self) -> None:
        app = FastAPI()
        app.include_router(api_routes.router)

        class Engine:
            lockdown = False

            def __init__(self):
                self.values: list[bool] = []

            async def set_lockdown(self, enabled: bool) -> None:
                self.values.append(enabled)
                self.lockdown = enabled

        engine = Engine()
        db = SimpleNamespace(log_admin_action=AsyncMock())
        app.state.auth_engine = engine
        app.state.db = db
        app.dependency_overrides[api_routes.verify_api_key] = lambda: {
            "key_id": 7,
            "name": "incident-automation",
            "scope": "full",
        }

        with TestClient(app) as client:
            self.assertEqual(client.post("/api/lockdown").status_code, 422)
            first = client.post("/api/lockdown?enabled=true")
            repeated = client.post("/api/lockdown?enabled=true")
            disabled = client.post("/api/lockdown?enabled=false")

        self.assertEqual(first.json(), {"lockdown": True})
        self.assertEqual(repeated.json(), {"lockdown": True})
        self.assertEqual(disabled.json(), {"lockdown": False})
        self.assertEqual(engine.values, [True, True, False])
        self.assertEqual(db.log_admin_action.await_count, 3)
        db.log_admin_action.assert_any_await(
            "api:incident-automation#7",
            "api_lockdown_set",
            "enabled",
            "result=success",
        )
        db.log_admin_action.assert_any_await(
            "api:incident-automation#7",
            "api_lockdown_set",
            "disabled",
            "result=success",
        )


class _CandidateConsole:
    def __init__(self) -> None:
        self.connected = True
        self.open_api_configured = False
        self.login = AsyncMock()
        self.validate_open_api = AsyncMock(return_value=False)
        self.close = AsyncMock()
        self.start_websocket = AsyncMock()
        self.stop_websocket = MagicMock()
        self.register_callback = MagicMock()
        self.get_console_identity = AsyncMock(return_value="site-identity")
        self.verify_console_identity = AsyncMock(return_value="site-identity")


class AtomicConfigBundleTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def _config_db(**values):
        defaults = dict(
            get_config=AsyncMock(return_value=None),
            consume_rate_limit=AsyncMock(return_value=True),
            clear_rate_limit=AsyncMock(),
            set_config=AsyncMock(),
            set_configs=AsyncMock(),
            log_admin_action=AsyncMock(),
        )
        defaults.update(values)
        return SimpleNamespace(**defaults)

    async def test_setup_persists_one_atomic_config_bundle(self) -> None:
        db = self._config_db()
        request = _request(
            db=db,
            configured=False,
            initialize_configured_state=AsyncMock(),
        )
        protect = _CandidateConsole()
        access = _CandidateConsole()
        access.get_console_identity = AsyncMock(return_value="site-identity")
        ha = SimpleNamespace(
            test_connection=AsyncMock(return_value=True),
            close=AsyncMock(),
        )

        with patch.object(web_routes, "_supervisor_proxy_active", return_value=False), \
             patch.object(web_routes, "ProtectClient", return_value=protect), \
             patch.object(web_routes, "AccessClient", return_value=access), \
             patch.object(web_routes, "HAClient", return_value=ha), \
             patch.object(web_routes, "hash_password", return_value="hash"), \
             patch.object(web_routes, "encrypt_value", side_effect=lambda value, _key: f"enc:{value}"):
            response = await web_routes.setup_post(
                request,
                admin_username="admin",
                admin_password="correct horse battery staple",
                unvr_host="unvr.local",
                unvr_username="unvr-user",
                unvr_password="unvr-pass",
                access_host="",
                access_username="",
                access_password="",
                ha_url="http://ha.local",
                ha_token="ha-token",
            )

        self.assertEqual(response.status_code, 303)
        db.set_configs.assert_awaited_once()
        db.set_config.assert_not_awaited()
        bundle = db.set_configs.await_args.args[0]
        self.assertEqual(bundle["admin_username"], "admin")
        self.assertEqual(bundle["unvr_host"], "unvr.local")
        self.assertEqual(bundle["ha_url"], "http://ha.local")
        self.assertIn("secret_key_source", bundle)
        self.assertIn("encryption_salt", bundle)

    async def test_setup_validates_and_encrypts_optional_access_token(self) -> None:
        db = self._config_db()
        request = _request(
            db=db,
            configured=False,
            initialize_configured_state=AsyncMock(),
        )
        protect = _CandidateConsole()
        access = _CandidateConsole()
        access.get_console_identity = AsyncMock(return_value="site-identity")
        ha = SimpleNamespace(
            test_connection=AsyncMock(return_value=True),
            close=AsyncMock(),
        )

        def encrypt(value, _key):
            if value == "plain-open-api-token":
                return "sealed-access-token"
            return f"enc:{value}"

        with patch.object(web_routes, "_supervisor_proxy_active", return_value=False), \
             patch.object(web_routes, "ProtectClient", return_value=protect), \
             patch.object(web_routes, "AccessClient", return_value=access) as access_factory, \
             patch.object(web_routes, "HAClient", return_value=ha), \
             patch.object(web_routes, "hash_password", return_value="hash"), \
             patch.object(web_routes, "encrypt_value", side_effect=encrypt):
            response = await web_routes.setup_post(
                request,
                admin_username="admin",
                admin_password="correct horse battery staple",
                unvr_host="unvr.local",
                unvr_username="unvr-user",
                unvr_password="unvr-pass",
                access_host="",
                access_username="",
                access_password="",
                ha_url="http://ha.local",
                ha_token="ha-token",
                access_api_token="  plain-open-api-token  ",
            )

        self.assertEqual(response.status_code, 303)
        access_factory.assert_called_once_with(
            "unvr.local",
            "unvr-user",
            "unvr-pass",
            api_token="plain-open-api-token",
        )
        access.validate_open_api.assert_awaited_once()
        bundle = db.set_configs.await_args.args[0]
        self.assertEqual(bundle["access_api_token"], "sealed-access-token")
        self.assertNotIn("plain-open-api-token", bundle.values())


class ConcurrentSettingsUpdateTests(unittest.IsolatedAsyncioTestCase):
    async def test_serialized_ha_updates_leave_db_and_runtime_on_same_candidate(self) -> None:
        first_persist_started = asyncio.Event()
        release_first_persist = asyncio.Event()
        persisted: list[dict] = []

        async def persist(values: dict) -> None:
            persisted.append(dict(values))
            if len(persisted) == 1:
                first_persist_started.set()
                await release_first_persist.wait()

        db = SimpleNamespace(
            consume_rate_limit=AsyncMock(return_value=True),
            set_configs=AsyncMock(side_effect=persist),
            log_admin_action=AsyncMock(),
        )
        initial = SimpleNamespace(close=AsyncMock())
        engine = SimpleNamespace(_ha_client=initial, set_timezone=MagicMock())
        request = _request(
            db=db,
            ha=initial,
            auth_engine=engine,
            settings_update_lock=asyncio.Lock(),
            seed_lock_states=None,
        )
        candidates: list[SimpleNamespace] = []

        def make_candidate(url: str, _token: str):
            candidate = SimpleNamespace(
                url=url,
                test_connection=AsyncMock(return_value=True),
                get_timezone=AsyncMock(return_value="America/New_York"),
                close=AsyncMock(),
            )
            candidates.append(candidate)
            return candidate

        with patch.object(web_routes, "_supervisor_proxy_active", return_value=False), \
             patch.object(web_routes, "HAClient", side_effect=make_candidate) as factory, \
             patch.object(web_routes, "encrypt_value", side_effect=lambda value, _key: f"enc:{value}"), \
             patch.object(web_routes, "_settings_with_result", new=AsyncMock(return_value="ok")):
            first = asyncio.create_task(
                web_routes.update_ha(
                    request,
                    ha_url="http://ha-first.local",
                    ha_token="first-token",
                    user="admin",
                )
            )
            await first_persist_started.wait()
            second = asyncio.create_task(
                web_routes.update_ha(
                    request,
                    ha_url="http://ha-second.local",
                    ha_token="second-token",
                    user="admin",
                )
            )
            await asyncio.sleep(0)

            # The second request cannot even construct/test a candidate until
            # the first persistence+publication transaction completes.
            self.assertEqual(factory.call_count, 1)
            release_first_persist.set()
            await asyncio.gather(first, second)

        self.assertEqual(factory.call_count, 2)
        self.assertEqual(persisted[-1]["ha_url"], "http://ha-second.local")
        self.assertIs(request.app.state.ha_client, candidates[-1])
        self.assertIs(engine._ha_client, candidates[-1])
        self.assertEqual(candidates[-1].url, persisted[-1]["ha_url"])


class FailedStartupCleanupTests(unittest.IsolatedAsyncioTestCase):
    async def test_failure_before_yield_closes_managers_clients_and_database(self) -> None:
        db = SimpleNamespace(close=AsyncMock())
        access = SimpleNamespace(close=AsyncMock())
        protect = SimpleNamespace(close=AsyncMock())
        ha = SimpleNamespace(close=AsyncMock())
        hub = SimpleNamespace(shutdown=AsyncMock())
        relock = SimpleNamespace(shutdown=AsyncMock())
        drain = AsyncMock()
        app = SimpleNamespace(state=SimpleNamespace())

        @asynccontextmanager
        async def fail_before_yield(target_app):
            target_app.state.lifecycle_cleanup_complete = False
            target_app.state.db = db
            target_app.state.access_client = access
            target_app.state.protect_client = protect
            target_app.state.ha_client = ha
            target_app.state.hub_sync_manager = hub
            target_app.state.relock_manager = relock
            target_app.state.drain_event_tasks = drain
            raise RuntimeError("startup exploded")
            yield  # pragma: no cover - makes this an async context manager

        body_entered = False
        with patch.object(main_module, "_lifespan_inner", new=fail_before_yield):
            with self.assertRaisesRegex(RuntimeError, "startup exploded"):
                async with main_module.lifespan(app):
                    body_entered = True

        self.assertFalse(body_entered)
        drain.assert_awaited_once()
        hub.shutdown.assert_awaited_once()
        relock.shutdown.assert_awaited_once()
        access.close.assert_awaited_once()
        protect.close.assert_awaited_once()
        ha.close.assert_awaited_once()
        db.close.assert_awaited_once()
        self.assertTrue(app.state.lifecycle_cleanup_complete)

    async def test_manager_timeout_does_not_block_remaining_cleanup(
        self,
    ) -> None:
        blocked_started = asyncio.Event()
        blocked_cancelled = asyncio.Event()

        async def blocked_shutdown() -> None:
            blocked_started.set()
            try:
                await asyncio.Event().wait()
            finally:
                blocked_cancelled.set()

        db = SimpleNamespace(close=AsyncMock())
        relock = SimpleNamespace(shutdown=AsyncMock())
        app = SimpleNamespace(
            state=SimpleNamespace(
                lifecycle_cleanup_complete=False,
                db=db,
                access_client=None,
                protect_client=None,
                ha_client=None,
                hub_sync_manager=SimpleNamespace(shutdown=blocked_shutdown),
                relock_manager=relock,
                drain_event_tasks=AsyncMock(),
            )
        )

        with patch.object(
            main_module, "_MANAGER_SHUTDOWN_TIMEOUT_SECONDS", 0.01
        ):
            await asyncio.wait_for(
                main_module._cleanup_failed_startup(app),
                timeout=0.5,
            )

        self.assertTrue(blocked_started.is_set())
        self.assertTrue(blocked_cancelled.is_set())
        relock.shutdown.assert_awaited_once()
        db.close.assert_awaited_once()
        self.assertTrue(app.state.lifecycle_cleanup_complete)


class SecretFingerprintMigrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_legacy_environment_verifier_is_replaced_without_key_write(
        self,
    ) -> None:
        db = SimpleNamespace(set_config=AsyncMock())

        with patch.object(
            main_module,
            "secret_key_fingerprint",
            return_value="pbkdf2_sha256$480000$salt$verifier",
        ):
            await main_module._persist_resolved_secret_key_metadata(
                db,
                original_source="environment",
                normalized_source="environment",
                stored_fingerprint="a" * 64,
                secret_key="unchanged-environment-key",
            )

        db.set_config.assert_awaited_once_with(
            "secret_key_fingerprint",
            "pbkdf2_sha256$480000$salt$verifier",
        )
        self.assertTrue(
            all(
                call_args.args[0] != "secret_key"
                for call_args in db.set_config.await_args_list
            )
        )

    async def test_versioned_environment_verifier_is_not_rewritten(self) -> None:
        db = SimpleNamespace(set_config=AsyncMock())

        await main_module._persist_resolved_secret_key_metadata(
            db,
            original_source="environment",
            normalized_source="environment",
            stored_fingerprint="pbkdf2_sha256$480000$salt$verifier",
            secret_key="environment-key",
        )

        db.set_config.assert_not_awaited()


class TopologyGenerationTests(unittest.IsolatedAsyncioTestCase):
    async def test_retired_snapshot_is_discarded_and_serialized_final_sync_wins(self) -> None:
        stats = {
            "users_seen": 1,
            "users_inserted": 1,
            "users_updated": 0,
            "users_marked_deleted": 0,
            "users_unchanged": 0,
            "locks_seen": 1,
            "locks_inserted": 1,
            "locks_updated": 0,
            "locks_unchanged": 0,
        }
        db = SimpleNamespace(
            connect=AsyncMock(),
            close=AsyncMock(),
            get_config=AsyncMock(return_value=None),
            sync_topology=AsyncMock(return_value=stats),
            prune_runtime_state=AsyncMock(),
        )
        old_fetch_started = asyncio.Event()
        release_old_fetch = asyncio.Event()

        async def old_bootstrap():
            old_fetch_started.set()
            await release_old_fetch.wait()
            return {"data": []}

        old = _CandidateConsole()
        old.fetch_users = AsyncMock(return_value=[{"ulp_id": "old"}])
        old.get_bootstrap = AsyncMock(side_effect=old_bootstrap)
        old.parse_doors_and_devices = MagicMock(return_value=[{
            "device_id": "old-hub",
            "location_id": "old-door",
            "name": "Old",
        }])

        new_bootstrap = {"data": [{
            "floors": [{
                "doors": [{
                    "unique_id": "new-door",
                    "device_groups": [[{
                        "unique_id": "new-camera",
                        "is_camera": True,
                    }]],
                }],
            }],
        }]}
        new_door = {
            "device_id": "new-hub",
            "location_id": "new-door",
            "name": "New",
        }
        new = _CandidateConsole()
        new.fetch_users = AsyncMock(return_value=[{"ulp_id": "new"}])
        new.get_bootstrap = AsyncMock(return_value=new_bootstrap)
        new.parse_doors_and_devices = MagicMock(return_value=[new_door])

        app = SimpleNamespace(state=SimpleNamespace())
        with patch.object(main_module, "Database", return_value=db):
            async with main_module.lifespan(app):
                app.state.access_client = old
                stale_sync = asyncio.create_task(app.state.sync_users())
                await old_fetch_started.wait()

                app.state.access_client = new
                final_sync = asyncio.create_task(app.state.sync_users())
                await asyncio.sleep(0)
                new.fetch_users.assert_not_awaited()

                release_old_fetch.set()
                await asyncio.gather(stale_sync, final_sync)

                old.parse_doors_and_devices.assert_not_called()
                db.sync_topology.assert_awaited_once_with(
                    [{"ulp_id": "new"}], [new_door]
                )
                self.assertEqual(
                    app.state.camera_to_location,
                    {"new-camera": "new-door"},
                )


class AtomicSettingsBundleTests(unittest.IsolatedAsyncioTestCase):
    _config_db = staticmethod(AtomicConfigBundleTests._config_db)

    async def test_unvr_settings_persist_one_atomic_bundle(self) -> None:
        db = self._config_db(
            get_config=AsyncMock(return_value="separate-access-configured")
        )
        candidate = _CandidateConsole()
        request = _request(
            db=db,
            protect_client=None,
            unvr_creds=None,
            on_protect_event=None,
            sync_users=None,
        )

        with patch.object(web_routes, "ProtectClient", return_value=candidate), \
             patch.object(web_routes, "encrypt_value", side_effect=lambda value, _key: f"enc:{value}"), \
             patch.object(web_routes, "_settings_with_result", new=AsyncMock(return_value="ok")):
            await web_routes.update_unvr(
                request,
                unvr_host="new-unvr.local",
                unvr_username="new-user",
                unvr_password="new-pass",
                user="admin",
            )

        db.set_configs.assert_awaited_once_with({
            "unvr_host": "new-unvr.local",
            "unvr_username": "enc:new-user",
            "unvr_password": "enc:new-pass",
        })
        db.set_config.assert_not_awaited()

    async def test_ha_settings_persist_one_atomic_bundle(self) -> None:
        db = self._config_db()
        candidate = SimpleNamespace(
            test_connection=AsyncMock(return_value=True),
            get_timezone=AsyncMock(return_value="America/New_York"),
            close=AsyncMock(),
        )
        request = _request(
            db=db,
            ha=None,
            seed_lock_states=None,
        )

        with patch.object(web_routes, "_supervisor_proxy_active", return_value=False), \
             patch.object(web_routes, "HAClient", return_value=candidate), \
             patch.object(web_routes, "encrypt_value", side_effect=lambda value, _key: f"enc:{value}"), \
             patch.object(web_routes, "_settings_with_result", new=AsyncMock(return_value="ok")):
            await web_routes.update_ha(
                request,
                ha_url="http://new-ha.local",
                ha_token="new-token",
                user="admin",
            )

        db.set_configs.assert_awaited_once_with({
            "ha_url": "http://new-ha.local",
            "ha_token": "enc:new-token",
        })
        db.set_config.assert_not_awaited()

    async def test_access_settings_persist_one_atomic_bundle(self) -> None:
        db = self._config_db()
        candidate = _CandidateConsole()
        request = _request(
            db=db,
            access=None,
            access_creds=None,
            unvr_creds=("unvr.local", "user", "pass"),
            on_access_event=None,
            sync_users=None,
        )

        with patch.object(web_routes, "AccessClient", return_value=candidate), \
             patch.object(web_routes, "encrypt_value", side_effect=lambda value, _key: f"enc:{value}"), \
             patch.object(web_routes, "_settings_with_result", new=AsyncMock(return_value="ok")):
            await web_routes.update_access_console(
                request,
                user="admin",
                access_host="access.local",
                access_username="access-user",
                access_password="access-pass",
                clear="",
            )

        db.set_configs.assert_awaited_once_with({
            "access_host": "access.local",
            "access_username": "enc:access-user",
            "access_password": "enc:access-pass",
            "access_console_identity": "site-identity",
        })
        db.set_config.assert_not_awaited()


class AccessApiTokenSettingsTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def _db(events: list[str] | None = None):
        async def persist(_key, _value):
            if events is not None:
                events.append("persist")

        return SimpleNamespace(
            consume_rate_limit=AsyncMock(return_value=True),
            get_config=AsyncMock(return_value="site-identity"),
            set_config=AsyncMock(side_effect=persist),
            log_admin_action=AsyncMock(),
        )

    @staticmethod
    def _request_for(db, old):
        return _request(
            db=db,
            access=old,
            enc_key=b"k" * 32,
            access_creds=("access.local", "service", "password"),
            access_started_client=old,
            access_generation=3,
            access_api_token="old-token",
            access_open_api_ready=True,
            access_open_api_error=None,
            event_topology_ready=True,
            on_access_event=None,
            sync_users=None,
        )

    async def test_save_validates_persists_then_promotes_candidate(self) -> None:
        events: list[str] = []
        db = self._db(events)
        old = _CandidateConsole()
        candidate = _CandidateConsole()
        candidate.validate_open_api = AsyncMock(
            side_effect=lambda: events.append("validate")
        )
        candidate.start_websocket = AsyncMock(
            side_effect=lambda: events.append("promote")
        )
        request = self._request_for(db, old)

        with patch.dict(
            web_routes.os.environ,
            {"ACCESS_CONTROL_ACCESS_API_TOKEN": ""},
            clear=False,
        ), patch.object(
            web_routes, "AccessClient", return_value=candidate
        ) as access_factory, patch.object(
            web_routes,
            "encrypt_value",
            return_value="sealed-access-token",
        ), patch.object(
            web_routes,
            "_settings_with_result",
            new=AsyncMock(return_value="saved"),
        ):
            response = await web_routes.update_access_api_token(
                request,
                user="admin",
                access_api_token="  plain-token  ",
                clear="",
            )

        self.assertEqual(response, "saved")
        access_factory.assert_called_once_with(
            "access.local",
            "service",
            "password",
            expected_identity="site-identity",
            api_token="plain-token",
        )
        candidate.validate_open_api.assert_awaited_once()
        db.set_config.assert_awaited_once_with(
            "access_api_token", "sealed-access-token"
        )
        self.assertNotIn("plain-token", db.set_config.await_args.args)
        self.assertLess(events.index("validate"), events.index("persist"))
        self.assertLess(events.index("persist"), events.index("promote"))
        self.assertIs(request.app.state.access_client, candidate)
        self.assertEqual(request.app.state.access_api_token, "plain-token")
        self.assertTrue(request.app.state.access_open_api_ready)
        self.assertIsNone(request.app.state.access_open_api_error)
        old.close.assert_awaited_once()
        db.log_admin_action.assert_awaited_once_with(
            "admin", "settings_access_api_token_update"
        )

    async def test_clear_promotes_compatibility_candidate(self) -> None:
        db = self._db()
        old = _CandidateConsole()
        candidate = _CandidateConsole()
        request = self._request_for(db, old)

        with patch.dict(
            web_routes.os.environ,
            {"ACCESS_CONTROL_ACCESS_API_TOKEN": ""},
            clear=False,
        ), patch.object(
            web_routes, "AccessClient", return_value=candidate
        ) as access_factory, patch.object(
            web_routes,
            "_settings_with_result",
            new=AsyncMock(return_value="cleared"),
        ):
            response = await web_routes.update_access_api_token(
                request,
                user="admin",
                access_api_token="ignored-on-clear",
                clear="on",
            )

        self.assertEqual(response, "cleared")
        access_factory.assert_called_once_with(
            "access.local",
            "service",
            "password",
            expected_identity="site-identity",
            api_token=None,
        )
        candidate.validate_open_api.assert_not_awaited()
        db.set_config.assert_awaited_once_with("access_api_token", "")
        self.assertIs(request.app.state.access_client, candidate)
        self.assertIsNone(request.app.state.access_api_token)
        self.assertFalse(request.app.state.access_open_api_ready)
        self.assertIsNone(request.app.state.access_open_api_error)
        db.log_admin_action.assert_awaited_once_with(
            "admin", "settings_access_api_token_clear"
        )

    async def test_environment_override_rejects_settings_mutation(self) -> None:
        db = self._db()
        old = _CandidateConsole()
        request = self._request_for(db, old)
        rendered = AsyncMock(return_value="rejected")

        with patch.dict(
            web_routes.os.environ,
            {"ACCESS_CONTROL_ACCESS_API_TOKEN": "environment-token"},
            clear=False,
        ), patch.object(
            web_routes, "AccessClient"
        ) as access_factory, patch.object(
            web_routes, "_settings_with_result", new=rendered
        ):
            response = await web_routes.update_access_api_token(
                request,
                user="admin",
                access_api_token="replacement",
                clear="",
            )

        self.assertEqual(response, "rejected")
        access_factory.assert_not_called()
        db.set_config.assert_not_awaited()
        self.assertIs(request.app.state.access_client, old)
        self.assertEqual(request.app.state.access_api_token, "old-token")
        self.assertIn(
            "ACCESS_CONTROL_ACCESS_API_TOKEN",
            rendered.await_args.args[4],
        )


class AccessApiTokenHealthTests(unittest.TestCase):
    def test_health_exposes_configured_readiness_and_error(self) -> None:
        app = FastAPI()
        app.include_router(api_routes.router)
        app.state.db = SimpleNamespace(
            get_user_count=AsyncMock(return_value=1),
            get_lock_count=AsyncMock(return_value=2),
        )
        app.state.access_client = SimpleNamespace(
            connected=True,
            ws_connected=True,
            open_api_configured=True,
        )
        app.state.protect_client = None
        app.state.ha_client = None
        app.state.auth_engine = SimpleNamespace(lockdown=False)
        app.state.hub_sync_manager = None
        app.state.access_open_api_ready = False
        app.state.access_open_api_error = "AccessClientError"
        app.dependency_overrides[api_routes.verify_api_key] = lambda: {
            "scope": "locks_only"
        }

        with TestClient(app) as client:
            response = client.get("/api/health")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["access_open_api_configured"])
        self.assertFalse(response.json()["access_open_api_ready"])
        self.assertEqual(
            response.json()["access_open_api_error"], "AccessClientError"
        )
        # The fail-safe field is present (and empty) even without a live latch.
        self.assertEqual(response.json()["hub_sync_fail_safe"], [])

    def test_health_exposes_hub_sync_fail_safe_latch(self) -> None:
        """1.5.12 (viii): a stuck locked-wins latch is visible in health so it
        cannot silently revert unlocks unnoticed, matching the scope handling of
        lockdown_enforcement_pending (entity IDs, all health scopes)."""
        app = FastAPI()
        app.include_router(api_routes.router)
        app.state.db = SimpleNamespace(
            get_user_count=AsyncMock(return_value=1),
            get_lock_count=AsyncMock(return_value=2),
        )
        app.state.access_client = SimpleNamespace(
            connected=True, ws_connected=True, open_api_configured=True
        )
        app.state.protect_client = None
        app.state.ha_client = None
        app.state.auth_engine = SimpleNamespace(lockdown=False)
        app.state.hub_sync_manager = SimpleNamespace(
            lockdown_unresolved=(),
            fail_safe_pending=("lock.front", "lock.back"),
        )
        app.state.access_open_api_ready = True
        app.state.access_open_api_error = None
        app.dependency_overrides[api_routes.verify_api_key] = lambda: {
            "scope": "read_only"
        }

        with TestClient(app) as client:
            response = client.get("/api/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["hub_sync_fail_safe"],
            ["lock.front", "lock.back"],
        )


class StartupSafetyWiringTests(unittest.IsolatedAsyncioTestCase):
    async def test_startup_shares_command_lock_and_recovers_hub_holds(self) -> None:
        config_values = {
            "admin_username": "admin",
            "admin_password_hash": "hash",
            "encryption_salt": "00" * 16,
            "secret_key": "secret",
            "secret_key_source": "database",
            "secret_key_fingerprint": "fingerprint",
            "unvr_host": "unvr.local",
            "unvr_username": "unvr-user",
            "unvr_password": "unvr-pass",
            "access_api_token": "encrypted-open-api-token",
            "ha_url": "http://ha.local",
            "ha_token": "ha-token",
        }
        db = SimpleNamespace(
            connect=AsyncMock(),
            close=AsyncMock(),
            get_config=AsyncMock(side_effect=lambda key: config_values.get(key)),
            set_config=AsyncMock(),
            get_all_locks=AsyncMock(return_value=[]),
            get_user_count=AsyncMock(return_value=0),
            sync_topology=AsyncMock(return_value={
                "users_seen": 0,
                "users_inserted": 0,
                "users_updated": 0,
                "users_marked_deleted": 0,
                "users_unchanged": 0,
                "locks_seen": 0,
                "locks_inserted": 0,
                "locks_updated": 0,
                "locks_unchanged": 0,
            }),
            prune_runtime_state=AsyncMock(),
        )
        access = _CandidateConsole()
        access.open_api_configured = True
        access.validate_open_api = AsyncMock(
            side_effect=[None, RuntimeError("port 12445 unavailable")]
        )
        access.fetch_users = AsyncMock(return_value=[])
        access.get_bootstrap = AsyncMock(return_value={"data": []})
        access.parse_doors_and_devices = MagicMock(return_value=[])
        protect = _CandidateConsole()
        ha = SimpleNamespace(
            connected=False,
            test_connection=AsyncMock(return_value=False),
            close=AsyncMock(),
        )
        relock = SimpleNamespace(
            rehydrate=AsyncMock(),
            sweep_overdue=AsyncMock(return_value=0),
            shutdown=AsyncMock(),
            schedule=AsyncMock(),
        )
        hub = SimpleNamespace(
            recover=AsyncMock(return_value=0),
            enforce_lockdown=AsyncMock(return_value=0),
            poll_once=AsyncMock(return_value=0),
            shutdown=AsyncMock(return_value=0),
        )
        engine = SimpleNamespace(
            lockdown=False,
            tz=timezone.utc,
            load_persisted_lockdown=AsyncMock(),
            set_timezone=MagicMock(),
            get_locks_for_location=AsyncMock(return_value=[]),
        )
        relock_kwargs: dict = {}
        hub_kwargs: dict = {}

        def make_relock(**kwargs):
            relock_kwargs.update(kwargs)
            return relock

        class HubFactory:
            POLL_INTERVAL = 60

            def __call__(self, **kwargs):
                hub_kwargs.update(kwargs)
                return hub

        app = SimpleNamespace(state=SimpleNamespace())
        with patch.object(main_module, "Database", return_value=db), \
             patch.object(main_module, "AccessClient", return_value=access) as access_factory, \
             patch.object(main_module, "ProtectClient", return_value=protect) as protect_factory, \
             patch.object(main_module, "HAClient", return_value=ha), \
             patch.object(main_module, "RelockManager", side_effect=make_relock), \
             patch.object(main_module, "HubSyncManager", new=HubFactory()), \
             patch.object(main_module, "AuthEngine", return_value=engine), \
             patch.object(main_module, "resolve_secret_key", return_value=("secret", "database")), \
             patch.object(main_module, "derive_key", return_value=b"k" * 32), \
             patch.object(
                 main_module,
                 "decrypt_value",
                 side_effect=lambda value, _key: (
                     "plain-open-api-token"
                     if value == "encrypted-open-api-token"
                     else value
                 ),
             ):
            async with main_module.lifespan(app):
                access_factory.assert_called_once_with(
                    host="unvr.local",
                    username="unvr-user",
                    password="unvr-pass",
                    expected_identity=None,
                    api_token="plain-open-api-token",
                )
                access.validate_open_api.assert_awaited_once()
                self.assertEqual(
                    app.state.access_api_token, "plain-open-api-token"
                )
                self.assertTrue(app.state.access_open_api_ready)
                self.assertIsNone(app.state.access_open_api_error)
                command_lock = app.state.physical_command_lock
                self.assertIs(relock_kwargs["command_lock"], command_lock)
                self.assertIs(hub_kwargs["command_lock"], command_lock)
                hub.recover.assert_awaited_once()

                # Simulate simultaneous cold-start supervisor ticks. Each
                # integration must create, authenticate, attach callbacks to,
                # and start exactly one candidate.
                app.state.access_client = None
                app.state.access_started_client = None
                access_factory.reset_mock()
                access.login.reset_mock()
                access.register_callback.reset_mock()
                access.start_websocket.reset_mock()
                hub.recover.reset_mock()
                self.assertEqual(
                    await asyncio.gather(
                        app.state.start_access_client(),
                        app.state.start_access_client(),
                    ),
                    [True, True],
                )
                access_factory.assert_called_once()
                access_factory.assert_called_once_with(
                    "unvr.local",
                    "unvr-user",
                    "unvr-pass",
                    expected_identity="site-identity",
                    api_token="plain-open-api-token",
                )
                access.login.assert_awaited_once()
                self.assertEqual(access.validate_open_api.await_count, 2)
                self.assertFalse(app.state.access_open_api_ready)
                self.assertEqual(
                    app.state.access_open_api_error, "RuntimeError"
                )
                access.register_callback.assert_called_once()
                access.start_websocket.assert_awaited_once()
                hub.recover.assert_awaited_once()

                app.state.protect_client = None
                app.state.protect_started_client = None
                protect_factory.reset_mock()
                protect.login.reset_mock()
                protect.register_callback.reset_mock()
                protect.start_websocket.reset_mock()
                self.assertEqual(
                    await asyncio.gather(
                        app.state.start_protect_client(),
                        app.state.start_protect_client(),
                    ),
                    [True, True],
                )
                protect_factory.assert_called_once()
                protect.login.assert_awaited_once()
                protect.register_callback.assert_called_once()
                protect.start_websocket.assert_awaited_once()

        db.close.assert_awaited_once()


class RestartBannerRegressionTests(unittest.TestCase):
    def test_restart_banner_polls_with_supported_get_and_retries_non_ok(self) -> None:
        source = (
            Path(web_routes.__file__).resolve().parent
            / "templates"
            / "settings.html"
        ).read_text()
        start = source.index("function tryReload()")
        banner_script = source[start : source.index("})();", start)]

        self.assertNotIn("method: 'HEAD'", banner_script)
        self.assertIn("r.ok", banner_script)
        # One retry is required for a non-OK response and another for a
        # network error while the process is between shutdown and startup.
        self.assertGreaterEqual(banner_script.count("setTimeout(tryReload"), 2)


if __name__ == "__main__":
    unittest.main()
