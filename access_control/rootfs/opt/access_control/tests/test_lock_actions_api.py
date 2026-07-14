"""Shared dashboard/API lock-command and schedule regressions."""
from __future__ import annotations

import asyncio
import tempfile
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from access_control import api_auth, api_routes, web_routes
from access_control.database import Database
from access_control.lock_actions import LockActionResult, execute_lock_action


def _state(*, db, access=None, ha=None, relock=None, lockdown=False):
    return SimpleNamespace(
        db=db,
        access_client=access,
        ha_client=ha,
        relock_manager=relock,
        auth_engine=SimpleNamespace(lockdown=lockdown),
        physical_command_lock=asyncio.Lock(),
        lock_states={},
        enc_key=None,
    )


def _db_for(lock: dict):
    return SimpleNamespace(
        get_lock=AsyncMock(return_value=lock),
        log_access=AsyncMock(),
        get_all_alarm_panels=AsyncMock(return_value=[]),
    )


class SharedLockActionTests(unittest.IsolatedAsyncioTestCase):
    async def test_dashboard_adapter_uses_shared_executor(self) -> None:
        state = SimpleNamespace()
        request = SimpleNamespace(
            app=SimpleNamespace(state=state),
            scope={},
        )
        executor = AsyncMock(
            return_value=LockActionResult(
                3,
                "unlock",
                "granted",
                confirmed_state="unlocked",
            )
        )
        with patch.object(web_routes, "execute_lock_action", executor):
            response = await web_routes._lock_action(
                3, "unlock", "admin", request
            )

        self.assertEqual(response.status_code, 303)
        executor.assert_awaited_once_with(
            state,
            3,
            "unlock",
            actor="admin",
            source="manual",
        )

    async def test_lock_remains_available_during_lockdown(self) -> None:
        lock = {
            "id": 4,
            "type": "access_native",
            "device_id": "hub-4",
            "location_id": "door-4",
            "name": "Front",
        }
        db = _db_for(lock)
        access = SimpleNamespace(force_lock=AsyncMock(return_value={"state": "locked"}))
        state = _state(db=db, access=access, lockdown=True)

        result = await execute_lock_action(
            state, 4, "lock", actor="admin", source="manual"
        )

        self.assertTrue(result.granted)
        self.assertEqual(result.confirmed_state, "locked")
        access.force_lock.assert_awaited_once_with(
            "hub-4", location_id="door-4"
        )
        self.assertEqual(state.lock_states["hub-4"], "locked")

    async def test_restore_schedule_is_denied_during_lockdown(self) -> None:
        lock = {
            "id": 14,
            "type": "access_native",
            "device_id": "hub-14",
            "location_id": "door-14",
            "name": "Lobby",
        }
        db = _db_for(lock)
        access = SimpleNamespace(restore_native_rule=AsyncMock())

        result = await execute_lock_action(
            _state(db=db, access=access, lockdown=True),
            14,
            "restore_schedule",
            actor="admin",
            source="manual",
        )

        self.assertEqual(result.outcome, "denied")
        access.restore_native_rule.assert_not_awaited()

    async def test_ha_unlock_cancels_relock_only_after_confirmation(self) -> None:
        lock = {
            "id": 5,
            "type": "ha_external",
            "entity_id": "lock.front",
            "name": "Front",
        }
        db = _db_for(lock)
        paused = {"entity_id": "lock.front", "deadline": 123.0}
        relock = SimpleNamespace(
            pause=AsyncMock(return_value=paused),
            resume=AsyncMock(),
            cancel=AsyncMock(),
        )
        ha = SimpleNamespace(
            unlock=AsyncMock(return_value=True),
            get_entity_state=AsyncMock(return_value="unlocked"),
        )
        state = _state(db=db, ha=ha, relock=relock)

        result = await execute_lock_action(
            state, 5, "unlock", actor="api:automation", source="api"
        )

        self.assertTrue(result.granted)
        relock.cancel.assert_awaited_once_with("lock.front")
        relock.resume.assert_not_awaited()
        self.assertEqual(state.lock_states["lock.front"], "unlocked")
        db.log_access.assert_awaited_once_with(
            method="api_unlock",
            result="granted",
            lock_id=5,
            lock_name="Front",
            user_name="api:automation",
            reason=None,
        )

    async def test_cancel_failure_rearms_paused_relock(self) -> None:
        lock = {
            "id": 15,
            "type": "ha_external",
            "entity_id": "lock.back",
            "name": "Back",
        }
        db = _db_for(lock)
        paused = {"entity_id": "lock.back", "deadline": 321.0}
        relock = SimpleNamespace(
            pause=AsyncMock(return_value=paused),
            resume=AsyncMock(),
            cancel=AsyncMock(side_effect=OSError("database unavailable")),
        )
        ha = SimpleNamespace(
            unlock=AsyncMock(return_value=True),
            get_entity_state=AsyncMock(return_value="unlocked"),
        )

        result = await execute_lock_action(
            _state(db=db, ha=ha, relock=relock),
            15,
            "unlock",
            actor="admin",
            source="manual",
        )

        self.assertEqual(result.outcome, "error")
        relock.resume.assert_awaited_once_with(paused)

    async def test_unconfirmed_ha_buzz_retains_durable_relock(self) -> None:
        lock = {
            "id": 6,
            "type": "ha_external",
            "entity_id": "lock.side",
            "name": "Side",
            "buzz_enabled": 1,
            "relock_duration": 20,
        }
        db = _db_for(lock)
        intent = object()
        relock = SimpleNamespace(
            schedule=AsyncMock(return_value=intent),
            retain_after_uncertain_unlock=AsyncMock(),
            extend_after_success=AsyncMock(),
        )
        ha = SimpleNamespace(
            unlock=AsyncMock(return_value=True),
            get_entity_state=AsyncMock(return_value="locked"),
        )
        state = _state(db=db, ha=ha, relock=relock)

        with patch(
            "access_control.lock_actions.asyncio.sleep", new=AsyncMock()
        ):
            result = await execute_lock_action(
                state, 6, "buzz", actor="admin", source="manual"
            )

        self.assertEqual(result.outcome, "error")
        self.assertIn("did not confirm unlocked", result.reason)
        relock.retain_after_uncertain_unlock.assert_awaited_once_with(intent)
        relock.extend_after_success.assert_not_awaited()
        self.assertNotIn("lock.side", state.lock_states)

    async def test_buzz_on_synced_lock_leases_momentary_hold(self) -> None:
        # Change 1: a timed buzz on a bidirectionally synced lock must lease a
        # momentary Access hold (same duration semantics as the remote path)
        # before the HA unlock, so the hub poller does not echo it back as a
        # persistent keep_unlock override.
        lock = {
            "id": 8,
            "type": "ha_external",
            "entity_id": "lock.sync",
            "name": "Sync",
            "buzz_enabled": 1,
            "relock_duration": 30,
            "sync_hub_state": 1,
        }
        db = _db_for(lock)
        intent = object()
        relock = SimpleNamespace(
            schedule=AsyncMock(return_value=intent),
            retain_after_uncertain_unlock=AsyncMock(),
            extend_after_success=AsyncMock(),
        )
        ha = SimpleNamespace(
            unlock=AsyncMock(return_value=True),
            get_entity_state=AsyncMock(return_value="unlocked"),
        )
        hub_sync = SimpleNamespace(mark_access_momentary=MagicMock())
        state = _state(db=db, ha=ha, relock=relock)
        state.hub_sync_manager = hub_sync

        with patch("access_control.lock_actions.asyncio.sleep", new=AsyncMock()):
            result = await execute_lock_action(
                state, 8, "buzz", actor="admin", source="manual"
            )

        self.assertTrue(result.granted)
        hub_sync.mark_access_momentary.assert_called_once_with("lock.sync", 30.0)

    async def test_buzz_on_unsynced_lock_does_not_lease(self) -> None:
        lock = {
            "id": 8,
            "type": "ha_external",
            "entity_id": "lock.plain",
            "name": "Plain",
            "buzz_enabled": 1,
            "relock_duration": 30,
            "sync_hub_state": 0,
        }
        db = _db_for(lock)
        relock = SimpleNamespace(
            schedule=AsyncMock(return_value=object()),
            retain_after_uncertain_unlock=AsyncMock(),
            extend_after_success=AsyncMock(),
        )
        ha = SimpleNamespace(
            unlock=AsyncMock(return_value=True),
            get_entity_state=AsyncMock(return_value="unlocked"),
        )
        hub_sync = SimpleNamespace(mark_access_momentary=MagicMock())
        state = _state(db=db, ha=ha, relock=relock)
        state.hub_sync_manager = hub_sync

        with patch("access_control.lock_actions.asyncio.sleep", new=AsyncMock()):
            result = await execute_lock_action(
                state, 8, "buzz", actor="admin", source="manual"
            )

        self.assertTrue(result.granted)
        hub_sync.mark_access_momentary.assert_not_called()

    async def test_manual_unlock_marks_app_initiated_on_synced_lock(self) -> None:
        # Change 4 exclusion (ii): a deliberate manual Unlock (hold-open) must
        # tag the imminent HA edge app-initiated so relock_on_ha_origin ignores
        # it. Unsynced locks are unaffected.
        lock = {
            "id": 9,
            "type": "ha_external",
            "entity_id": "lock.sync2",
            "name": "Sync2",
            "sync_hub_state": 1,
        }
        db = _db_for(lock)
        relock = SimpleNamespace(
            pause=AsyncMock(return_value=None),
            resume=AsyncMock(),
            cancel=AsyncMock(),
        )
        ha = SimpleNamespace(
            unlock=AsyncMock(return_value=True),
            get_entity_state=AsyncMock(return_value="unlocked"),
        )
        hub_sync = SimpleNamespace(mark_app_initiated_unlock=MagicMock())
        state = _state(db=db, ha=ha, relock=relock)
        state.hub_sync_manager = hub_sync

        result = await execute_lock_action(
            state, 9, "unlock", actor="admin", source="manual"
        )

        self.assertTrue(result.granted)
        hub_sync.mark_app_initiated_unlock.assert_called_once_with("lock.sync2")

    async def test_manual_lock_does_not_mark_app_initiated(self) -> None:
        lock = {
            "id": 9,
            "type": "ha_external",
            "entity_id": "lock.sync3",
            "name": "Sync3",
            "sync_hub_state": 1,
        }
        db = _db_for(lock)
        relock = SimpleNamespace(
            pause=AsyncMock(return_value=None),
            resume=AsyncMock(),
            cancel=AsyncMock(),
        )
        ha = SimpleNamespace(
            lock=AsyncMock(return_value=True),
            get_entity_state=AsyncMock(return_value="locked"),
        )
        hub_sync = SimpleNamespace(mark_app_initiated_unlock=MagicMock())
        state = _state(db=db, ha=ha, relock=relock)
        state.hub_sync_manager = hub_sync

        result = await execute_lock_action(
            state, 9, "lock", actor="admin", source="manual"
        )

        self.assertTrue(result.granted)
        hub_sync.mark_app_initiated_unlock.assert_not_called()

    async def test_restore_schedule_uses_confirmed_native_operation(self) -> None:
        lock = {
            "id": 7,
            "type": "access_native",
            "device_id": "hub-7",
            "location_id": "door-7",
            "name": "Garage",
        }
        db = _db_for(lock)
        access = SimpleNamespace(
            restore_native_rule=AsyncMock(
                return_value={"type": "reset", "state": "unlocked"}
            )
        )

        state = _state(db=db, access=access)

        result = await execute_lock_action(
            state,
            7,
            "restore_schedule",
            actor="admin",
            source="manual",
        )

        self.assertTrue(result.granted)
        self.assertEqual(result.confirmed_state, "scheduled")
        access.restore_native_rule.assert_awaited_once_with(
            "hub-7", location_id="door-7"
        )
        self.assertEqual(state.lock_states["hub-7"], "unlocked")


class LockModeApiTests(unittest.TestCase):
    @staticmethod
    def _app(scope: str) -> FastAPI:
        app = FastAPI()
        app.include_router(api_routes.router)
        app.state.db = SimpleNamespace()
        app.dependency_overrides[api_routes.verify_api_key] = lambda: {
            "key_id": 8,
            "name": "automation",
            "scope": scope,
        }
        return app

    def test_dashboard_and_api_import_the_same_executor(self) -> None:
        self.assertIs(
            web_routes.execute_lock_action,
            api_routes.execute_lock_action,
        )

    def test_locks_only_can_repeatedly_set_explicit_mode(self) -> None:
        app = self._app("locks_only")
        executor = AsyncMock(
            return_value=LockActionResult(
                9,
                "unlock",
                "granted",
                confirmed_state="unlocked",
                lock_name="Front",
            )
        )
        with patch.object(api_routes, "execute_lock_action", executor):
            with TestClient(app) as client:
                first = client.put(
                    "/api/locks/9/mode", json={"mode": "hold_unlocked"}
                )
                repeated = client.put(
                    "/api/locks/9/mode", json={"mode": "hold_unlocked"}
                )

        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.json(), repeated.json())
        self.assertEqual(first.json()["confirmed_state"], "unlocked")
        self.assertEqual(executor.await_count, 2)
        executor.assert_awaited_with(
            app.state,
            9,
            "unlock",
            actor="api:automation",
            source="api",
            auto_disarm=False,
        )

    def test_full_scope_retains_explicit_auto_disarm_authority(self) -> None:
        app = self._app("full")
        executor = AsyncMock(
            return_value=LockActionResult(
                9,
                "unlock",
                "granted",
                confirmed_state="unlocked",
            )
        )
        with patch.object(api_routes, "execute_lock_action", executor):
            with TestClient(app) as client:
                response = client.put(
                    "/api/locks/9/mode", json={"mode": "hold_unlocked"}
                )

        self.assertEqual(response.status_code, 200)
        executor.assert_awaited_once_with(
            app.state,
            9,
            "unlock",
            actor="api:automation",
            source="api",
            auto_disarm=True,
        )

    def test_read_only_cannot_operate_locks(self) -> None:
        app = self._app("read_only")
        executor = AsyncMock()
        with patch.object(api_routes, "execute_lock_action", executor):
            with TestClient(app) as client:
                response = client.put(
                    "/api/locks/9/mode", json={"mode": "force_locked"}
                )
        self.assertEqual(response.status_code, 403)
        executor.assert_not_awaited()

    def test_command_outcomes_have_stable_http_statuses(self) -> None:
        app = self._app("full")
        cases = (
            ("not_found", 404),
            ("denied", 409),
            ("error", 503),
        )
        with TestClient(app) as client:
            for outcome, expected_status in cases:
                with self.subTest(outcome=outcome), patch.object(
                    api_routes,
                    "execute_lock_action",
                    new=AsyncMock(
                        return_value=LockActionResult(
                            9,
                            "lock",
                            outcome,
                            reason="safe public reason",
                        )
                    ),
                ):
                    response = client.put(
                        "/api/locks/9/mode", json={"mode": "force_locked"}
                    )
                    self.assertEqual(response.status_code, expected_status)
                    self.assertEqual(response.json()["result"], outcome)
                    self.assertEqual(
                        response.json()["reason"], "safe public reason"
                    )


class HealthPendingRelockTests(unittest.TestCase):
    """Change 3(b): /api/health reports scope-safe pending-relock counts."""

    @staticmethod
    def _app(scope: str = "read_only") -> FastAPI:
        app = FastAPI()
        app.include_router(api_routes.router)
        app.state.access_client = None
        app.state.ha_client = None
        app.state.protect_client = None
        app.state.hub_sync_manager = None
        app.state.relock_manager = None
        app.state.db = SimpleNamespace(
            get_user_count=AsyncMock(return_value=3),
            get_lock_count=AsyncMock(return_value=2),
        )
        app.state.auth_engine = SimpleNamespace(lockdown=False)
        app.dependency_overrides[api_routes.verify_api_key] = lambda: {
            "key_id": 1,
            "name": "automation",
            "scope": scope,
        }
        return app

    def test_health_reports_total_and_overdue_counts(self) -> None:
        app = self._app()
        app.state.relock_manager = SimpleNamespace(
            pending_relock_status=AsyncMock(
                return_value={"lock.a": True, "lock.b": False, "lock.c": True}
            )
        )
        with TestClient(app) as client:
            resp = client.get("/api/health")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(
            resp.json()["pending_relocks"], {"total": 3, "overdue": 2}
        )
        # Scope-safe: no entity IDs leak into the lowest-privilege read.
        self.assertNotIn("lock.a", resp.text)

    def test_health_pending_relocks_zero_without_manager(self) -> None:
        app = self._app()
        with TestClient(app) as client:
            resp = client.get("/api/health")
        self.assertEqual(
            resp.json()["pending_relocks"], {"total": 0, "overdue": 0}
        )


class ApiAuthIdentityTests(unittest.IsolatedAsyncioTestCase):
    async def test_verified_context_does_not_retain_raw_bearer_secret(self) -> None:
        db = SimpleNamespace(
            is_rate_limited=AsyncMock(return_value=False),
            verify_api_key=AsyncMock(
                return_value={"id": 12, "name": "HA", "scope": "locks_only"}
            ),
            clear_rate_limit=AsyncMock(),
            record_rate_limit_failure=AsyncMock(),
        )
        request = SimpleNamespace(
            client=SimpleNamespace(host="127.0.0.1"),
            app=SimpleNamespace(state=SimpleNamespace(db=db)),
        )
        credentials = SimpleNamespace(credentials="raw-secret-must-not-escape")

        context = await api_auth.verify_api_key(request, credentials)

        self.assertEqual(
            context,
            {"key_id": 12, "name": "HA", "scope": "locks_only"},
        )
        self.assertNotIn("raw-secret-must-not-escape", repr(context))


class RuleScheduleApiIntegrationTests(unittest.TestCase):
    def test_json_schedule_persists_and_invalid_update_is_atomic(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            path = Path(tempdir) / "schedule.db"
            observed: dict[str, object] = {}

            @asynccontextmanager
            async def lifespan(app: FastAPI):
                db = Database(path=path)
                await db.connect()
                user_id = await db.upsert_user(
                    "person-1", "Alex", None, "ACTIVE"
                )
                lock_id = await db.add_external_lock(
                    "lock.front", "Front", None
                )
                rule_id = await db.add_rule(user_id, lock_id, enabled=True)
                observed.update(
                    db=db,
                    user_id=user_id,
                    rule_id=rule_id,
                )
                app.state.db = db
                yield
                observed["row"] = await db.get_rule(rule_id)
                await db.close()

            app = FastAPI(lifespan=lifespan)
            app.include_router(api_routes.router)
            app.dependency_overrides[api_routes.verify_api_key] = lambda: {
                "key_id": 1,
                "name": "scheduler",
                "scope": "full",
            }

            with TestClient(app) as client:
                rule_id = observed["rule_id"]
                valid = client.put(
                    f"/api/rules/{rule_id}/schedule",
                    json={
                        "enabled": True,
                        "days": ["fri", "mon", "fri"],
                        "start": "22:00",
                        "end": "06:00",
                    },
                )
                invalid = client.put(
                    f"/api/rules/{rule_id}/schedule",
                    json={
                        "enabled": True,
                        "days": [],
                        "start": "09:00",
                        "end": None,
                    },
                )

            self.assertEqual(valid.status_code, 200)
            self.assertEqual(
                valid.json()["schedule"],
                {
                    "enabled": True,
                    "days": ["mon", "fri"],
                    "start": "22:00",
                    "end": "06:00",
                },
            )
            self.assertEqual(invalid.status_code, 422)
            row = observed["row"]
            self.assertEqual(row["enabled"], 1)
            self.assertEqual(row["schedule_enabled"], 1)
            self.assertEqual(row["schedule_days"], "mon,fri")
            self.assertEqual(row["schedule_start"], "22:00")
            self.assertEqual(row["schedule_end"], "06:00")

    def test_dashboard_form_schedule_persists_through_real_database(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            path = Path(tempdir) / "form-schedule.db"
            observed: dict[str, object] = {}

            @asynccontextmanager
            async def lifespan(app: FastAPI):
                db = Database(path=path)
                await db.connect()
                user_id = await db.upsert_user(
                    "person-form", "Morgan", None, "ACTIVE"
                )
                lock_id = await db.add_external_lock(
                    "lock.side", "Side", None
                )
                rule_id = await db.add_rule(user_id, lock_id, enabled=True)
                observed.update(user_id=user_id, rule_id=rule_id)
                app.state.db = db
                yield
                observed["row"] = await db.get_rule(rule_id)
                await db.close()

            app = FastAPI(lifespan=lifespan)
            app.include_router(web_routes.router)
            app.dependency_overrides[web_routes.require_csrf] = lambda: "admin"

            with TestClient(app) as client:
                rule_id = observed["rule_id"]
                response = client.post(
                    f"/rules/{rule_id}/schedule",
                    data={
                        "schedule_enabled": "on",
                        "schedule_start": "21:30",
                        "schedule_end": "05:45",
                        "tue": "on",
                        "sat": "on",
                    },
                    follow_redirects=False,
                )

            self.assertEqual(response.status_code, 303)
            self.assertEqual(
                response.headers["location"], f"/users/{observed['user_id']}"
            )
            row = observed["row"]
            self.assertEqual(row["enabled"], 1)
            self.assertEqual(row["schedule_enabled"], 1)
            self.assertEqual(row["schedule_days"], "tue,sat")
            self.assertEqual(row["schedule_start"], "21:30")
            self.assertEqual(row["schedule_end"], "05:45")


if __name__ == "__main__":
    unittest.main()
