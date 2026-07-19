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
from access_control.access_client import (
    AccessClientError,
    AccessCommandAcceptedUnconfirmedError,
    AccessCommandOutcomeUnknownError,
)
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

    async def test_dashboard_reports_accepted_unlock_as_unconfirmed(self) -> None:
        state = SimpleNamespace()
        request = SimpleNamespace(
            app=SimpleNamespace(state=state),
            scope={},
        )
        executor = AsyncMock(
            return_value=LockActionResult(
                3,
                "unlock",
                "accepted_unconfirmed",
                reason=(
                    "UniFi Access accepted the persistent unlock, "
                    "but the resulting door state is unconfirmed"
                ),
            )
        )

        with patch.object(web_routes, "execute_lock_action", executor):
            response = await web_routes._lock_action(
                3, "unlock", "admin", request
            )

        self.assertEqual(response.status_code, 303)
        location = response.headers["location"]
        self.assertIn("/locks?notice=", location)
        self.assertIn("accepted+the+persistent+unlock", location)
        self.assertIn("state+is+unconfirmed", location)

    async def test_lock_remains_available_during_lockdown(self) -> None:
        lock = {
            "id": 4,
            "type": "access_native",
            "device_id": "hub-4",
            "location_id": "door-4",
            "name": "Front",
        }
        db = _db_for(lock)
        access = SimpleNamespace(
            open_api_configured=True,
            force_lock=AsyncMock(return_value={"state": "locked"}),
        )
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

    async def test_native_unlock_accepted_but_unconfirmed_is_not_granted(
        self,
    ) -> None:
        lock = {
            "id": 16,
            "type": "access_native",
            "device_id": "hub-16",
            "location_id": "door-16",
            "name": "Front",
        }
        db = _db_for(lock)
        access = SimpleNamespace(
            hold_unlocked=AsyncMock(
                side_effect=AccessCommandAcceptedUnconfirmedError(
                    "bounded readback expired"
                )
            )
        )
        state = _state(db=db, access=access)
        state.lock_states["hub-16"] = "locked"

        result = await execute_lock_action(
            state,
            16,
            "unlock",
            actor="admin",
            source="manual",
            auto_disarm=True,
        )

        self.assertEqual(result.outcome, "accepted_unconfirmed")
        self.assertFalse(result.granted)
        self.assertIsNone(result.confirmed_state)
        self.assertIn("accepted", result.reason)
        self.assertIn("unconfirmed", result.reason)
        self.assertEqual(state.lock_states["hub-16"], "unknown")
        db.get_all_alarm_panels.assert_not_awaited()
        db.log_access.assert_awaited_once_with(
            method="manual_unlock",
            result="accepted_unconfirmed",
            lock_id=16,
            lock_name="Front",
            user_name="admin",
            reason=result.reason,
        )

    async def test_native_unlock_cancelled_after_write_is_unknown_and_audited(
        self,
    ) -> None:
        lock = {
            "id": 116,
            "type": "access_native",
            "device_id": "hub-116",
            "location_id": "door-116",
            "name": "Cancelled Native",
        }
        db = _db_for(lock)
        wrote = asyncio.Event()

        async def accepted_then_wait(
            device_id,
            *,
            location_id=None,
            on_written=None,
        ):
            self.assertEqual(device_id, "hub-116")
            if on_written is not None:
                on_written()
            wrote.set()
            await asyncio.Event().wait()

        state = _state(
            db=db,
            access=SimpleNamespace(
                open_api_configured=True,
                hold_unlocked=accepted_then_wait,
            ),
        )
        state.lock_states["hub-116"] = "locked"

        task = asyncio.create_task(
            execute_lock_action(
                state,
                116,
                "unlock",
                actor="admin",
                source="manual",
            )
        )
        await wrote.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task

        self.assertEqual(state.lock_states["hub-116"], "unknown")
        db.log_access.assert_awaited_once()
        self.assertEqual(
            db.log_access.await_args.kwargs["result"],
            "accepted_unconfirmed",
        )

    async def test_native_unlock_prewrite_rejection_remains_error(self) -> None:
        lock = {
            "id": 17,
            "type": "access_native",
            "device_id": "hub-17",
            "location_id": "door-17",
            "name": "Side",
        }
        db = _db_for(lock)
        access = SimpleNamespace(
            hold_unlocked=AsyncMock(
                side_effect=AccessClientError("write rejected")
            )
        )
        state = _state(db=db, access=access)

        result = await execute_lock_action(
            state,
            17,
            "unlock",
            actor="admin",
            source="manual",
            auto_disarm=True,
        )

        self.assertEqual(result.outcome, "error")
        self.assertFalse(result.granted)
        # A generic client/transport error cannot prove the controller did not
        # see the mutation, so the prior cache value is no longer trustworthy.
        self.assertEqual(state.lock_states["hub-17"], "unknown")
        db.get_all_alarm_panels.assert_not_awaited()

    async def test_native_transport_ambiguity_is_accepted_unconfirmed(
        self,
    ) -> None:
        lock = {
            "id": 117,
            "type": "access_native",
            "device_id": "hub-117",
            "location_id": "door-117",
            "name": "Ambiguous Native",
        }
        db = _db_for(lock)
        access = SimpleNamespace(
            hold_unlocked=AsyncMock(
                side_effect=AccessCommandOutcomeUnknownError(
                    "network timeout during PUT"
                )
            )
        )
        state = _state(db=db, access=access)
        state.lock_states["hub-117"] = "locked"

        result = await execute_lock_action(
            state,
            117,
            "unlock",
            actor="admin",
            source="manual",
        )

        self.assertEqual(result.outcome, "accepted_unconfirmed")
        self.assertFalse(result.granted)
        self.assertIn("may already be active", result.reason)
        self.assertEqual(state.lock_states["hub-117"], "unknown")
        self.assertEqual(
            db.log_access.await_args.kwargs["result"],
            "accepted_unconfirmed",
        )

    async def test_native_buzz_accepted_unconfirmed_is_not_granted(
        self,
    ) -> None:
        lock = {
            "id": 18,
            "type": "access_native",
            "device_id": "hub-18",
            "location_id": "door-18",
            "name": "Native Front",
            "buzz_enabled": 1,
        }
        db = _db_for(lock)
        access = SimpleNamespace(
            unlock_momentary_confirmed=AsyncMock(
                side_effect=AccessCommandAcceptedUnconfirmedError(
                    "bounded relay readback expired"
                )
            )
        )
        state = _state(db=db, access=access)
        state.lock_states["hub-18"] = "locked"

        result = await execute_lock_action(
            state,
            18,
            "buzz",
            actor="admin",
            source="manual",
            auto_disarm=True,
        )

        self.assertEqual(result.outcome, "accepted_unconfirmed")
        self.assertFalse(result.granted)
        self.assertIsNone(result.confirmed_state)
        self.assertIn("momentary unlock", result.reason)
        self.assertIn("unconfirmed", result.reason)
        self.assertEqual(state.lock_states["hub-18"], "unknown")
        db.get_all_alarm_panels.assert_not_awaited()
        db.log_access.assert_awaited_once_with(
            method="manual_buzz",
            result="accepted_unconfirmed",
            lock_id=18,
            lock_name="Native Front",
            user_name="admin",
            reason=result.reason,
        )

    async def test_native_buzz_releases_barrier_before_confirmation(
        self,
    ) -> None:
        lock = {
            "id": 19,
            "type": "access_native",
            "device_id": "hub-19",
            "location_id": "door-19",
            "name": "Native Side",
            "buzz_enabled": 1,
        }
        confirmation_started = asyncio.Event()
        release_confirmation = asyncio.Event()

        async def confirm_after_write(
            location_id: str,
            *,
            on_written=None,
        ) -> dict:
            self.assertEqual(location_id, "door-19")
            self.assertIsNotNone(on_written)
            on_written()
            confirmation_started.set()
            await release_confirmation.wait()
            return {"state": "unlocked"}

        state = _state(
            db=_db_for(lock),
            access=SimpleNamespace(
                unlock_momentary_confirmed=confirm_after_write
            ),
        )
        task = asyncio.create_task(
            execute_lock_action(
                state,
                19,
                "buzz",
                actor="admin",
                source="manual",
                auto_disarm=False,
            )
        )

        acquired = False
        try:
            await asyncio.wait_for(confirmation_started.wait(), timeout=1)
            await asyncio.wait_for(
                state.physical_command_lock.acquire(),
                timeout=0.25,
            )
            acquired = True
        finally:
            if acquired:
                state.physical_command_lock.release()
            release_confirmation.set()

        result = await asyncio.wait_for(task, timeout=1)
        self.assertTrue(result.granted)
        self.assertEqual(result.confirmed_state, "unlocked")
        self.assertEqual(state.lock_states["hub-19"], "unlocked")

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

    async def test_same_ha_lock_commands_cannot_overtake_readback(self) -> None:
        lock = {
            "id": 105,
            "type": "ha_external",
            "entity_id": "lock.serialized",
            "name": "Serialized",
        }
        db = _db_for(lock)
        first_confirmation_started = asyncio.Event()
        release_first_confirmation = asyncio.Event()
        confirmation_count = 0

        async def get_state(_entity_id):
            nonlocal confirmation_count
            confirmation_count += 1
            if confirmation_count == 1:
                first_confirmation_started.set()
                await release_first_confirmation.wait()
                return "unlocked"
            return "locked"

        ha = SimpleNamespace(
            unlock=AsyncMock(return_value=True),
            lock=AsyncMock(return_value=True),
            get_entity_state=AsyncMock(side_effect=get_state),
        )
        state = _state(db=db, ha=ha)

        unlock_task = asyncio.create_task(
            execute_lock_action(
                state,
                105,
                "unlock",
                actor="admin",
                source="manual",
            )
        )
        await first_confirmation_started.wait()
        lock_task = asyncio.create_task(
            execute_lock_action(
                state,
                105,
                "lock",
                actor="admin",
                source="manual",
            )
        )
        await asyncio.sleep(0)

        # The app-wide write barrier is free, but the same-entity workflow lock
        # keeps the later lock command behind the earlier exact-state readback.
        ha.lock.assert_not_awaited()

        release_first_confirmation.set()
        unlock_result, lock_result = await asyncio.gather(
            unlock_task,
            lock_task,
        )

        self.assertTrue(unlock_result.granted)
        self.assertTrue(lock_result.granted)
        ha.unlock.assert_awaited_once_with("lock.serialized")
        ha.lock.assert_awaited_once_with("lock.serialized")
        self.assertEqual(state.lock_states["lock.serialized"], "locked")

    async def test_ha_client_lease_spans_write_and_confirmation(self) -> None:
        lock = {
            "id": 205,
            "type": "ha_external",
            "entity_id": "lock.leased",
            "name": "Leased",
        }
        db = _db_for(lock)
        confirmation_started = asyncio.Event()
        release_confirmation = asyncio.Event()

        class LeasedHA:
            lease_active = False

            @asynccontextmanager
            async def operation_lease(self):
                self.lease_active = True
                try:
                    yield
                finally:
                    self.lease_active = False

            async def unlock(self, _entity_id):
                self.assert_leased()
                return True

            async def get_entity_state(self, _entity_id):
                self.assert_leased()
                confirmation_started.set()
                await release_confirmation.wait()
                self.assert_leased()
                return "unlocked"

            def assert_leased(self):
                if not self.lease_active:
                    raise AssertionError("HA operation ran outside its lease")

        ha = LeasedHA()
        state = _state(db=db, ha=ha)
        command = asyncio.create_task(
            execute_lock_action(
                state,
                205,
                "unlock",
                actor="admin",
                source="manual",
            )
        )
        await confirmation_started.wait()

        self.assertTrue(ha.lease_active)
        self.assertFalse(state.physical_command_lock.locked())

        release_confirmation.set()
        result = await command
        self.assertTrue(result.granted)
        self.assertFalse(ha.lease_active)

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

    async def test_cancel_during_ha_write_cannot_strand_paused_relock(self) -> None:
        lock = {
            "id": 16,
            "type": "ha_external",
            "entity_id": "lock.write_cancel",
            "name": "Write Cancel",
        }
        db = _db_for(lock)
        row = {"entity_id": "lock.write_cancel", "deadline": 456.0}
        paused_entities: set[str] = set()
        unlock_started = asyncio.Event()
        resume_started = asyncio.Event()
        resume_release = asyncio.Event()

        async def pause(entity_id):
            paused_entities.add(entity_id)
            return row

        async def resume(paused_row):
            resume_started.set()
            await resume_release.wait()
            paused_entities.discard(paused_row["entity_id"])

        async def unlock(_entity_id):
            unlock_started.set()
            await asyncio.Event().wait()

        relock = SimpleNamespace(
            _paused=paused_entities,
            pause=AsyncMock(side_effect=pause),
            resume=AsyncMock(side_effect=resume),
            cancel=AsyncMock(),
        )
        state = _state(
            db=db,
            ha=SimpleNamespace(
                unlock=AsyncMock(side_effect=unlock),
                get_entity_state=AsyncMock(),
            ),
            relock=relock,
        )

        task = asyncio.create_task(
            execute_lock_action(
                state, 16, "unlock", actor="admin", source="manual"
            )
        )
        await unlock_started.wait()
        task.cancel()
        await resume_started.wait()

        # A second cancellation while resume is blocked must not interrupt the
        # safety cleanup or let `_paused` survive the request.
        task.cancel()
        await asyncio.sleep(0)
        self.assertFalse(task.done())
        self.assertEqual(relock._paused, {"lock.write_cancel"})

        resume_release.set()
        with self.assertRaises(asyncio.CancelledError):
            await task

        self.assertEqual(relock._paused, set())
        relock.resume.assert_awaited_once_with(row)
        self.assertFalse(state.physical_command_lock.locked())

    async def test_cancel_during_ha_confirmation_resumes_paused_relock(self) -> None:
        lock = {
            "id": 17,
            "type": "ha_external",
            "entity_id": "lock.confirm_cancel",
            "name": "Confirm Cancel",
        }
        db = _db_for(lock)
        row = {"entity_id": "lock.confirm_cancel", "deadline": 789.0}
        paused_entities: set[str] = set()
        confirmation_started = asyncio.Event()

        async def pause(entity_id):
            paused_entities.add(entity_id)
            return row

        async def resume(paused_row):
            paused_entities.discard(paused_row["entity_id"])

        async def confirm(_entity_id):
            confirmation_started.set()
            await asyncio.Event().wait()

        relock = SimpleNamespace(
            _paused=paused_entities,
            pause=AsyncMock(side_effect=pause),
            resume=AsyncMock(side_effect=resume),
            cancel=AsyncMock(),
        )
        state = _state(
            db=db,
            ha=SimpleNamespace(
                unlock=AsyncMock(return_value=True),
                get_entity_state=AsyncMock(side_effect=confirm),
            ),
            relock=relock,
        )

        task = asyncio.create_task(
            execute_lock_action(
                state, 17, "unlock", actor="api:test", source="api"
            )
        )
        await confirmation_started.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task

        self.assertEqual(relock._paused, set())
        relock.resume.assert_awaited_once_with(row)
        relock.cancel.assert_not_awaited()
        self.assertFalse(state.physical_command_lock.locked())

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

        self.assertEqual(result.outcome, "accepted_unconfirmed")
        self.assertIn("did not confirm unlocked", result.reason)
        relock.retain_after_uncertain_unlock.assert_awaited_once_with(intent)
        relock.extend_after_success.assert_not_awaited()
        self.assertEqual(state.lock_states["lock.side"], "unknown")

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
            open_api_configured=True,
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
            actor="api:automation#8",
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
            actor="api:automation#8",
            source="api",
            auto_disarm=True,
        )

    def test_accepted_unconfirmed_unlock_returns_202(self) -> None:
        app = self._app("full")
        executor = AsyncMock(
            return_value=LockActionResult(
                9,
                "unlock",
                "accepted_unconfirmed",
                reason=(
                    "UniFi Access accepted the persistent unlock, "
                    "but the resulting door state is unconfirmed"
                ),
            )
        )
        with patch.object(api_routes, "execute_lock_action", executor):
            with TestClient(app) as client:
                response = client.put(
                    "/api/locks/9/mode", json={"mode": "hold_unlocked"}
                )

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()["result"], "accepted_unconfirmed")
        self.assertFalse(response.json()["confirmed"])
        self.assertIsNone(response.json()["confirmed_state"])
        self.assertIn("accepted", response.json()["reason"])
        self.assertIn("unconfirmed", response.json()["reason"])

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


class ApiAuditResilienceTests(unittest.TestCase):
    @staticmethod
    def _app(db) -> FastAPI:
        app = FastAPI()
        app.include_router(api_routes.router)
        app.state.db = db
        app.dependency_overrides[api_routes.verify_api_key] = lambda: {
            "key_id": 23,
            "name": "operator",
            "scope": "full",
        }
        return app

    def test_lockdown_failure_remains_503_when_audit_write_fails(self) -> None:
        db = SimpleNamespace(
            log_admin_action=AsyncMock(side_effect=OSError("audit unavailable"))
        )
        app = self._app(db)
        app.state.auth_engine = SimpleNamespace(
            lockdown=True,
            set_lockdown=AsyncMock(
                side_effect=RuntimeError("lockdown convergence incomplete")
            ),
        )

        with TestClient(app) as client:
            response = client.post("/api/lockdown?enabled=true")

        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.json()["detail"], "lockdown convergence incomplete"
        )
        db.log_admin_action.assert_awaited_once_with(
            "api:operator#23",
            "api_lockdown_set",
            "enabled",
            "result=error",
        )

    def test_successful_schedule_response_survives_audit_write_failure(
        self,
    ) -> None:
        db = SimpleNamespace(
            get_rule=AsyncMock(
                return_value={"id": 7, "user_id": 4, "enabled": 0}
            ),
            update_rule_schedule=AsyncMock(
                return_value={"user_id": 4, "enabled": 0}
            ),
            log_admin_action=AsyncMock(side_effect=OSError("audit unavailable")),
        )
        app = self._app(db)

        with TestClient(app) as client:
            response = client.put(
                "/api/rules/7/schedule",
                json={
                    "enabled": True,
                    "days": ["mon"],
                    "start": "08:00",
                    "end": "17:00",
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["enabled"])
        db.update_rule_schedule.assert_awaited_once_with(
            7,
            schedule_enabled=True,
            schedule_days="mon",
            schedule_start="08:00",
            schedule_end="17:00",
        )
        db.log_admin_action.assert_awaited_once()


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
        self.assertEqual(resp.json()["status"], "critical")
        # Scope-safe: no entity IDs leak into the lowest-privilege read.
        self.assertNotIn("lock.a", resp.text)

    def test_health_pending_relocks_zero_without_manager(self) -> None:
        app = self._app()
        with TestClient(app) as client:
            resp = client.get("/api/health")
        self.assertEqual(
            resp.json()["pending_relocks"], {"total": 0, "overdue": 0}
        )
        self.assertEqual(resp.json()["status"], "degraded")

    def test_unused_optional_protect_does_not_degrade_healthy_system(self) -> None:
        app = self._app()
        app.state.access_client = SimpleNamespace(
            connected=True,
            ws_connected=True,
            open_api_configured=False,
        )
        app.state.ha_client = SimpleNamespace(
            connected=True,
            last_error=None,
            circuit_state="closed",
        )
        app.state.db.is_protect_in_use = AsyncMock(return_value=False)

        with TestClient(app) as client:
            resp = client.get("/api/health")

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "ok")
        self.assertFalse(resp.json()["protect_connected"])
        self.assertFalse(resp.json()["protect_in_use"])

    def test_disconnected_protect_degrades_when_doorbell_path_uses_it(self) -> None:
        app = self._app()
        app.state.access_client = SimpleNamespace(
            connected=True,
            ws_connected=True,
            open_api_configured=False,
        )
        app.state.ha_client = SimpleNamespace(
            connected=True,
            last_error=None,
            circuit_state="closed",
        )
        app.state.db.is_protect_in_use = AsyncMock(return_value=True)

        with TestClient(app) as client:
            resp = client.get("/api/health")

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "degraded")
        self.assertTrue(resp.json()["protect_in_use"])


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


class DashboardRuleAuditTests(unittest.TestCase):
    def test_add_toggle_and_delete_are_attributed_to_admin(self) -> None:
        db = SimpleNamespace(
            consume_rate_limit=AsyncMock(return_value=True),
            get_rules_for_user_and_lock=AsyncMock(return_value=None),
            add_rule=AsyncMock(return_value=11),
            toggle_rule_enabled=AsyncMock(
                return_value={"user_id": 2, "enabled": 0}
            ),
            get_rule=AsyncMock(
                return_value={"id": 11, "user_id": 2, "lock_id": 3}
            ),
            delete_rule=AsyncMock(),
            log_admin_action=AsyncMock(),
        )
        app = FastAPI()
        app.include_router(web_routes.router)
        app.state.db = db
        app.dependency_overrides[web_routes.require_csrf] = lambda: "admin"

        with TestClient(app) as client:
            added = client.post(
                "/users/2/rules",
                data={"lock_id": "3"},
                follow_redirects=False,
            )
            toggled = client.post(
                "/rules/11/toggle", follow_redirects=False
            )
            deleted = client.post(
                "/rules/11/delete", follow_redirects=False
            )

        self.assertEqual(
            [added.status_code, toggled.status_code, deleted.status_code],
            [303, 303, 303],
        )
        self.assertEqual(
            [entry.args[1] for entry in db.log_admin_action.await_args_list],
            [
                "access_rule_add",
                "access_rule_toggle",
                "access_rule_delete",
            ],
        )
        for entry in db.log_admin_action.await_args_list:
            self.assertEqual(entry.args[0], "admin")
            self.assertEqual(entry.args[2], "11")


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
                observed["admin_log"] = await db.get_admin_log()
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
            audit = observed["admin_log"]
            self.assertEqual(len(audit), 1)
            self.assertEqual(audit[0]["username"], "api:scheduler#1")
            self.assertEqual(
                audit[0]["action"], "api_rule_schedule_update"
            )
            self.assertEqual(audit[0]["target"], str(observed["rule_id"]))
            self.assertNotIn("Bearer", audit[0]["detail"])

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
                observed["admin_log"] = await db.get_admin_log()
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
            audit = observed["admin_log"]
            self.assertEqual(len(audit), 1)
            self.assertEqual(audit[0]["username"], "admin")
            self.assertEqual(
                audit[0]["action"], "access_rule_schedule_update"
            )
            self.assertEqual(audit[0]["target"], str(observed["rule_id"]))


if __name__ == "__main__":
    unittest.main()
