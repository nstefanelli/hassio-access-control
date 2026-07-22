"""Regression tests for update_lock_settings against a real SQLite database.

Guards the e2e-review 2026-07-12 finding: the lock settings form never
renders access_location_id, so the route passing a blank form default
through was silently NULLing legacy hub pairings on every settings save.
"""
from __future__ import annotations

import asyncio
import importlib
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

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


_load_package()
db_module = importlib.import_module("access_control.database")
Database = db_module.Database


def _run(coro):
    return asyncio.run(coro)


class TestUpdateLockSettingsPreservesPairing(unittest.TestCase):
    def test_settings_save_without_location_keeps_pairing(self) -> None:
        async def go():
            db = Database(path=Path(tempfile.mkdtemp()) / "t.db")
            await db.connect()
            try:
                lock_id = await db.add_external_lock(
                    entity_id="lock.front", name="Front",
                )
                # Establish a legacy pairing explicitly.
                await db.update_lock_settings(
                    lock_id, buzz_enabled=True, relock_duration=30,
                    access_location_id="loc-1",
                )
                lock = await db.get_lock(lock_id)
                self.assertEqual(lock["access_location_id"], "loc-1")

                # The settings-form save path: no access_location_id kwarg.
                # The pairing MUST survive.
                await db.update_lock_settings(
                    lock_id, buzz_enabled=False, relock_duration=45,
                    relock_on_remote=True, sync_hub_state=True,
                )
                lock = await db.get_lock(lock_id)
                self.assertEqual(lock["access_location_id"], "loc-1")
                self.assertEqual(lock["buzz_enabled"], 0)
                self.assertEqual(lock["relock_duration"], 45)
                self.assertEqual(lock["relock_on_remote"], 1)
                self.assertEqual(lock["sync_hub_state"], 1)
            finally:
                await db.close()
        _run(go())

    def test_explicit_location_still_updates_and_clears(self) -> None:
        async def go():
            db = Database(path=Path(tempfile.mkdtemp()) / "t.db")
            await db.connect()
            try:
                lock_id = await db.add_external_lock(
                    entity_id="lock.front", name="Front",
                )
                await db.update_lock_settings(
                    lock_id, buzz_enabled=True, relock_duration=30,
                    access_location_id="loc-1",
                )
                await db.update_lock_settings(
                    lock_id, buzz_enabled=True, relock_duration=30,
                    access_location_id="loc-2",
                )
                lock = await db.get_lock(lock_id)
                self.assertEqual(lock["access_location_id"], "loc-2")

                # Explicit empty/None clears the pairing (deliberate).
                await db.update_lock_settings(
                    lock_id, buzz_enabled=True, relock_duration=30,
                    access_location_id=None,
                )
                lock = await db.get_lock(lock_id)
                self.assertIsNone(lock["access_location_id"])
            finally:
                await db.close()
        _run(go())


class TestRelockOnHaOriginColumn(unittest.TestCase):
    """Change 4 plumbing: the relock_on_ha_origin column defaults off and round
    trips through update_lock_settings."""

    def test_column_defaults_off_and_persists(self) -> None:
        async def go():
            db = Database(path=Path(tempfile.mkdtemp()) / "t.db")
            await db.connect()
            try:
                lock_id = await db.add_external_lock(
                    entity_id="lock.front", name="Front",
                )
                lock = await db.get_lock(lock_id)
                # Default off — existing installs keep current behaviour.
                self.assertEqual(lock["relock_on_ha_origin"], 0)

                await db.update_lock_settings(
                    lock_id, buzz_enabled=True, relock_duration=30,
                    sync_hub_state=True, relock_on_ha_origin=True,
                )
                lock = await db.get_lock(lock_id)
                self.assertEqual(lock["relock_on_ha_origin"], 1)
                self.assertEqual(lock["sync_hub_state"], 1)

                # Omitting the kwarg writes the default (checkbox unchecked).
                await db.update_lock_settings(
                    lock_id, buzz_enabled=True, relock_duration=30,
                    sync_hub_state=True,
                )
                lock = await db.get_lock(lock_id)
                self.assertEqual(lock["relock_on_ha_origin"], 0)
            finally:
                await db.close()
        _run(go())


class TestPreserveHoldOnRestartColumn(unittest.TestCase):
    """Graceful-restart hold preservation plumbing: the
    preserve_hold_on_restart column defaults off and round trips through
    update_lock_settings."""

    def test_column_defaults_off_and_persists(self) -> None:
        async def go():
            db = Database(path=Path(tempfile.mkdtemp()) / "t.db")
            await db.connect()
            try:
                lock_id = await db.add_external_lock(
                    entity_id="lock.front", name="Front",
                )
                lock = await db.get_lock(lock_id)
                # Default off — existing installs keep current behaviour.
                self.assertEqual(lock["preserve_hold_on_restart"], 0)

                await db.update_lock_settings(
                    lock_id, buzz_enabled=True, relock_duration=30,
                    sync_hub_state=True, preserve_hold_on_restart=True,
                )
                lock = await db.get_lock(lock_id)
                self.assertEqual(lock["preserve_hold_on_restart"], 1)

                # Omitting the kwarg writes the default (checkbox unchecked).
                await db.update_lock_settings(
                    lock_id, buzz_enabled=True, relock_duration=30,
                    sync_hub_state=True,
                )
                lock = await db.get_lock(lock_id)
                self.assertEqual(lock["preserve_hold_on_restart"], 0)
            finally:
                await db.close()
        _run(go())


class TestConfigDelete(unittest.TestCase):
    def test_delete_config_removes_key(self) -> None:
        async def go():
            db = Database(path=Path(tempfile.mkdtemp()) / "t.db")
            await db.connect()
            try:
                await db.set_config("some_key", "some_value")
                self.assertEqual(await db.get_config("some_key"), "some_value")
                await db.delete_config("some_key")
                self.assertIsNone(await db.get_config("some_key"))
                # Deleting a missing key is a no-op, not an error.
                await db.delete_config("some_key")
            finally:
                await db.close()
        _run(go())


if __name__ == "__main__":
    unittest.main()
