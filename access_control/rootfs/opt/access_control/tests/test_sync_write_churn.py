"""Regression tests for sync write-churn fixes (e2e review 2026-07-12).

upsert_user must no-op when nothing changed (the 15-minute topology
resync previously rewrote every user row — with synced_at freshly
stamped — in its own committed transaction, forever), and both upserts
must support commit=False batching.
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


class TestUpsertUserSkipsUnchanged(unittest.TestCase):
    def test_unchanged_upsert_is_a_noop(self) -> None:
        async def go():
            db = Database(path=Path(tempfile.mkdtemp()) / "t.db")
            await db.connect()
            try:
                uid = await db.upsert_user(
                    ulp_id="u-1", name="Nick", email="n@x.com", status="active",
                )
                first = await db.get_user(uid)

                # Re-sync with identical data — synced_at must NOT move
                # (proves the row wasn't rewritten).
                uid2 = await db.upsert_user(
                    ulp_id="u-1", name="Nick", email="n@x.com", status="active",
                    synced_at="2099-01-01 00:00:00",
                )
                self.assertEqual(uid2, uid)
                unchanged = await db.get_user(uid)
                self.assertEqual(unchanged["synced_at"], first["synced_at"])

                # A real change still writes (and bumps synced_at).
                await db.upsert_user(
                    ulp_id="u-1", name="Nick S", email="n@x.com", status="active",
                    synced_at="2099-01-01 00:00:00",
                )
                changed = await db.get_user(uid)
                self.assertEqual(changed["name"], "Nick S")
                self.assertEqual(changed["synced_at"], "2099-01-01 00:00:00")
            finally:
                await db.close()
        _run(go())

    def test_batched_upserts_land_on_explicit_commit(self) -> None:
        async def go():
            db = Database(path=Path(tempfile.mkdtemp()) / "t.db")
            await db.connect()
            try:
                await db.upsert_user(
                    ulp_id="u-1", name="A", email=None, status="active",
                    commit=False,
                )
                lock_id = await db.upsert_native_lock(
                    device_id="dev-1", location_id="loc-1", name="Front",
                    commit=False,
                )
                await db.commit()

                user = await db.get_user_by_ulp_id("u-1")
                self.assertIsNotNone(user)
                lock = await db.get_lock(lock_id)
                self.assertEqual(lock["device_id"], "dev-1")
            finally:
                await db.close()
        _run(go())

    def test_rollback_discards_batch(self) -> None:
        async def go():
            db = Database(path=Path(tempfile.mkdtemp()) / "t.db")
            await db.connect()
            try:
                await db.upsert_user(
                    ulp_id="u-gone", name="X", email=None, status="active",
                    commit=False,
                )
                await db.rollback()
                self.assertIsNone(await db.get_user_by_ulp_id("u-gone"))
            finally:
                await db.close()
        _run(go())


if __name__ == "__main__":
    unittest.main()
