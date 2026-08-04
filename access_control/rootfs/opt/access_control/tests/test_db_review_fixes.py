"""Regression tests for the 2026-08 database review fixes.

Covers:
- DB-1: the api_keys.key_encrypted add/drop migration churn is gone.
- DB-2: rate_limits rows with lockout_until=0 are pruned once stale.
- DB-3: the dead ui_cache table (and its index) is dropped by migration.
- DB-4: WAL runs with synchronous=NORMAL on the main connection.
- DB-8: query-path indexes exist on fresh installs and after upgrade.
- WEB-3: add_rule's OR IGNORE dedupe and recovery branch work.
- WEB-6: get_all_visitors is bounded (newest first) by default.
- Double connect() to the same file runs migrations idempotently.
"""
from __future__ import annotations

import importlib
import importlib.util
import sqlite3
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
Database = importlib.import_module("access_control.database").Database


class DbReviewFixesTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._tempdir = tempfile.TemporaryDirectory()
        self.path = Path(self._tempdir.name) / "review.db"
        self.db = Database(path=self.path)
        await self.db.connect()

    async def asyncTearDown(self) -> None:
        await self.db.close()
        self._tempdir.cleanup()

    async def _reconnect(self) -> None:
        await self.db.close()
        self.db = Database(path=self.path)
        await self.db.connect()

    async def _api_keys_columns(self) -> set[str]:
        async with self.db._db.execute("PRAGMA table_info(api_keys)") as cur:
            return {row[1] for row in await cur.fetchall()}

    async def _index_exists(self, name: str) -> bool:
        async with self.db._db.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name=?",
            (name,),
        ) as cur:
            return (await cur.fetchone()) is not None

    # ------------------------------------------------------------------
    # DB-1
    # ------------------------------------------------------------------

    async def test_key_encrypted_is_never_readded_and_legacy_column_drops(
        self,
    ) -> None:
        # Fresh install: the column must not exist.
        self.assertNotIn("key_encrypted", await self._api_keys_columns())

        # Reconnect must not re-add it (the old Migration 1 did, forcing
        # Migration 16 to DROP it again on every boot).
        await self._reconnect()
        self.assertNotIn("key_encrypted", await self._api_keys_columns())

        # A legacy database that still carries the column (with data) is
        # upgraded: Migration 16 drops it.
        await self.db.close()
        with sqlite3.connect(self.path) as legacy:
            legacy.execute("ALTER TABLE api_keys ADD COLUMN key_encrypted TEXT")
        self.db = Database(path=self.path)
        await self.db.connect()
        self.assertNotIn("key_encrypted", await self._api_keys_columns())

    async def test_repeat_connect_leaves_api_keys_schema_untouched(self) -> None:
        # The add/drop cycle rewrote api_keys each boot; a steady-state boot
        # must leave the stored table definition byte-identical.
        async with self.db._db.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='api_keys'"
        ) as cur:
            before = (await cur.fetchone())[0]
        await self._reconnect()
        async with self.db._db.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='api_keys'"
        ) as cur:
            after = (await cur.fetchone())[0]
        self.assertEqual(before, after)

    # ------------------------------------------------------------------
    # DB-2
    # ------------------------------------------------------------------

    async def _rate_limit_subjects(self) -> set[str]:
        async with self.db._db.execute("SELECT subject FROM rate_limits") as cur:
            return {row[0] for row in await cur.fetchall()}

    async def test_prune_removes_stale_zero_lockout_rows(self) -> None:
        # Allowed attempt → row with lockout_until=0.
        self.assertTrue(
            await self.db.consume_rate_limit(
                "action", "stale-allowed",
                max_attempts=20, window=60, lockout=60, now=1000.0,
            )
        )
        # Sub-threshold failure → row with lockout_until=0.
        self.assertFalse(
            await self.db.record_rate_limit_failure(
                "login", "stale-failure",
                max_attempts=5, window=300, lockout=60, now=1000.0,
            )
        )
        # Recent allowed attempt → must survive the prune.
        self.assertTrue(
            await self.db.consume_rate_limit(
                "action", "fresh-allowed",
                max_attempts=20, window=60, lockout=60, now=4000.0,
            )
        )
        self.assertEqual(
            await self._rate_limit_subjects(),
            {"stale-allowed", "stale-failure", "fresh-allowed"},
        )

        # now - default stale horizon (3600s) == 1000 → both stale rows are
        # beyond any window a caller could still count them against.
        await self.db.prune_runtime_state(now=4600.0)
        self.assertEqual(await self._rate_limit_subjects(), {"fresh-allowed"})

    async def test_prune_never_drops_an_active_lockout(self) -> None:
        for _ in range(3):
            await self.db.record_rate_limit_failure(
                "setup", "locked-subject",
                max_attempts=3, window=300, lockout=300, now=1000.0,
            )
        self.assertTrue(
            await self.db.is_rate_limited("setup", "locked-subject", now=1100.0)
        )

        # Even with an aggressive stale horizon the active lockout survives.
        await self.db.prune_runtime_state(now=1100.0, rate_limit_stale_after=1.0)
        self.assertTrue(
            await self.db.is_rate_limited("setup", "locked-subject", now=1100.0)
        )

        # Once expired, the prune reclaims it.
        await self.db.prune_runtime_state(now=1400.0, rate_limit_stale_after=1.0)
        self.assertEqual(await self._rate_limit_subjects(), set())

    # ------------------------------------------------------------------
    # DB-3
    # ------------------------------------------------------------------

    async def test_ui_cache_table_absent_on_fresh_install(self) -> None:
        async with self.db._db.execute(
            "SELECT name FROM sqlite_master WHERE name IN "
            "('ui_cache', 'idx_ui_cache_expires_at')"
        ) as cur:
            self.assertEqual(await cur.fetchall(), [])

    async def test_legacy_ui_cache_table_is_dropped_by_migration(self) -> None:
        await self.db.close()
        with sqlite3.connect(self.path) as legacy:
            legacy.execute(
                """CREATE TABLE IF NOT EXISTS ui_cache (
                    key        TEXT PRIMARY KEY,
                    value_json TEXT NOT NULL,
                    expires_at REAL NOT NULL
                )"""
            )
            legacy.execute(
                "CREATE INDEX IF NOT EXISTS idx_ui_cache_expires_at "
                "ON ui_cache(expires_at)"
            )
            legacy.execute(
                "INSERT INTO ui_cache VALUES ('stale', '[]', 123.0)"
            )

        self.db = Database(path=self.path)
        await self.db.connect()
        async with self.db._db.execute(
            "SELECT name FROM sqlite_master WHERE name IN "
            "('ui_cache', 'idx_ui_cache_expires_at')"
        ) as cur:
            self.assertEqual(await cur.fetchall(), [])

    # ------------------------------------------------------------------
    # DB-4
    # ------------------------------------------------------------------

    async def test_main_connection_runs_wal_with_synchronous_normal(self) -> None:
        async with self.db._db.execute("PRAGMA journal_mode") as cur:
            self.assertEqual((await cur.fetchone())[0], "wal")
        async with self.db._db.execute("PRAGMA synchronous") as cur:
            self.assertEqual((await cur.fetchone())[0], 1)  # 1 == NORMAL

    # ------------------------------------------------------------------
    # DB-8
    # ------------------------------------------------------------------

    QUERY_PATH_INDEXES = (
        "idx_entry_dev_type_device",
        "idx_entry_dev_type_entity",
        "idx_group_members_user",
    )

    async def test_query_path_indexes_exist_on_fresh_install(self) -> None:
        for name in self.QUERY_PATH_INDEXES:
            self.assertTrue(await self._index_exists(name), name)

    async def test_query_path_indexes_are_backfilled_on_upgrade(self) -> None:
        await self.db.close()
        with sqlite3.connect(self.path) as legacy:
            for name in self.QUERY_PATH_INDEXES:
                legacy.execute(f"DROP INDEX IF EXISTS {name}")
        self.db = Database(path=self.path)
        await self.db.connect()
        for name in self.QUERY_PATH_INDEXES:
            self.assertTrue(await self._index_exists(name), name)

    # ------------------------------------------------------------------
    # WEB-3
    # ------------------------------------------------------------------

    async def test_add_rule_second_insert_is_ignored_and_recovers_id(
        self,
    ) -> None:
        self.assertTrue(await self._index_exists("idx_access_rules_user_lock"))
        user_id = await self.db.upsert_user(
            "dedupe-person", "Dedupe Person", None, "ACTIVE"
        )
        lock_id = await self.db.add_external_lock(
            "lock.dedupe_target", "Dedupe Target", None
        )

        first = await self.db.add_rule(user_id, lock_id)
        # Double submit: the INSERT OR IGNORE hits the unique index and the
        # recovery branch returns the existing rule id.
        second = await self.db.add_rule(user_id, lock_id, enabled=False)
        self.assertEqual(first, second)

        async with self.db._db.execute(
            "SELECT COUNT(*), MAX(enabled) FROM access_rules "
            "WHERE user_id = ? AND lock_id = ?",
            (user_id, lock_id),
        ) as cur:
            count, enabled = await cur.fetchone()
        self.assertEqual(count, 1)
        # The ignored duplicate must not have overwritten the original policy.
        self.assertEqual(enabled, 1)

    # ------------------------------------------------------------------
    # WEB-6
    # ------------------------------------------------------------------

    async def test_get_all_visitors_is_bounded_newest_first(self) -> None:
        ids = []
        for n in range(3):
            ids.append(
                await self.db.add_visitor(f"visitor-{n}", f"V{n}", "s", "e")
            )
        # Force distinct, ordered created_at values (schema default is
        # second-granular so same-second inserts would tie).
        for n, visitor_id in enumerate(ids):
            await self.db._db.execute(
                "UPDATE visitors SET created_at = ? WHERE id = ?",
                (f"2026-08-0{n + 1} 00:00:00", visitor_id),
            )
        await self.db._db.commit()

        newest_two = await self.db.get_all_visitors(limit=2)
        self.assertEqual([v["id"] for v in newest_two], [ids[2], ids[1]])

        # Default keeps existing callers working (bounded at 500).
        self.assertEqual(len(await self.db.get_all_visitors()), 3)
        # Explicit opt-out returns the full history.
        self.assertEqual(len(await self.db.get_all_visitors(limit=None)), 3)

    # ------------------------------------------------------------------
    # Migration idempotency
    # ------------------------------------------------------------------

    async def test_double_connect_is_idempotent(self) -> None:
        def schema_dump() -> list[tuple]:
            with sqlite3.connect(self.path) as raw:
                return raw.execute(
                    "SELECT type, name, tbl_name, sql FROM sqlite_master "
                    "ORDER BY type, name"
                ).fetchall()

        await self.db.close()
        first = schema_dump()
        self.db = Database(path=self.path)
        await self.db.connect()
        await self.db.close()
        second = schema_dump()
        self.assertEqual(first, second)

        self.db = Database(path=self.path)
        await self.db.connect()


if __name__ == "__main__":
    unittest.main()
