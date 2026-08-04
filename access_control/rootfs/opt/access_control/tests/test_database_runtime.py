"""Database concurrency, cache, and atomic topology regression tests."""
from __future__ import annotations

import asyncio
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


class DatabaseRuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._tempdir = tempfile.TemporaryDirectory()
        self.path = Path(self._tempdir.name) / "runtime.db"
        self.db = Database(path=self.path)
        await self.db.connect()

    async def asyncTearDown(self) -> None:
        await self.db.close()
        self._tempdir.cleanup()

    async def test_concurrent_rate_limit_operations_are_serialized(self) -> None:
        allowed = await asyncio.gather(
            *(
                self.db.consume_rate_limit(
                    "action",
                    "same-subject",
                    max_attempts=20,
                    window=300,
                    lockout=60,
                    now=100.0,
                )
                for _ in range(25)
            )
        )
        self.assertEqual(sum(allowed), 20)
        self.assertTrue(
            await self.db.is_rate_limited("action", "same-subject", now=100.0)
        )

        await self.db.clear_rate_limit("action", "same-subject")
        failures = await asyncio.gather(
            *(
                self.db.record_rate_limit_failure(
                    "login",
                    "same-subject",
                    max_attempts=20,
                    window=300,
                    lockout=60,
                    now=200.0,
                )
                for _ in range(25)
            )
        )
        # The threshold-reaching call and every later call observe the
        # existing lockout; concurrent failures cannot accidentally clear it.
        self.assertEqual(sum(failures), 6)
        self.assertTrue(
            await self.db.is_rate_limited("login", "same-subject", now=200.0)
        )

    async def test_clear_missing_rate_limit_does_not_issue_delete(self) -> None:
        statements: list[str] = []
        await self.db._db.set_trace_callback(statements.append)
        await self.db.clear_rate_limit("api", "never-failed")
        self.assertFalse(
            any(statement.lstrip().upper().startswith("DELETE") for statement in statements),
            statements,
        )

    async def test_ui_cache_is_copying_expiring_and_non_persistent(self) -> None:
        original = {"nested": [1, {"value": "original"}]}
        await self.db.set_ui_cache("key", original, ttl=10, now=100.0)

        # JSON storage semantics provide a deep copy on both write and read.
        original["nested"][1]["value"] = "mutated-after-write"
        first = await self.db.get_ui_cache("key", now=105.0)
        self.assertEqual(first, {"nested": [1, {"value": "original"}]})
        first["nested"][1]["value"] = "mutated-after-read"
        self.assertEqual(
            await self.db.get_ui_cache("key", now=105.0),
            {"nested": [1, {"value": "original"}]},
        )
        self.assertIsNone(await self.db.get_ui_cache("key", now=110.0))

        await self.db.set_ui_cache("restart-key", ["value"], ttl=60, now=100.0)
        # The cache is purely in-process now: the legacy ui_cache table is
        # dropped by migration and never recreated.
        async with self.db._db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='ui_cache'"
        ) as cursor:
            self.assertIsNone(await cursor.fetchone())
        await self.db.close()

        restarted = Database(path=self.path)
        await restarted.connect()
        try:
            self.assertIsNone(
                await restarted.get_ui_cache("restart-key", now=101.0)
            )
        finally:
            await restarted.close()

    async def test_peek_ui_cache_serves_stale_without_evicting(self) -> None:
        # Missing key: no value, not fresh.
        self.assertEqual(
            await self.db.peek_ui_cache("missing", now=100.0), (None, False)
        )

        await self.db.set_ui_cache("swr", {"n": 1}, ttl=10, now=100.0)
        # Within TTL → fresh.
        self.assertEqual(
            await self.db.peek_ui_cache("swr", now=105.0), ({"n": 1}, True)
        )
        # Past TTL → the value is still served (stale) and, crucially, NOT
        # evicted: the stale-while-revalidate path reuses it while a background
        # refresh runs. Repeated stale peeks keep returning it.
        self.assertEqual(
            await self.db.peek_ui_cache("swr", now=200.0), ({"n": 1}, False)
        )
        self.assertEqual(
            await self.db.peek_ui_cache("swr", now=200.0), ({"n": 1}, False)
        )
        # get_ui_cache keeps its original contract: expiry evicts and returns None.
        self.assertIsNone(await self.db.get_ui_cache("swr", now=200.0))
        self.assertEqual(
            await self.db.peek_ui_cache("swr", now=200.0), (None, False)
        )

    async def test_prune_cache_does_not_touch_sqlite_ui_cache(self) -> None:
        await self.db.set_ui_cache("expired", {"x": 1}, ttl=1, now=10.0)
        statements: list[str] = []
        await self.db._db.set_trace_callback(statements.append)
        await self.db.prune_runtime_state(now=20.0)
        self.assertIsNone(await self.db.get_ui_cache("expired", now=20.0))
        self.assertFalse(any("UI_CACHE" in statement.upper() for statement in statements))

    async def test_access_rule_business_key_is_idempotent_under_concurrency(
        self,
    ) -> None:
        user_id = await self.db.upsert_user(
            "rule-person", "Rule Person", None, "ACTIVE"
        )
        lock_id = await self.db.add_external_lock(
            "lock.rule_target", "Rule Target", None
        )

        rule_ids = await asyncio.gather(
            *(self.db.add_rule(user_id, lock_id) for _ in range(20))
        )

        self.assertEqual(len(set(rule_ids)), 1)
        await self.db.close()
        self.db = Database(path=self.path)
        await self.db.connect()
        async with self.db._db.execute(
            """SELECT COUNT(*) FROM access_rules
               WHERE user_id = ? AND lock_id = ?""",
            (user_id, lock_id),
        ) as cursor:
            self.assertEqual((await cursor.fetchone())[0], 1)

    async def test_concurrent_rule_toggle_and_schedule_update_do_not_lose_policy(
        self,
    ) -> None:
        user_id = await self.db.upsert_user(
            "atomic-rule-person", "Atomic Rule Person", None, "ACTIVE"
        )
        lock_id = await self.db.add_external_lock(
            "lock.atomic_rule", "Atomic Rule", None
        )
        rule_id = await self.db.add_rule(user_id, lock_id, enabled=True)

        toggle, schedule = await asyncio.gather(
            self.db.toggle_rule_enabled(rule_id),
            self.db.update_rule_schedule(
                rule_id,
                schedule_enabled=True,
                schedule_days="mon,fri",
                schedule_start="08:00",
                schedule_end="17:00",
            ),
        )

        self.assertEqual(toggle["enabled"], 0)
        self.assertEqual(schedule["user_id"], user_id)
        row = await self.db.get_rule(rule_id)
        self.assertEqual(row["enabled"], 0)
        self.assertEqual(row["schedule_enabled"], 1)
        self.assertEqual(row["schedule_days"], "mon,fri")
        self.assertEqual(row["schedule_start"], "08:00")
        self.assertEqual(row["schedule_end"], "17:00")

    async def test_protect_usage_tracks_durable_doorbell_mappings(self) -> None:
        self.assertFalse(await self.db.is_protect_in_use())
        lock_id = await self.db.add_external_lock(
            "lock.protect_entry", "Protect Entry", None
        )
        await self.db.add_entry_device(
            lock_id,
            "access_reader",
            "Access Reader",
            device_id="reader-1",
        )
        self.assertFalse(await self.db.is_protect_in_use())
        await self.db.add_entry_device(
            lock_id,
            "protect_doorbell",
            "Protect Doorbell",
            device_id="camera-1",
        )
        self.assertTrue(await self.db.is_protect_in_use())

    async def test_conflicting_legacy_duplicate_rules_migrate_fail_closed(
        self,
    ) -> None:
        user_id = await self.db.upsert_user(
            "legacy-rule-person", "Legacy Rule Person", None, "ACTIVE"
        )
        lock_id = await self.db.add_external_lock(
            "lock.legacy_rule", "Legacy Rule", None
        )
        survivor_id = await self.db.add_rule(
            user_id,
            lock_id,
            enabled=True,
            schedule_enabled=True,
            schedule_days="mon",
            schedule_start="08:00",
            schedule_end="09:00",
        )
        await self.db._db.execute("DROP INDEX idx_access_rules_user_lock")
        await self.db._db.execute(
            """INSERT INTO access_rules
                   (user_id, lock_id, enabled, schedule_enabled,
                    schedule_days, schedule_start, schedule_end)
               VALUES (?, ?, 1, 1, 'tue', '18:00', '19:00')""",
            (user_id, lock_id),
        )
        await self.db.close()

        self.db = Database(path=self.path)
        await self.db.connect()

        async with self.db._db.execute(
            """SELECT * FROM access_rules
               WHERE user_id = ? AND lock_id = ?""",
            (user_id, lock_id),
        ) as cursor:
            rows = await cursor.fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], survivor_id)
        self.assertEqual(rows[0]["enabled"], 0)
        self.assertEqual(rows[0]["schedule_enabled"], 0)
        self.assertIsNone(rows[0]["schedule_days"])
        with self.assertRaises(sqlite3.IntegrityError):
            await self.db._db.execute(
                "INSERT INTO access_rules (user_id, lock_id) VALUES (?, ?)",
                (user_id, lock_id),
            )

    async def test_identical_legacy_duplicate_rules_preserve_oldest_policy(
        self,
    ) -> None:
        user_id = await self.db.upsert_user(
            "identical-rule-person", "Identical Rule Person", None, "ACTIVE"
        )
        lock_id = await self.db.add_external_lock(
            "lock.identical_rule", "Identical Rule", None
        )
        survivor_id = await self.db.add_rule(
            user_id,
            lock_id,
            enabled=True,
            schedule_enabled=True,
            schedule_days="mon,tue",
            schedule_start="08:00",
            schedule_end="17:00",
        )
        await self.db._db.execute("DROP INDEX idx_access_rules_user_lock")
        await self.db._db.execute(
            """INSERT INTO access_rules
                   (user_id, lock_id, enabled, schedule_enabled,
                    schedule_days, schedule_start, schedule_end)
               VALUES (?, ?, 1, 1, 'mon,tue', '08:00', '17:00')""",
            (user_id, lock_id),
        )
        await self.db.close()

        self.db = Database(path=self.path)
        await self.db.connect()

        async with self.db._db.execute(
            """SELECT * FROM access_rules
               WHERE user_id = ? AND lock_id = ?""",
            (user_id, lock_id),
        ) as cursor:
            rows = await cursor.fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], survivor_id)
        self.assertEqual(rows[0]["enabled"], 1)
        self.assertEqual(rows[0]["schedule_enabled"], 1)
        self.assertEqual(rows[0]["schedule_days"], "mon,tue")
        self.assertEqual(rows[0]["schedule_start"], "08:00")
        self.assertEqual(rows[0]["schedule_end"], "17:00")

    async def test_legacy_hub_sync_hold_migrates_location_and_override_type(
        self,
    ) -> None:
        hub_lock_id = await self.db.upsert_native_lock(
            "hub-front", "door-front", "Front Door Hub"
        )
        await self.db.close()

        # Recreate the table exactly as it existed before official Access API
        # door identifiers and durable keep-lock ownership were introduced.
        with sqlite3.connect(self.path) as legacy:
            legacy.execute("DROP TABLE hub_sync_holds")
            legacy.execute(
                """CREATE TABLE hub_sync_holds (
                    entity_id     TEXT    NOT NULL,
                    hub_device_id TEXT    NOT NULL,
                    hub_lock_id   INTEGER,
                    hub_name      TEXT    NOT NULL,
                    created_at    REAL    NOT NULL,
                    PRIMARY KEY (entity_id, hub_device_id)
                )"""
            )
            legacy.execute(
                """INSERT INTO hub_sync_holds
                       (entity_id, hub_device_id, hub_lock_id, hub_name, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    "lock.front",
                    "hub-front",
                    hub_lock_id,
                    "Front Door Hub",
                    1234.0,
                ),
            )

        self.db = Database(path=self.path)
        await self.db.connect()

        self.assertEqual(
            await self.db.get_hub_sync_holds(),
            [{
                "entity_id": "lock.front",
                "hub_device_id": "hub-front",
                "hub_lock_id": hub_lock_id,
                "hub_location_id": "door-front",
                "hub_name": "Front Door Hub",
                "override_type": "keep_unlock",
                "created_at": 1234.0,
            }],
        )

    async def test_keep_lock_hold_roundtrips_location_across_restart(self) -> None:
        await self.db.record_hub_sync_hold(
            "lock.front",
            "hub-front",
            7,
            "Front Door Hub",
            hub_location_id="door-front",
            override_type="keep_lock",
            now=5678.0,
        )
        await self.db.close()

        self.db = Database(path=self.path)
        await self.db.connect()

        self.assertEqual(
            await self.db.get_hub_sync_holds(),
            [{
                "entity_id": "lock.front",
                "hub_device_id": "hub-front",
                "hub_lock_id": 7,
                "hub_location_id": "door-front",
                "hub_name": "Front Door Hub",
                "override_type": "keep_lock",
                "created_at": 5678.0,
            }],
        )

    async def test_topology_sync_is_noop_for_unchanged_rows_and_guards_empty_users(self) -> None:
        await self.db._db.executescript(
            """
            CREATE TABLE topology_writes (kind TEXT NOT NULL);
            CREATE TRIGGER count_user_insert AFTER INSERT ON users
            BEGIN INSERT INTO topology_writes VALUES ('user_insert'); END;
            CREATE TRIGGER count_user_update AFTER UPDATE ON users
            BEGIN INSERT INTO topology_writes VALUES ('user_update'); END;
            CREATE TRIGGER count_lock_insert AFTER INSERT ON locks
            BEGIN INSERT INTO topology_writes VALUES ('lock_insert'); END;
            CREATE TRIGGER count_lock_update AFTER UPDATE ON locks
            BEGIN INSERT INTO topology_writes VALUES ('lock_update'); END;
            """
        )
        await self.db.commit()

        users = [
            {"ulp_id": "u-1", "name": "One", "email": "one@example.test", "status": "active"},
            {"ulp_id": "u-2", "name": "Two", "email": None, "status": "active"},
        ]
        locks = [
            {"device_id": "hub-1", "location_id": "door-1", "name": "Front", "door_name": "Front Door"}
        ]
        first = await self.db.sync_topology(users, locks)
        self.assertEqual(first["users_inserted"], 2)
        self.assertEqual(first["locks_inserted"], 1)

        await self.db._db.execute("DELETE FROM topology_writes")
        await self.db.commit()
        second = await self.db.sync_topology(users, locks)
        self.assertEqual(second["users_unchanged"], 2)
        self.assertEqual(second["locks_unchanged"], 1)
        self.assertEqual(second["users_updated"], 0)
        self.assertEqual(second["locks_updated"], 0)
        async with self.db._db.execute("SELECT kind FROM topology_writes") as cursor:
            self.assertEqual(await cursor.fetchall(), [])

        guarded = await self.db.sync_topology([], locks)
        self.assertEqual(guarded["empty_user_guard"], 1)
        self.assertEqual(guarded["users_marked_deleted"], 0)
        self.assertEqual((await self.db.get_user_by_ulp_id("u-1"))["status"], "active")
        self.assertEqual((await self.db.get_user_by_ulp_id("u-2"))["status"], "active")

    async def test_native_lock_retirement_is_hidden_and_revival_restores_it(self) -> None:
        users = [{
            "ulp_id": "u-1",
            "name": "One",
            "email": None,
            "status": "active",
        }]
        front = {
            "device_id": "hub-front",
            "location_id": "door-front",
            "name": "Front",
            "door_name": "Front Door",
        }
        side = {
            "device_id": "hub-side",
            "location_id": "door-side",
            "name": "Side",
            "door_name": "Side Door",
        }
        await self.db.sync_topology(users, [front, side])

        retired = await self.db.sync_topology(users, [front])

        self.assertEqual(retired["locks_marked_missing"], 1)
        self.assertIsNone(await self.db.get_lock_by_location("door-side"))
        self.assertEqual(
            await self.db.get_locks_for_location(
                "door-side", include_hidden=True
            ),
            [],
        )
        self.assertEqual(await self.db.get_lock_count(), 1)
        historical = {
            lock["location_id"]: lock
            for lock in await self.db.get_all_locks(include_hidden=True)
        }
        self.assertEqual(historical["door-side"]["upstream_present"], 0)

        revived_side = {**side, "name": "Side (renamed)"}
        revived = await self.db.sync_topology(users, [front, revived_side])

        self.assertEqual(revived["locks_updated"], 1)
        restored = await self.db.get_lock_by_location("door-side")
        self.assertIsNotNone(restored)
        self.assertEqual(restored["upstream_present"], 1)
        self.assertEqual(restored["name"], "Side (renamed)")
        self.assertEqual(await self.db.get_lock_count(), 2)

    async def test_empty_lock_snapshot_does_not_retire_existing_native_locks(self) -> None:
        users = [{
            "ulp_id": "u-1",
            "name": "One",
            "email": None,
            "status": "active",
        }]
        front = {
            "device_id": "hub-front",
            "location_id": "door-front",
            "name": "Front",
            "door_name": "Front Door",
        }
        await self.db.sync_topology(users, [front])

        guarded = await self.db.sync_topology(users, [])

        self.assertEqual(guarded["locks_seen"], 0)
        self.assertEqual(guarded["locks_marked_missing"], 0)
        preserved = await self.db.get_lock_by_location("door-front")
        self.assertIsNotNone(preserved)
        self.assertEqual(preserved["upstream_present"], 1)

    async def test_topology_sync_rolls_back_every_table_on_failure(self) -> None:
        await self.db.upsert_user("existing", "Existing", None, "active")
        await self.db._db.executescript(
            """
            CREATE TRIGGER reject_broken_topology BEFORE INSERT ON locks
            WHEN NEW.location_id = 'broken-location'
            BEGIN SELECT RAISE(ABORT, 'simulated topology failure'); END;
            """
        )
        await self.db.commit()

        with self.assertRaises(sqlite3.IntegrityError):
            await self.db.sync_topology(
                [{"ulp_id": "new-user", "name": "New", "status": "active"}],
                [{
                    "device_id": "broken-hub",
                    "location_id": "broken-location",
                    "name": "Broken",
                }],
            )

        self.assertIsNone(await self.db.get_user_by_ulp_id("new-user"))
        existing = await self.db.get_user_by_ulp_id("existing")
        self.assertEqual(existing["status"], "active")
        self.assertIsNone(await self.db.get_lock_by_location("broken-location"))

    async def test_set_configs_is_atomic_on_failure(self) -> None:
        await self.db.set_configs({"bundle-a": "old-a", "unrelated": "old"})
        await self.db._db.executescript(
            """
            CREATE TRIGGER reject_torn_config BEFORE INSERT ON config
            WHEN NEW.key = 'bundle-b' AND NEW.value = 'reject'
            BEGIN SELECT RAISE(ABORT, 'simulated config failure'); END;
            """
        )
        await self.db.commit()

        with self.assertRaises(sqlite3.IntegrityError):
            await self.db.set_configs(
                {"bundle-a": "new-a", "bundle-b": "reject"}
            )

        # The first executemany item was applied before the trigger rejected
        # the second; rollback must restore the entire logical bundle.
        self.assertEqual(await self.db.get_config("bundle-a"), "old-a")
        self.assertIsNone(await self.db.get_config("bundle-b"))
        self.assertEqual(await self.db.get_config("unrelated"), "old")

        await self.db.set_configs({"bundle-a": "new-a", "bundle-c": "new-c"})
        self.assertEqual(await self.db.get_config("bundle-a"), "new-a")
        self.assertEqual(await self.db.get_config("bundle-c"), "new-c")

    async def test_active_visitors_and_single_pending_relock_helpers(self) -> None:
        active_id = await self.db.add_visitor(
            "visitor-active", "Active", "start", "end", status=1
        )
        await self.db.add_visitor(
            "visitor-expired", "Expired", "start", "end", status=4
        )
        self.assertEqual(
            [visitor["id"] for visitor in await self.db.get_active_visitors()],
            [active_id],
        )

        await self.db.add_pending_relock(
            "lock.front", 1, "Front", "buzz", deadline=123.0, now=100.0
        )
        row = await self.db.get_pending_relock("lock.front")
        self.assertEqual(row["deadline"], 123.0)
        self.assertIsNone(await self.db.get_pending_relock("lock.missing"))

    async def test_hub_sync_convergence_state_round_trips_and_clears(self) -> None:
        await self.db.set_hub_sync_state(
            entity_id="lock.front",
            desired_state="unlocked",
            source="access_schedule",
            ha_state="unlocked",
            access_state="unlocked",
            access_rule_fingerprint='{"type":"schedule"}',
            pairing_signature='["hub-front"]',
            now=123.0,
        )
        rows = await self.db.get_hub_sync_states()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["entity_id"], "lock.front")
        self.assertEqual(rows[0]["source"], "access_schedule")
        self.assertEqual(rows[0]["updated_at"], 123.0)

        await self.db.set_hub_sync_state(
            entity_id="lock.front",
            desired_state="locked",
            source="ha",
            ha_state="locked",
            access_state="locked",
            access_rule_fingerprint='{"type":"lock_early"}',
            pairing_signature='["hub-front"]',
            now=456.0,
        )
        rows = await self.db.get_hub_sync_states()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["desired_state"], "locked")
        self.assertEqual(rows[0]["updated_at"], 456.0)

        await self.db.clear_hub_sync_state("lock.front")
        self.assertEqual(await self.db.get_hub_sync_states(), [])

    async def test_hub_sync_convergence_rejects_unknown_state(self) -> None:
        with self.assertRaisesRegex(ValueError, "desired_state"):
            await self.db.set_hub_sync_state(
                entity_id="lock.front",
                desired_state="unknown",
                source="test",
                ha_state="locked",
                access_state="locked",
                access_rule_fingerprint="rule",
                pairing_signature="[]",
            )

    async def _index_exists(self, name: str) -> bool:
        async with self.db._db.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name=?", (name,)
        ) as cur:
            return (await cur.fetchone()) is not None

    async def test_admin_log_and_visitors_indexes_exist_on_fresh_init(self) -> None:
        self.assertTrue(await self._index_exists("idx_admin_log_timestamp"))
        self.assertTrue(await self._index_exists("idx_visitors_created_at"))

    async def test_admin_log_and_visitors_indexes_are_added_by_migration(
        self,
    ) -> None:
        await self.db.close()

        # Recreate admin_log and visitors exactly as they existed before
        # Migration 24 added the timestamp/created_at indexes, to prove an
        # upgrade from an older install backfills them too.
        with sqlite3.connect(self.path) as legacy:
            legacy.execute("DROP INDEX IF EXISTS idx_admin_log_timestamp")
            legacy.execute("DROP INDEX IF EXISTS idx_visitors_created_at")

        with sqlite3.connect(self.path) as legacy:
            rows = legacy.execute(
                "SELECT name FROM sqlite_master WHERE type='index' "
                "AND name IN ('idx_admin_log_timestamp', 'idx_visitors_created_at')"
            ).fetchall()
        self.assertEqual(rows, [])

        self.db = Database(path=self.path)
        await self.db.connect()

        self.assertTrue(await self._index_exists("idx_admin_log_timestamp"))
        self.assertTrue(await self._index_exists("idx_visitors_created_at"))


if __name__ == "__main__":
    unittest.main()
