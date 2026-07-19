from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import aiosqlite

_LOGGER = logging.getLogger(__name__)

DB_PATH = Path(os.environ.get("DATA_DIR", str(Path(__file__).parent / "data"))) / "access_control.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ulp_id     TEXT    NOT NULL UNIQUE,
    name       TEXT    NOT NULL,
    email      TEXT,
    status     TEXT    NOT NULL DEFAULT 'active',
    hidden     INTEGER NOT NULL DEFAULT 0,
    synced_at  TEXT
);

CREATE TABLE IF NOT EXISTS locks (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    type                TEXT    NOT NULL,
    device_id           TEXT,
    location_id         TEXT,
    entity_id           TEXT,
    name                TEXT    NOT NULL,
    door_name           TEXT,
    buzz_enabled        INTEGER NOT NULL DEFAULT 1,
    buzz_duration       INTEGER NOT NULL DEFAULT 30,
    remote_buzz_enabled INTEGER NOT NULL DEFAULT 0,
    access_location_id  TEXT,
    sync_hub_state      INTEGER NOT NULL DEFAULT 0,
    relock_on_ha_origin INTEGER NOT NULL DEFAULT 0,
    upstream_present    INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS access_rules (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id          INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    lock_id          INTEGER NOT NULL REFERENCES locks(id) ON DELETE CASCADE,
    enabled          INTEGER NOT NULL DEFAULT 1,
    schedule_enabled INTEGER NOT NULL DEFAULT 0,
    schedule_days    TEXT,
    schedule_start   TEXT,
    schedule_end     TEXT,
    created_at       TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at       TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS access_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT    NOT NULL DEFAULT (datetime('now')),
    user_id   INTEGER,
    user_name TEXT,
    lock_id   INTEGER,
    lock_name TEXT,
    method    TEXT    NOT NULL,
    result    TEXT    NOT NULL,
    reason    TEXT
);

CREATE TABLE IF NOT EXISTS groups (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    name                    TEXT    NOT NULL UNIQUE,
    description             TEXT,
    all_locks               INTEGER NOT NULL DEFAULT 0,
    blocked_when_armed_away INTEGER NOT NULL DEFAULT 0,
    blocked_when_armed_home INTEGER NOT NULL DEFAULT 0,
    can_disarm              INTEGER NOT NULL DEFAULT 1,
    schedule_enabled        INTEGER NOT NULL DEFAULT 0,
    schedule_days           TEXT,
    schedule_start          TEXT,
    schedule_end            TEXT,
    created_at              TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS group_members (
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);

CREATE TABLE IF NOT EXISTS group_locks (
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    lock_id  INTEGER NOT NULL REFERENCES locks(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, lock_id)
);

CREATE TABLE IF NOT EXISTS entry_devices (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    lock_id     INTEGER NOT NULL REFERENCES locks(id) ON DELETE CASCADE,
    type        TEXT    NOT NULL,
    device_id   TEXT,
    entity_id   TEXT,
    name        TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS alarm_panels (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id   TEXT    NOT NULL UNIQUE,
    name        TEXT    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS api_keys (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT    NOT NULL,
    key_hash      TEXT    NOT NULL UNIQUE,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS admin_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT    NOT NULL DEFAULT (datetime('now')),
    username  TEXT    NOT NULL,
    action    TEXT    NOT NULL,
    target    TEXT,
    detail    TEXT
);

CREATE TABLE IF NOT EXISTS visitors (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    unvr_visitor_id   TEXT    NOT NULL UNIQUE,
    name              TEXT    NOT NULL,
    location_id       TEXT,
    location_name     TEXT,
    pin_encrypted     TEXT,
    start_time        TEXT    NOT NULL,
    end_time          TEXT    NOT NULL,
    unvr_schedule_id  TEXT,
    status            INTEGER NOT NULL DEFAULT 1,
    created_by        TEXT,
    created_at        TEXT    NOT NULL DEFAULT (datetime('now')),
    notes             TEXT
);

CREATE TABLE IF NOT EXISTS rate_limits (
    scope         TEXT NOT NULL,
    subject       TEXT NOT NULL,
    attempts_json TEXT NOT NULL DEFAULT '[]',
    lockout_until REAL NOT NULL DEFAULT 0,
    PRIMARY KEY (scope, subject)
);

CREATE TABLE IF NOT EXISTS ui_cache (
    key        TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    expires_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS pending_relocks (
    entity_id  TEXT PRIMARY KEY,
    lock_id    INTEGER,
    lock_name  TEXT,
    source     TEXT NOT NULL,
    deadline   REAL NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS hub_sync_holds (
    entity_id       TEXT    NOT NULL,
    hub_device_id   TEXT    NOT NULL,
    hub_lock_id     INTEGER,
    hub_location_id TEXT,
    hub_name        TEXT    NOT NULL,
    override_type   TEXT    NOT NULL DEFAULT 'keep_unlock',
    created_at      REAL    NOT NULL,
    PRIMARY KEY (entity_id, hub_device_id)
);

CREATE TABLE IF NOT EXISTS hub_sync_state (
    entity_id              TEXT PRIMARY KEY,
    desired_state          TEXT NOT NULL,
    source                 TEXT NOT NULL,
    ha_state               TEXT NOT NULL,
    access_state           TEXT NOT NULL,
    access_rule_fingerprint TEXT NOT NULL,
    pairing_signature      TEXT NOT NULL,
    updated_at             REAL NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_entry_dev_device ON entry_devices(lock_id, type, device_id) WHERE device_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_entry_dev_entity ON entry_devices(lock_id, type, entity_id) WHERE entity_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_access_rules_user   ON access_rules(user_id);
CREATE INDEX IF NOT EXISTS idx_access_rules_lock   ON access_rules(lock_id);
CREATE INDEX IF NOT EXISTS idx_access_log_timestamp ON access_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_access_log_lock_ts  ON access_log(lock_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_access_log_user_ts  ON access_log(user_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_ui_cache_expires_at ON ui_cache(expires_at);
CREATE INDEX IF NOT EXISTS idx_visitors_status ON visitors(status);
CREATE INDEX IF NOT EXISTS idx_admin_log_timestamp ON admin_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_visitors_created_at ON visitors(created_at);
"""


def _row_to_dict(row: aiosqlite.Row) -> dict[str, Any]:
    return dict(row)


def _utc_now_sqlite() -> str:
    """
    Produce a UTC timestamp string compatible with SQLite's `datetime('now')`.

    Audit 2026-05-24, db-#4: The schema defaults use SQLite's
    `datetime('now')` which returns `YYYY-MM-DD HH:MM:SS` (space-
    separated, no timezone suffix, no microseconds). Previous Python
    writes used `datetime.now(timezone.utc).isoformat()` which produces
    `YYYY-MM-DDTHH:MM:SS.ffffff+00:00`. Lexically these two formats sort
    against each other incorrectly (space < 'T'), so any range query
    (`prune_logs`, the `since` filter in `get_filtered_log`) gives wrong
    results when the column contains a mix.

    Returns the same format the schema defaults produce so the column
    stays consistent and range queries are correct.
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


class Database:
    def __init__(self, path: Path = DB_PATH) -> None:
        self._path = path
        self._db: Optional[aiosqlite.Connection] = None
        # Rate-limit rows are read/modified as small read-modify-write
        # operations.  Serialising those operations in-process avoids two
        # coroutines racing the same subject without using BEGIN IMMEDIATE on
        # the application's shared connection (which also collided with the
        # topology sync's formerly uncommitted batch).
        self._rate_limit_lock = asyncio.Lock()
        # Config values frequently form one logical secret/credential bundle.
        # Keep all config writers behind the same lock so a multi-key update
        # cannot be interleaved with a single-key update on the shared
        # connection.
        self._config_lock = asyncio.Lock()
        # Hub hold ownership crosses a physical-command boundary and therefore
        # needs transaction ownership stronger than the shared connection can
        # provide. Its writes use isolated connections and serialize here.
        self._hub_hold_lock = asyncio.Lock()
        # A pending relock is a write-ahead safety intent for a physical
        # unlock. Give those transitions isolated transaction ownership so an
        # unrelated coroutine cannot commit or roll them back on the shared
        # application connection.
        self._pending_relock_lock = asyncio.Lock()
        self._group_locks_write_lock = asyncio.Lock()
        # Legacy explicit commit=False upserts use a task-owned isolated
        # connection. The main connection runs in autocommit mode so one
        # coroutine's commit/rollback can never capture another's write.
        self._batch_connections: dict[asyncio.Task, aiosqlite.Connection] = {}
        # UI response caches are deliberately process-local.  Persisting
        # 15-30 second values to SQLite added two write transactions at every
        # expiry (delete-on-read + upsert) and retained stale console data
        # across restarts.  Store the JSON representation so every read still
        # returns a defensive deep copy and non-JSON values fail exactly as
        # they did when written to the database.
        self._ui_cache: dict[str, tuple[str, float]] = {}

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._ui_cache.clear()
        self._db = await aiosqlite.connect(self._path, isolation_level=None)
        self._db.row_factory = aiosqlite.Row
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA foreign_keys=ON")
        await self._db.execute("PRAGMA busy_timeout = 5000")
        await self._db.execute("PRAGMA secure_delete = ON")
        await self._db.executescript(SCHEMA)
        await self._migrate()
        await self._db.commit()

    async def _migrate(self) -> None:
        """Run incremental migrations for schema changes."""
        await self._db.execute("BEGIN IMMEDIATE")
        try:
            # Migration 1: add key_encrypted column to api_keys
            async with self._db.execute("PRAGMA table_info(api_keys)") as cur:
                cols = {row[1] for row in await cur.fetchall()}
            if "key_encrypted" not in cols:
                await self._db.execute("ALTER TABLE api_keys ADD COLUMN key_encrypted TEXT")

            # Migration 2: add hidden column to users
            async with self._db.execute("PRAGMA table_info(users)") as cur:
                cols = {row[1] for row in await cur.fetchall()}
            if "hidden" not in cols:
                await self._db.execute("ALTER TABLE users ADD COLUMN hidden INTEGER NOT NULL DEFAULT 0")

            # Migration 3: add buzz_enabled and buzz_duration to locks
            async with self._db.execute("PRAGMA table_info(locks)") as cur:
                cols = {row[1] for row in await cur.fetchall()}
            if "buzz_enabled" not in cols:
                await self._db.execute("ALTER TABLE locks ADD COLUMN buzz_enabled INTEGER NOT NULL DEFAULT 1")
                await self._db.execute("ALTER TABLE locks ADD COLUMN buzz_duration INTEGER NOT NULL DEFAULT 5")

            # Migration 4: add access_location_id to locks
            async with self._db.execute("PRAGMA table_info(locks)") as cur:
                cols = {row[1] for row in await cur.fetchall()}
            if "access_location_id" not in cols:
                await self._db.execute("ALTER TABLE locks ADD COLUMN access_location_id TEXT")

            # Migration 5: unique index on locks.location_id for upsert
            await self._db.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_locks_location_id ON locks(location_id) WHERE location_id IS NOT NULL"
            )

            # Migration 6: add alarm control columns to groups
            async with self._db.execute("PRAGMA table_info(groups)") as cur:
                cols = {row[1] for row in await cur.fetchall()}
            if "blocked_when_armed_away" not in cols:
                # Handle legacy single column migration — copy value if it exists
                if "blocked_when_armed" in cols:
                    await self._db.execute("ALTER TABLE groups ADD COLUMN blocked_when_armed_away INTEGER NOT NULL DEFAULT 0")
                    await self._db.execute("ALTER TABLE groups ADD COLUMN blocked_when_armed_home INTEGER NOT NULL DEFAULT 0")
                    await self._db.execute("ALTER TABLE groups ADD COLUMN can_disarm INTEGER NOT NULL DEFAULT 1")
                    await self._db.execute("UPDATE groups SET blocked_when_armed_away = blocked_when_armed")
                else:
                    await self._db.execute("ALTER TABLE groups ADD COLUMN blocked_when_armed_away INTEGER NOT NULL DEFAULT 0")
                    await self._db.execute("ALTER TABLE groups ADD COLUMN blocked_when_armed_home INTEGER NOT NULL DEFAULT 0")
                    await self._db.execute("ALTER TABLE groups ADD COLUMN can_disarm INTEGER NOT NULL DEFAULT 1")

            # Migration 7: add schedule columns to groups
            async with self._db.execute("PRAGMA table_info(groups)") as cur:
                cols = {row[1] for row in await cur.fetchall()}
            if "schedule_enabled" not in cols:
                await self._db.execute("ALTER TABLE groups ADD COLUMN schedule_enabled INTEGER NOT NULL DEFAULT 0")
                await self._db.execute("ALTER TABLE groups ADD COLUMN schedule_days TEXT")
                await self._db.execute("ALTER TABLE groups ADD COLUMN schedule_start TEXT")
                await self._db.execute("ALTER TABLE groups ADD COLUMN schedule_end TEXT")

            # Migration 8: (removed — duplicate of idx_locks_location_id from Migration 5)
            # Drop the duplicate index if it was already created on an existing install
            async with self._db.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND name='uq_locks_location_id'"
            ) as cur:
                if await cur.fetchone():
                    await self._db.execute("DROP INDEX uq_locks_location_id")

            # Migration 9: seed "Full Access" group
            async with self._db.execute("SELECT id FROM groups WHERE name = 'Full Access'") as cur:
                if not await cur.fetchone():
                    await self._db.execute(
                        "INSERT INTO groups (name, description, all_locks) VALUES (?, ?, ?)",
                        ("Full Access", "Access to all locks", 1),
                    )

            # Migration 10: add scope column to api_keys
            async with self._db.execute("PRAGMA table_info(api_keys)") as cur:
                cols = {row[1] for row in await cur.fetchall()}
            if "scope" not in cols:
                await self._db.execute(
                    "ALTER TABLE api_keys ADD COLUMN scope TEXT NOT NULL DEFAULT 'full'"
                )

            # Migration 11: add pin_encrypted column to users
            async with self._db.execute("PRAGMA table_info(users)") as cur:
                cols = {row[1] for row in await cur.fetchall()}
            if "pin_encrypted" not in cols:
                await self._db.execute("ALTER TABLE users ADD COLUMN pin_encrypted TEXT")

            # Migration 12: add hidden column to locks
            async with self._db.execute("PRAGMA table_info(locks)") as cur:
                cols = {row[1] for row in await cur.fetchall()}
            if "hidden" not in cols:
                await self._db.execute(
                    "ALTER TABLE locks ADD COLUMN hidden INTEGER NOT NULL DEFAULT 0"
                )

            # Migration 13: add remote_buzz_enabled to locks + update buzz_duration default to 30
            async with self._db.execute("PRAGMA table_info(locks)") as cur:
                cols = {row[1] for row in await cur.fetchall()}
            if "remote_buzz_enabled" not in cols:
                await self._db.execute(
                    "ALTER TABLE locks ADD COLUMN remote_buzz_enabled INTEGER NOT NULL DEFAULT 0"
                )
                # Update existing locks that still have the old 5s default
                await self._db.execute(
                    "UPDATE locks SET buzz_duration = 30 WHERE buzz_duration = 5"
                )

            # Migration 14: relock settings — independent toggles for remote vs device-auth
            async with self._db.execute("PRAGMA table_info(locks)") as cur:
                cols = {row[1] for row in await cur.fetchall()}
            if "relock_on_remote" not in cols:
                await self._db.execute(
                    "ALTER TABLE locks ADD COLUMN relock_on_remote INTEGER NOT NULL DEFAULT 0"
                )
                await self._db.execute(
                    "ALTER TABLE locks ADD COLUMN relock_on_device_auth INTEGER NOT NULL DEFAULT 0"
                )
                await self._db.execute(
                    "ALTER TABLE locks ADD COLUMN relock_duration INTEGER NOT NULL DEFAULT 30"
                )
                # Carry over existing values
                await self._db.execute(
                    "UPDATE locks SET relock_on_remote = remote_buzz_enabled, relock_duration = buzz_duration"
                )

            # Migration 15: add disarm_code_encrypted to alarm_panels
            async with self._db.execute("PRAGMA table_info(alarm_panels)") as cur:
                cols = {row[1] for row in await cur.fetchall()}
            if "disarm_code_encrypted" not in cols:
                await self._db.execute(
                    "ALTER TABLE alarm_panels ADD COLUMN disarm_code_encrypted TEXT"
                )

            # Migration 16: drop key_encrypted column (keys shown once at creation only)
            async with self._db.execute("PRAGMA table_info(api_keys)") as cur:
                cols = [row[1] for row in await cur.fetchall()]
            if "key_encrypted" in cols:
                await self._db.execute("ALTER TABLE api_keys DROP COLUMN key_encrypted")

            # Migration 17: pending_relocks table for survival across restarts
            await self._db.execute(
                """CREATE TABLE IF NOT EXISTS pending_relocks (
                    entity_id  TEXT PRIMARY KEY,
                    lock_id    INTEGER,
                    lock_name  TEXT,
                    source     TEXT NOT NULL,
                    deadline   REAL NOT NULL,
                    created_at REAL NOT NULL
                )"""
            )

            # Migration 18: opt-in hub sync — mirror a third-party HA lock's
            # state onto its paired Access hub. Default 0 (off) so existing
            # installs keep current behaviour.
            async with self._db.execute("PRAGMA table_info(locks)") as cur:
                cols = {row[1] for row in await cur.fetchall()}
            if "sync_hub_state" not in cols:
                await self._db.execute(
                    "ALTER TABLE locks ADD COLUMN sync_hub_state INTEGER NOT NULL DEFAULT 0"
                )

            # Migration 19: access_log indexes for the per-lock/per-user
            # history views — with 90 days of events these were table
            # scans (e2e review 2026-07-12). Also drop idx_users_ulp_id:
            # it duplicates the implicit index from the UNIQUE constraint
            # on users.ulp_id, costing write amplification on every sync.
            await self._db.execute(
                "CREATE INDEX IF NOT EXISTS idx_access_log_lock_ts ON access_log(lock_id, timestamp)"
            )
            await self._db.execute(
                "CREATE INDEX IF NOT EXISTS idx_access_log_user_ts ON access_log(user_id, timestamp)"
            )
            await self._db.execute("DROP INDEX IF EXISTS idx_users_ulp_id")

            # Migration 20: durable ownership of persistent Access rules
            # created by HubSyncManager. These rows are written before the
            # physical command and removed only after a confirmed replacement,
            # allowing a fresh process to fail-safe and later release them.
            await self._db.execute(
                """CREATE TABLE IF NOT EXISTS hub_sync_holds (
                    entity_id       TEXT    NOT NULL,
                    hub_device_id   TEXT    NOT NULL,
                    hub_lock_id     INTEGER,
                    hub_location_id TEXT,
                    hub_name        TEXT    NOT NULL,
                    override_type   TEXT    NOT NULL DEFAULT 'keep_unlock',
                    created_at      REAL    NOT NULL,
                    PRIMARY KEY (entity_id, hub_device_id)
                )"""
            )
            # Migration 23: official Access commands address doors by their
            # location id, and fail-safe keep_lock is itself a persistent rule
            # that must be released after an incident.  Preserve both pieces of
            # app-owned override state across restarts. Existing rows predate
            # these columns and necessarily represent keep_unlock ownership.
            async with self._db.execute(
                "PRAGMA table_info(hub_sync_holds)"
            ) as cur:
                hold_cols = {row[1] for row in await cur.fetchall()}
            if "hub_location_id" not in hold_cols:
                await self._db.execute(
                    "ALTER TABLE hub_sync_holds ADD COLUMN hub_location_id TEXT"
                )
            if "override_type" not in hold_cols:
                await self._db.execute(
                    "ALTER TABLE hub_sync_holds ADD COLUMN override_type "
                    "TEXT NOT NULL DEFAULT 'keep_unlock'"
                )
            await self._db.execute(
                """UPDATE hub_sync_holds
                      SET hub_location_id = (
                              SELECT location_id
                                FROM locks
                               WHERE locks.id = hub_sync_holds.hub_lock_id
                               LIMIT 1
                          )
                    WHERE hub_location_id IS NULL
                      AND hub_lock_id IS NOT NULL"""
            )
            await self._db.execute(
                """UPDATE hub_sync_holds
                      SET hub_location_id = (
                              SELECT location_id
                                FROM locks
                               WHERE locks.device_id = hub_sync_holds.hub_device_id
                               LIMIT 1
                          )
                    WHERE hub_location_id IS NULL
                      AND hub_device_id != ''"""
            )

            # Migration 22: last fully confirmed bidirectional convergence.
            # This is deliberately separate from hub_sync_holds: a rule that
            # originated in Access (not this app) is useful reconciliation
            # history, but it must never be mistaken for an app-owned override
            # that startup/opt-out is allowed to clear.
            await self._db.execute(
                """CREATE TABLE IF NOT EXISTS hub_sync_state (
                    entity_id               TEXT PRIMARY KEY,
                    desired_state           TEXT NOT NULL,
                    source                  TEXT NOT NULL,
                    ha_state                TEXT NOT NULL,
                    access_state            TEXT NOT NULL,
                    access_rule_fingerprint TEXT NOT NULL,
                    pairing_signature       TEXT NOT NULL,
                    updated_at              REAL NOT NULL
                )"""
            )

            # Migration 21: preserve native lock history while retiring doors
            # absent from a non-empty authoritative Access snapshot.
            async with self._db.execute("PRAGMA table_info(locks)") as cur:
                cols = {row[1] for row in await cur.fetchall()}
            if "upstream_present" not in cols:
                await self._db.execute(
                    "ALTER TABLE locks ADD COLUMN upstream_present "
                    "INTEGER NOT NULL DEFAULT 1"
                )

            # Migration 24: admin_log and visitors indexes. get_admin_log's
            # `ORDER BY timestamp DESC LIMIT 50` (settings page, every load)
            # and prune_logs' timestamp scan of admin_log were full-table
            # scans, as was get_all_visitors' unbounded `ORDER BY created_at
            # DESC` (e2e review 2026-07-12).
            await self._db.execute(
                "CREATE INDEX IF NOT EXISTS idx_admin_log_timestamp ON admin_log(timestamp)"
            )
            await self._db.execute(
                "CREATE INDEX IF NOT EXISTS idx_visitors_created_at ON visitors(created_at)"
            )

            # Migration 25: opt-in "re-lock after external unlocks". When a
            # bidirectionally synced HA lock is unlocked from HA's side (a
            # thumb-turn or HA automation), schedule a durable time-bounded
            # re-lock. Default 0 (off) so existing installs keep current
            # behaviour. Mirrors the migration-18 sync_hub_state add.
            async with self._db.execute("PRAGMA table_info(locks)") as cur:
                cols = {row[1] for row in await cur.fetchall()}
            if "relock_on_ha_origin" not in cols:
                await self._db.execute(
                    "ALTER TABLE locks ADD COLUMN relock_on_ha_origin "
                    "INTEGER NOT NULL DEFAULT 0"
                )

            # Migration 26: one individual authorization rule per user/lock.
            #
            # The dashboard previously enforced this with a check-then-insert,
            # which is racy: two concurrent submissions could create duplicate
            # grants.  Authorization then selected an arbitrary matching row,
            # so deleting or disabling one duplicate could leave another grant
            # active.  Reconcile legacy rows before adding the database-owned
            # invariant. Identical duplicates preserve their oldest row;
            # conflicting duplicates are disabled fail-closed for an
            # administrator to review.
            async with self._db.execute(
                """SELECT user_id, lock_id
                     FROM access_rules
                 GROUP BY user_id, lock_id
                   HAVING COUNT(*) > 1"""
            ) as cur:
                duplicate_pairs = await cur.fetchall()
            for pair in duplicate_pairs:
                user_id, lock_id = int(pair[0]), int(pair[1])
                async with self._db.execute(
                    """SELECT *
                         FROM access_rules
                        WHERE user_id = ? AND lock_id = ?
                     ORDER BY id""",
                    (user_id, lock_id),
                ) as cur:
                    rows = await cur.fetchall()
                survivor = rows[0]
                policy_fields = (
                    "enabled",
                    "schedule_enabled",
                    "schedule_days",
                    "schedule_start",
                    "schedule_end",
                )
                policies = {
                    tuple(row[field] for field in policy_fields)
                    for row in rows
                }
                if len(policies) > 1:
                    await self._db.execute(
                        """UPDATE access_rules
                              SET enabled = 0,
                                  schedule_enabled = 0,
                                  schedule_days = NULL,
                                  schedule_start = NULL,
                                  schedule_end = NULL,
                                  updated_at = ?
                            WHERE id = ?""",
                        (_utc_now_sqlite(), survivor["id"]),
                    )
                    _LOGGER.warning(
                        "Disabled conflicting duplicate access rules for "
                        "user_id=%s lock_id=%s during migration",
                        user_id,
                        lock_id,
                    )
                await self._db.execute(
                    """DELETE FROM access_rules
                       WHERE user_id = ? AND lock_id = ? AND id != ?""",
                    (user_id, lock_id, survivor["id"]),
                )
            await self._db.execute(
                """CREATE UNIQUE INDEX IF NOT EXISTS
                       idx_access_rules_user_lock
                     ON access_rules(user_id, lock_id)"""
            )

            await self._db.commit()
        except Exception:
            await self._db.rollback()
            raise

    async def close(self) -> None:
        self._ui_cache.clear()
        batches = list(self._batch_connections.values())
        self._batch_connections.clear()
        for connection in batches:
            try:
                await connection.rollback()
            finally:
                await connection.close()
        if self._db is not None:
            await self._db.close()
            self._db = None

    async def commit(self) -> None:
        """Commit this task's isolated batch started with ``commit=False``."""
        task = asyncio.current_task()
        connection = self._batch_connections.pop(task, None)
        if connection is None:
            await self._db.commit()
            return
        try:
            await connection.commit()
        finally:
            await connection.close()

    async def rollback(self) -> None:
        """Discard this task's isolated ``commit=False`` batch."""
        task = asyncio.current_task()
        connection = self._batch_connections.pop(task, None)
        if connection is None:
            await self._db.rollback()
            return
        try:
            await connection.rollback()
        finally:
            await connection.close()

    async def _batch_connection(self) -> aiosqlite.Connection:
        """Return/create the current task's isolated explicit batch."""
        if str(self._path) == ":memory:":
            raise RuntimeError("commit=False batches require a file-backed database")
        task = asyncio.current_task()
        connection = self._batch_connections.get(task)
        if connection is not None:
            return connection
        connection = await aiosqlite.connect(self._path)
        connection.row_factory = aiosqlite.Row
        await connection.execute("PRAGMA foreign_keys=ON")
        await connection.execute("PRAGMA busy_timeout = 5000")
        await connection.execute("BEGIN IMMEDIATE")
        self._batch_connections[task] = connection
        return connection

    async def sync_topology(
        self,
        users: list[dict[str, Any]],
        locks: list[dict[str, Any]],
    ) -> dict[str, int]:
        """Atomically apply a complete Access user/lock topology snapshot.

        The sync runs on a short-lived, dedicated SQLite connection.  A
        commit or rollback here therefore cannot flush or discard work queued
        by request handlers on the application's primary connection.  This is
        important because an ``aiosqlite.Connection`` serialises statements,
        but it does *not* give concurrent coroutines transaction ownership.

        Unchanged rows are not rewritten.  An empty (or wholly malformed)
        user snapshot is treated as an upstream failure and never marks every
        local user deleted; valid lock rows can still be refreshed.
        """
        if str(self._path) == ":memory:":
            raise ValueError("sync_topology requires a file-backed database")

        normalized_users: dict[str, tuple[str, Optional[str], str]] = {}
        users_skipped = 0
        users_duplicates = 0
        for user in users:
            ulp_id = user.get("ulp_id")
            if not ulp_id:
                users_skipped += 1
                continue
            ulp_id = str(ulp_id)
            if ulp_id in normalized_users:
                users_duplicates += 1
            normalized_users[ulp_id] = (
                user.get("name") or "",
                user.get("email") or None,
                user.get("status") or "active",
            )

        normalized_locks: dict[str, tuple[str, str, Optional[str]]] = {}
        locks_skipped = 0
        locks_duplicates = 0
        for lock in locks:
            device_id = lock.get("device_id")
            location_id = lock.get("location_id")
            if not device_id or not location_id:
                locks_skipped += 1
                continue
            location_id = str(location_id)
            if location_id in normalized_locks:
                locks_duplicates += 1
            normalized_locks[location_id] = (
                str(device_id),
                lock.get("name") or "",
                lock.get("door_name") or None,
            )

        stats: dict[str, int] = {
            "users_seen": len(normalized_users),
            "users_inserted": 0,
            "users_updated": 0,
            "users_unchanged": 0,
            "users_marked_deleted": 0,
            "users_skipped": users_skipped,
            "users_duplicates": users_duplicates,
            "empty_user_guard": int(not normalized_users),
            "locks_seen": len(normalized_locks),
            "locks_inserted": 0,
            "locks_updated": 0,
            "locks_unchanged": 0,
            "locks_marked_missing": 0,
            "locks_skipped": locks_skipped,
            "locks_duplicates": locks_duplicates,
        }

        if not normalized_users:
            _LOGGER.warning(
                "Topology sync received no valid users — refusing to mark all "
                "local users deleted"
            )

        isolated: Optional[aiosqlite.Connection] = None
        try:
            isolated = await aiosqlite.connect(self._path)
            isolated.row_factory = aiosqlite.Row
            await isolated.execute("PRAGMA foreign_keys=ON")
            await isolated.execute("PRAGMA busy_timeout = 5000")
            await isolated.execute("BEGIN IMMEDIATE")

            async with isolated.execute(
                "SELECT ulp_id, name, email, status FROM users"
            ) as cursor:
                existing_users = {
                    row["ulp_id"]: (row["name"], row["email"], row["status"])
                    for row in await cursor.fetchall()
                }

            user_inserts: list[tuple[str, str, Optional[str], str, str]] = []
            user_updates: list[tuple[str, Optional[str], str, str, str]] = []
            synced_at = _utc_now_sqlite()
            for ulp_id, values in normalized_users.items():
                existing = existing_users.get(ulp_id)
                if existing is None:
                    name, email, status = values
                    user_inserts.append((ulp_id, name, email, status, synced_at))
                elif existing != values:
                    name, email, status = values
                    user_updates.append((name, email, status, synced_at, ulp_id))
                else:
                    stats["users_unchanged"] += 1

            if user_inserts:
                await isolated.executemany(
                    """INSERT INTO users (ulp_id, name, email, status, synced_at)
                       VALUES (?, ?, ?, ?, ?)""",
                    user_inserts,
                )
                stats["users_inserted"] = len(user_inserts)
            if user_updates:
                await isolated.executemany(
                    """UPDATE users
                       SET name = ?, email = ?, status = ?, synced_at = ?
                       WHERE ulp_id = ?""",
                    user_updates,
                )
                stats["users_updated"] = len(user_updates)

            if normalized_users:
                deleted_user_ids = [
                    (ulp_id,)
                    for ulp_id, (_, _, status) in existing_users.items()
                    if ulp_id not in normalized_users
                    and status != "deleted_upstream"
                ]
                if deleted_user_ids:
                    # executemany avoids a giant NOT IN placeholder list and
                    # emits no UPDATE at all for the steady-state no-op sync.
                    await isolated.executemany(
                        """UPDATE users SET status = 'deleted_upstream'
                           WHERE ulp_id = ?""",
                        deleted_user_ids,
                    )
                    stats["users_marked_deleted"] = len(deleted_user_ids)

            async with isolated.execute(
                """SELECT location_id, device_id, name, door_name,
                          upstream_present
                   FROM locks
                   WHERE type = 'access_native' AND location_id IS NOT NULL"""
            ) as cursor:
                existing_locks = {
                    row["location_id"]: (
                        row["device_id"], row["name"], row["door_name"],
                        row["upstream_present"]
                    )
                    for row in await cursor.fetchall()
                }

            lock_inserts: list[tuple[str, str, str, Optional[str]]] = []
            lock_updates: list[tuple[str, str, Optional[str], str]] = []
            for location_id, values in normalized_locks.items():
                existing = existing_locks.get(location_id)
                if existing is None:
                    device_id, name, door_name = values
                    lock_inserts.append((device_id, location_id, name, door_name))
                elif existing != (*values, 1):
                    device_id, name, door_name = values
                    lock_updates.append((device_id, name, door_name, location_id))
                else:
                    stats["locks_unchanged"] += 1

            if lock_inserts:
                await isolated.executemany(
                    """INSERT INTO locks
                           (type, device_id, location_id, name, door_name)
                       VALUES ('access_native', ?, ?, ?, ?)""",
                    lock_inserts,
                )
                stats["locks_inserted"] = len(lock_inserts)
            if lock_updates:
                await isolated.executemany(
                    """UPDATE locks
                       SET device_id = ?, name = ?, door_name = ?,
                           upstream_present = 1
                       WHERE location_id = ?""",
                    lock_updates,
                )
                stats["locks_updated"] = len(lock_updates)

            if normalized_locks:
                missing_locations = [
                    (location_id,)
                    for location_id, values in existing_locks.items()
                    if location_id not in normalized_locks and values[3] != 0
                ]
                if missing_locations:
                    await isolated.executemany(
                        """UPDATE locks SET upstream_present = 0
                           WHERE type = 'access_native' AND location_id = ?""",
                        missing_locations,
                    )
                    stats["locks_marked_missing"] = len(missing_locations)

            await isolated.commit()
        except Exception:
            if isolated is not None:
                await isolated.rollback()
            raise
        finally:
            if isolated is not None:
                await isolated.close()

        return stats

    # ------------------------------------------------------------------
    # Config
    # ------------------------------------------------------------------

    async def get_config(self, key: str) -> Optional[str]:
        async with self._db.execute(
            "SELECT value FROM config WHERE key = ?", (key,)
        ) as cursor:
            row = await cursor.fetchone()
            return row["value"] if row else None

    async def set_config(self, key: str, value: str) -> None:
        async with self._config_lock:
            try:
                await self._db.execute(
                    "INSERT INTO config (key, value) VALUES (?, ?)"
                    " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (key, value),
                )
                await self._db.commit()
            except BaseException:
                await self._db.rollback()
                raise

    async def set_configs(self, values: dict[str, str]) -> None:
        """Atomically upsert a logical bundle of config values.

        Credential and encryption metadata must never be observable as a
        partly-written bundle. File-backed databases use an isolated
        transaction so an unrelated coroutine on the application's shared
        connection cannot commit or roll back the bundle. The config lock also
        serializes this with :meth:`set_config`.
        """
        if not values:
            return
        async with self._config_lock:
            if str(self._path) == ":memory:":
                try:
                    await self._db.executemany(
                        "INSERT INTO config (key, value) VALUES (?, ?)"
                        " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                        list(values.items()),
                    )
                    await self._db.commit()
                except BaseException:
                    await self._db.rollback()
                    raise
                return

            isolated: Optional[aiosqlite.Connection] = None
            try:
                isolated = await aiosqlite.connect(self._path)
                await isolated.execute("PRAGMA busy_timeout = 5000")
                await isolated.execute("BEGIN IMMEDIATE")
                await isolated.executemany(
                    "INSERT INTO config (key, value) VALUES (?, ?)"
                    " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    list(values.items()),
                )
                await isolated.commit()
            except BaseException:
                if isolated is not None:
                    await isolated.rollback()
                raise
            finally:
                if isolated is not None:
                    await isolated.close()

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------

    async def get_user(self, user_id: int) -> Optional[dict[str, Any]]:
        async with self._db.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ) as cursor:
            row = await cursor.fetchone()
            return _row_to_dict(row) if row else None

    async def get_user_by_ulp_id(self, ulp_id: str) -> Optional[dict[str, Any]]:
        async with self._db.execute(
            "SELECT * FROM users WHERE ulp_id = ?", (ulp_id,)
        ) as cursor:
            row = await cursor.fetchone()
            return _row_to_dict(row) if row else None

    async def get_user_count(self) -> int:
        async with self._db.execute("SELECT COUNT(*) FROM users") as cur:
            row = await cur.fetchone()
            return row[0] if row else 0

    async def get_all_users(self, include_hidden: bool = False) -> list[dict[str, Any]]:
        """Return all users with an additional rule_count column."""
        # `where` is a hardcoded literal chosen by an internal bool, NOT
        # user input. Bandit B608 false positive suppressed below.
        where = "" if include_hidden else "WHERE u.hidden = 0"
        async with self._db.execute(
            f"""
            SELECT u.*, COUNT(r.id) AS rule_count
            FROM users u
            LEFT JOIN access_rules r ON r.user_id = u.id
            {where}
            GROUP BY u.id
            ORDER BY u.name
            """  # nosec B608 — `where` is a literal
        ) as cursor:
            rows = await cursor.fetchall()
            return [_row_to_dict(r) for r in rows]

    async def set_user_hidden(self, user_id: int, hidden: bool) -> None:
        await self._db.execute(
            "UPDATE users SET hidden = ? WHERE id = ?", (1 if hidden else 0, user_id)
        )
        await self._db.commit()

    async def upsert_user(
        self,
        ulp_id: str,
        name: str,
        email: Optional[str],
        status: str,
        synced_at: Optional[str] = None,
        commit: bool = True,
    ) -> int:
        """Insert or update a user by ulp_id. Returns the row id.

        No-ops (no write, no synced_at bump) when the incoming values
        match the stored row — the topology resync calls this for every
        user every 15 minutes, and unconditionally rewriting rows in
        per-row transactions was ~10k fsync'd write transactions/day at
        complete idle on an SD-card host (e2e review 2026-07-12).
        synced_at therefore means "last time upstream data changed", not
        "last sync tick". Pass commit=False to batch several upserts
        into one transaction; the caller then owns commit()/rollback().
        """
        connection = self._db if commit else await self._batch_connection()
        async with connection.execute(
            "SELECT id, name, email, status FROM users WHERE ulp_id = ?", (ulp_id,)
        ) as cursor:
            existing = await cursor.fetchone()
        if (
            existing is not None
            and existing["name"] == name
            and existing["email"] == email
            and existing["status"] == status
        ):
            return existing["id"]

        if synced_at is None:
            synced_at = _utc_now_sqlite()
        await connection.execute(
            """
            INSERT INTO users (ulp_id, name, email, status, synced_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(ulp_id) DO UPDATE SET
                name      = excluded.name,
                email     = excluded.email,
                status    = excluded.status,
                synced_at = excluded.synced_at
            """,
            (ulp_id, name, email, status, synced_at),
        )
        if commit:
            await connection.commit()
        if existing is not None:
            return existing["id"]
        async with connection.execute(
            "SELECT id FROM users WHERE ulp_id = ?", (ulp_id,)
        ) as cursor:
            row = await cursor.fetchone()
            return row["id"]

    async def mark_deleted_users(self, active_ulp_ids: list[str]) -> int:
        """Mark users not in active_ulp_ids as deleted_upstream. Returns count.

        Audit 2026-05-24, db-#3: an empty `active_ulp_ids` from a failed
        upstream sync (UniFi returns []) used to mark every local user
        as deleted. Now refuse the empty case explicitly — callers can
        still pass `[""]` or a real list. If a real sync ever needs to
        deactivate everyone, it must call with a known sentinel.
        """
        if not active_ulp_ids:
            _LOGGER.warning(
                "mark_deleted_users called with empty list — refusing to mass-delete. "
                "Likely an upstream sync error; check UniFi Access connection."
            )
            return 0
        # `placeholders` is a comma-joined string of `?` literals,
        # NOT user input. Values flow through aiosqlite parameter
        # binding via `active_ulp_ids`. Bandit B608 false positive.
        placeholders = ",".join("?" * len(active_ulp_ids))
        cursor = await self._db.execute(
            f"UPDATE users SET status = 'deleted_upstream'"
            f" WHERE ulp_id NOT IN ({placeholders})"
            f"   AND status != 'deleted_upstream'",  # nosec B608 — placeholders only
            active_ulp_ids,
        )
        await self._db.commit()
        return cursor.rowcount

    # ------------------------------------------------------------------
    # Locks
    # ------------------------------------------------------------------

    async def get_lock_count(self) -> int:
        async with self._db.execute(
            "SELECT COUNT(*) FROM locks "
            "WHERE type != 'access_native' OR upstream_present = 1"
        ) as cur:
            row = await cur.fetchone()
            return row[0] if row else 0

    async def get_all_locks(self, include_hidden: bool = False) -> list[dict[str, Any]]:
        if include_hidden:
            sql = "SELECT * FROM locks ORDER BY name"
        else:
            sql = (
                "SELECT * FROM locks WHERE hidden = 0 "
                "AND (type != 'access_native' OR upstream_present = 1) "
                "ORDER BY name"
            )
        async with self._db.execute(sql) as cursor:
            rows = await cursor.fetchall()
            return [_row_to_dict(r) for r in rows]

    async def set_lock_hidden(self, lock_id: int, hidden: bool) -> None:
        await self._db.execute(
            "UPDATE locks SET hidden = ? WHERE id = ?", (1 if hidden else 0, lock_id)
        )
        await self._db.commit()

    async def get_lock(self, lock_id: int) -> Optional[dict[str, Any]]:
        async with self._db.execute(
            "SELECT * FROM locks WHERE id = ? "
            "AND (type != 'access_native' OR upstream_present = 1)",
            (lock_id,),
        ) as cursor:
            row = await cursor.fetchone()
            return _row_to_dict(row) if row else None

    async def get_lock_by_location(self, location_id: str) -> Optional[dict[str, Any]]:
        async with self._db.execute(
            "SELECT * FROM locks WHERE location_id = ? "
            "AND (type != 'access_native' OR upstream_present = 1)",
            (location_id,),
        ) as cursor:
            row = await cursor.fetchone()
            return _row_to_dict(row) if row else None

    async def upsert_native_lock(
        self,
        device_id: str,
        location_id: str,
        name: str,
        door_name: Optional[str] = None,
        commit: bool = True,
    ) -> int:
        """Upsert an ACCESS_NATIVE lock by location_id. Returns row id.

        Pass commit=False to batch into the caller's transaction (the
        topology resync batches all lock+user upserts into one commit).
        """
        connection = self._db if commit else await self._batch_connection()
        cursor = await connection.execute(
            """INSERT INTO locks (type, device_id, location_id, name, door_name)
               VALUES ('access_native', ?, ?, ?, ?)
               ON CONFLICT(location_id) WHERE location_id IS NOT NULL DO UPDATE SET
                   device_id  = excluded.device_id,
                   name       = excluded.name,
                   door_name  = excluded.door_name,
                   upstream_present = 1
               RETURNING id""",
            (device_id, location_id, name, door_name),
        )
        row = await cursor.fetchone()
        if commit:
            await connection.commit()
        return row[0]

    async def add_external_lock(
        self,
        entity_id: str,
        name: str,
        door_name: Optional[str] = None,
        buzz_enabled: bool = True,
        relock_duration: int = 30,
    ) -> int:
        """Insert an HA_EXTERNAL lock. Returns the new row id."""
        cursor = await self._db.execute(
            """
            INSERT INTO locks (type, entity_id, name, door_name, buzz_enabled, relock_duration)
            VALUES ('ha_external', ?, ?, ?, ?, ?)
            """,
            (entity_id, name, door_name, 1 if buzz_enabled else 0, relock_duration),
        )
        await self._db.commit()
        return cursor.lastrowid

    async def delete_lock(self, lock_id: int) -> None:
        await self._db.execute("DELETE FROM locks WHERE id = ?", (lock_id,))
        await self._db.commit()

    # Sentinel distinguishing "caller didn't supply access_location_id"
    # from an explicit None/"" (clear the pairing). The lock settings
    # form has never rendered this field, so passing a form default
    # through unconditionally was silently NULLing legacy pairings on
    # every settings save (e2e review 2026-07-12).
    _KEEP = object()

    async def update_lock_settings(
        self, lock_id: int, buzz_enabled: bool, relock_duration: int,
        access_location_id: Any = _KEEP, relock_on_remote: bool = False,
        relock_on_device_auth: bool = False, sync_hub_state: bool = False,
        relock_on_ha_origin: bool = False,
    ) -> None:
        sets = (
            "buzz_enabled = ?, relock_duration = ?, relock_on_remote = ?, "
            "relock_on_device_auth = ?, sync_hub_state = ?, "
            "relock_on_ha_origin = ?"
        )
        params: list[Any] = [
            1 if buzz_enabled else 0, relock_duration,
            1 if relock_on_remote else 0, 1 if relock_on_device_auth else 0,
            1 if sync_hub_state else 0, 1 if relock_on_ha_origin else 0,
        ]
        # Resolve the sentinel via type(self), NOT the module-global
        # `Database`: importlib.reload (used by the integration tests)
        # re-executes this module in place, rebinding the global to a new
        # class with a new sentinel while live instances still carry the
        # old default — the global lookup would then never match.
        if access_location_id is not type(self)._KEEP:
            sets += ", access_location_id = ?"
            params.append(access_location_id or None)
        params.append(lock_id)
        # `sets` is assembled from hardcoded literals above, not user
        # input; values flow through parameter binding.
        await self._db.execute(
            f"UPDATE locks SET {sets} WHERE id = ?",  # nosec B608
            params,
        )
        await self._db.commit()

    async def get_locks_for_location(
        self, location_id: str, include_hidden: bool = False
    ) -> list[dict[str, Any]]:
        """Return locks associated with an Access location (native or linked).

        Hidden locks are excluded by default (a hidden lock must not
        unlock on a tap). Hub sync passes include_hidden=True: hiding a
        hub card from the dashboard is cosmetic and must not silently
        break hub-state mirroring (field report 2026-07-12).
        """
        sql = "SELECT * FROM locks WHERE (location_id = ? OR access_location_id = ?)"
        sql += " AND (type != 'access_native' OR upstream_present = 1)"
        if not include_hidden:
            sql += " AND hidden = 0"
        async with self._db.execute(sql, (location_id, location_id)) as cursor:
            return [_row_to_dict(r) for r in await cursor.fetchall()]

    # ------------------------------------------------------------------
    # Access Rules
    # ------------------------------------------------------------------

    async def get_rules_for_user(self, user_id: int) -> list[dict[str, Any]]:
        """Return all rules for a user, joined with lock name."""
        async with self._db.execute(
            """
            SELECT r.*, l.name AS lock_name
            FROM access_rules r
            JOIN locks l ON l.id = r.lock_id
            WHERE r.user_id = ?
            ORDER BY l.name
            """,
            (user_id,),
        ) as cursor:
            rows = await cursor.fetchall()
            return [_row_to_dict(r) for r in rows]

    async def get_rule(self, rule_id: int) -> Optional[dict[str, Any]]:
        async with self._db.execute(
            "SELECT * FROM access_rules WHERE id = ?", (rule_id,)
        ) as cursor:
            row = await cursor.fetchone()
            return _row_to_dict(row) if row else None

    async def get_rules_for_user_and_lock(
        self, user_id: int, lock_id: int
    ) -> Optional[dict[str, Any]]:
        async with self._db.execute(
            "SELECT * FROM access_rules WHERE user_id = ? AND lock_id = ?",
            (user_id, lock_id),
        ) as cursor:
            row = await cursor.fetchone()
            return _row_to_dict(row) if row else None

    async def add_rule(
        self,
        user_id: int,
        lock_id: int,
        enabled: bool = True,
        schedule_enabled: bool = False,
        schedule_days: Optional[str] = None,
        schedule_start: Optional[str] = None,
        schedule_end: Optional[str] = None,
    ) -> int:
        now = _utc_now_sqlite()
        cursor = await self._db.execute(
            """
            INSERT OR IGNORE INTO access_rules
                (user_id, lock_id, enabled, schedule_enabled,
                 schedule_days, schedule_start, schedule_end,
                 created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                lock_id,
                int(enabled),
                int(schedule_enabled),
                schedule_days,
                schedule_start,
                schedule_end,
                now,
                now,
            ),
        )
        if cursor.rowcount:
            rule_id = int(cursor.lastrowid)
        else:
            async with self._db.execute(
                """SELECT id FROM access_rules
                   WHERE user_id = ? AND lock_id = ?""",
                (user_id, lock_id),
            ) as existing:
                row = await existing.fetchone()
            if row is None:  # Defensive: the conflict must identify a row.
                raise RuntimeError(
                    "Access rule insert was ignored without an existing row"
                )
            rule_id = int(row["id"])
        await self._db.commit()
        return rule_id

    async def update_rule(
        self,
        rule_id: int,
        enabled: bool,
        schedule_enabled: bool = False,
        schedule_days: Optional[str] = None,
        schedule_start: Optional[str] = None,
        schedule_end: Optional[str] = None,
    ) -> None:
        now = _utc_now_sqlite()
        await self._db.execute(
            """
            UPDATE access_rules SET
                enabled          = ?,
                schedule_enabled = ?,
                schedule_days    = ?,
                schedule_start   = ?,
                schedule_end     = ?,
                updated_at       = ?
            WHERE id = ?
            """,
            (
                int(enabled),
                int(schedule_enabled),
                schedule_days,
                schedule_start,
                schedule_end,
                now,
                rule_id,
            ),
        )
        await self._db.commit()

    async def toggle_rule_enabled(
        self, rule_id: int
    ) -> Optional[dict[str, Any]]:
        """Atomically toggle only a rule's authorization switch.

        The schedule editor and enabled switch are independent policy
        controls.  Keeping this as one SQLite statement prevents a concurrent
        schedule save from writing a stale ``enabled`` value back over the
        toggle.
        """
        now = _utc_now_sqlite()
        async with self._db.execute(
            """
            UPDATE access_rules
               SET enabled = CASE enabled WHEN 0 THEN 1 ELSE 0 END,
                   updated_at = ?
             WHERE id = ?
         RETURNING user_id, enabled
            """,
            (now, rule_id),
        ) as cursor:
            row = await cursor.fetchone()
        await self._db.commit()
        return _row_to_dict(row) if row else None

    async def update_rule_schedule(
        self,
        rule_id: int,
        *,
        schedule_enabled: bool,
        schedule_days: Optional[str] = None,
        schedule_start: Optional[str] = None,
        schedule_end: Optional[str] = None,
    ) -> Optional[dict[str, Any]]:
        """Atomically update schedule columns without changing authorization."""
        now = _utc_now_sqlite()
        async with self._db.execute(
            """
            UPDATE access_rules
               SET schedule_enabled = ?,
                   schedule_days = ?,
                   schedule_start = ?,
                   schedule_end = ?,
                   updated_at = ?
             WHERE id = ?
         RETURNING user_id, enabled
            """,
            (
                int(schedule_enabled),
                schedule_days,
                schedule_start,
                schedule_end,
                now,
                rule_id,
            ),
        ) as cursor:
            row = await cursor.fetchone()
        await self._db.commit()
        return _row_to_dict(row) if row else None

    async def delete_rule(self, rule_id: int) -> None:
        await self._db.execute(
            "DELETE FROM access_rules WHERE id = ?", (rule_id,)
        )
        await self._db.commit()

    # ------------------------------------------------------------------
    # Access Log
    # ------------------------------------------------------------------

    async def log_access(
        self,
        method: str,
        result: str,
        user_id: Optional[int] = None,
        user_name: Optional[str] = None,
        lock_id: Optional[int] = None,
        lock_name: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> int:
        now = _utc_now_sqlite()
        cursor = await self._db.execute(
            """
            INSERT INTO access_log
                (timestamp, user_id, user_name, lock_id, lock_name, method, result, reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (now, user_id, user_name, lock_id, lock_name, method, result, reason),
        )
        await self._db.commit()
        return cursor.lastrowid

    async def get_recent_log(self, limit: int = 100) -> list[dict[str, Any]]:
        async with self._db.execute(
            "SELECT * FROM access_log ORDER BY timestamp DESC LIMIT ?", (limit,)
        ) as cursor:
            rows = await cursor.fetchall()
            return [_row_to_dict(r) for r in rows]

    async def get_log_for_lock(self, lock_id: int, limit: int = 100) -> list[dict[str, Any]]:
        async with self._db.execute(
            "SELECT * FROM access_log WHERE lock_id = ? ORDER BY timestamp DESC LIMIT ?",
            (lock_id, limit),
        ) as cursor:
            rows = await cursor.fetchall()
            return [_row_to_dict(r) for r in rows]

    async def get_filtered_log(
        self,
        user_id: Optional[int] = None,
        lock_id: Optional[int] = None,
        result: Optional[str] = None,
        since: Optional[str] = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        conditions: list[str] = []
        params: list[Any] = []

        if user_id is not None:
            conditions.append("user_id = ?")
            params.append(user_id)
        if lock_id is not None:
            conditions.append("lock_id = ?")
            params.append(lock_id)
        if result is not None:
            conditions.append("result = ?")
            params.append(result)
        if since is not None:
            conditions.append("timestamp >= ?")
            params.append(since)

        # `conditions` only ever contains hardcoded fragments like
        # `result = ?` / `timestamp >= ?` (built above this line); the
        # actual values are bound via `params`. Bandit B608 false positive.
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        params.append(limit)

        async with self._db.execute(
            f"SELECT * FROM access_log {where} ORDER BY timestamp DESC LIMIT ?",  # nosec B608 — hardcoded fragments
            params,
        ) as cursor:
            rows = await cursor.fetchall()
            return [_row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # API Keys
    # ------------------------------------------------------------------

    async def add_api_key(
        self, name: str, key_hash: str, scope: str = "full"
    ) -> int:
        now = _utc_now_sqlite()
        cursor = await self._db.execute(
            "INSERT INTO api_keys (name, key_hash, created_at, scope) VALUES (?, ?, ?, ?)",
            (name, key_hash, now, scope),
        )
        await self._db.commit()
        return cursor.lastrowid

    async def get_api_key_scope(self, key_hash: str) -> str | None:
        async with self._db.execute(
            "SELECT scope FROM api_keys WHERE key_hash = ?", (key_hash,)
        ) as cursor:
            row = await cursor.fetchone()
            return row["scope"] if row else None

    async def verify_api_key(self, key_hash: str) -> Optional[dict[str, Any]]:
        """Return the api_key row if the hash matches, else None."""
        async with self._db.execute(
            "SELECT * FROM api_keys WHERE key_hash = ?", (key_hash,)
        ) as cursor:
            row = await cursor.fetchone()
            return _row_to_dict(row) if row else None

    async def get_all_api_keys(self) -> list[dict[str, Any]]:
        async with self._db.execute(
            "SELECT id, name, created_at, scope FROM api_keys ORDER BY created_at"
        ) as cursor:
            rows = await cursor.fetchall()
            return [_row_to_dict(r) for r in rows]

    async def delete_api_key(self, key_id: int) -> None:
        await self._db.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))
        await self._db.commit()

    # ------------------------------------------------------------------
    # Groups
    # ------------------------------------------------------------------

    async def get_all_groups(self) -> list[dict[str, Any]]:
        async with self._db.execute(
            """
            SELECT g.*, COUNT(gm.user_id) AS member_count
            FROM groups g
            LEFT JOIN group_members gm ON gm.group_id = g.id
            GROUP BY g.id
            ORDER BY g.name
            """
        ) as cursor:
            rows = await cursor.fetchall()
            return [_row_to_dict(r) for r in rows]

    async def get_group(self, group_id: int) -> Optional[dict[str, Any]]:
        async with self._db.execute("SELECT * FROM groups WHERE id = ?", (group_id,)) as cur:
            row = await cur.fetchone()
            return _row_to_dict(row) if row else None

    async def create_group(
        self, name: str, description: str = "", all_locks: bool = False,
        blocked_when_armed_away: bool = False, blocked_when_armed_home: bool = False,
        can_disarm: bool = True,
        schedule_enabled: bool = False, schedule_days: str | None = None,
        schedule_start: str | None = None, schedule_end: str | None = None,
    ) -> int:
        cursor = await self._db.execute(
            """INSERT INTO groups (name, description, all_locks,
               blocked_when_armed_away, blocked_when_armed_home, can_disarm,
               schedule_enabled, schedule_days, schedule_start, schedule_end)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (name, description, int(all_locks),
             int(blocked_when_armed_away), int(blocked_when_armed_home), int(can_disarm),
             int(schedule_enabled), schedule_days, schedule_start, schedule_end),
        )
        await self._db.commit()
        return cursor.lastrowid

    async def delete_group(self, group_id: int) -> None:
        await self._db.execute("DELETE FROM groups WHERE id = ?", (group_id,))
        await self._db.commit()

    async def update_group(
        self, group_id: int, name: str, description: str, all_locks: bool,
        blocked_when_armed_away: bool = False, blocked_when_armed_home: bool = False,
        can_disarm: bool = True,
        schedule_enabled: bool = False, schedule_days: str | None = None,
        schedule_start: str | None = None, schedule_end: str | None = None,
    ) -> None:
        await self._db.execute(
            """UPDATE groups SET name = ?, description = ?, all_locks = ?,
               blocked_when_armed_away = ?, blocked_when_armed_home = ?, can_disarm = ?,
               schedule_enabled = ?, schedule_days = ?, schedule_start = ?, schedule_end = ?
               WHERE id = ?""",
            (name, description, int(all_locks),
             int(blocked_when_armed_away), int(blocked_when_armed_home), int(can_disarm),
             int(schedule_enabled), schedule_days, schedule_start, schedule_end, group_id),
        )
        await self._db.commit()

    async def get_group_members(self, group_id: int) -> list[dict[str, Any]]:
        async with self._db.execute(
            """
            SELECT u.* FROM users u
            JOIN group_members gm ON gm.user_id = u.id
            WHERE gm.group_id = ?
            ORDER BY u.name
            """,
            (group_id,),
        ) as cursor:
            return [_row_to_dict(r) for r in await cursor.fetchall()]

    async def add_group_member(self, group_id: int, user_id: int) -> None:
        await self._db.execute(
            "INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)",
            (group_id, user_id),
        )
        await self._db.commit()

    async def remove_group_member(self, group_id: int, user_id: int) -> None:
        await self._db.execute(
            "DELETE FROM group_members WHERE group_id = ? AND user_id = ?",
            (group_id, user_id),
        )
        await self._db.commit()

    async def get_group_locks(self, group_id: int) -> list[dict[str, Any]]:
        async with self._db.execute(
            """
            SELECT l.* FROM locks l
            JOIN group_locks gl ON gl.lock_id = l.id
            WHERE gl.group_id = ?
            ORDER BY l.name
            """,
            (group_id,),
        ) as cursor:
            return [_row_to_dict(r) for r in await cursor.fetchall()]

    async def set_group_locks(self, group_id: int, lock_ids: list[int]) -> None:
        async with self._group_locks_write_lock:
            if str(self._path) == ":memory:":
                connection = self._db
                close_after = False
            else:
                connection = await aiosqlite.connect(self._path)
                await connection.execute("PRAGMA foreign_keys=ON")
                await connection.execute("PRAGMA busy_timeout = 5000")
                close_after = True
            try:
                await connection.execute("BEGIN IMMEDIATE")
                await connection.execute(
                    "DELETE FROM group_locks WHERE group_id = ?", (group_id,)
                )
                if lock_ids:
                    await connection.executemany(
                        "INSERT INTO group_locks (group_id, lock_id) VALUES (?, ?)",
                        [(group_id, lid) for lid in lock_ids],
                    )
                await connection.commit()
            except BaseException:
                await connection.rollback()
                raise
            finally:
                if close_after:
                    await connection.close()

    async def get_all_user_group_names(self) -> dict[int, list[str]]:
        """Return a mapping of user_id → list of group names for all users."""
        async with self._db.execute(
            """
            SELECT gm.user_id, g.name
            FROM group_members gm
            JOIN groups g ON g.id = gm.group_id
            ORDER BY g.name
            """
        ) as cursor:
            rows = await cursor.fetchall()
        result: dict[int, list[str]] = {}
        for row in rows:
            result.setdefault(row["user_id"], []).append(row["name"])
        return result

    async def get_user_groups(self, user_id: int) -> list[dict[str, Any]]:
        async with self._db.execute(
            """
            SELECT g.* FROM groups g
            JOIN group_members gm ON gm.group_id = g.id
            WHERE gm.user_id = ?
            ORDER BY g.name
            """,
            (user_id,),
        ) as cursor:
            return [_row_to_dict(r) for r in await cursor.fetchall()]

    # ------------------------------------------------------------------
    # Alarm Panels
    # ------------------------------------------------------------------
    # Entry Devices
    # ------------------------------------------------------------------

    async def get_entry_devices_for_lock(self, lock_id: int) -> list[dict[str, Any]]:
        async with self._db.execute(
            "SELECT * FROM entry_devices WHERE lock_id = ? ORDER BY name", (lock_id,)
        ) as cur:
            return [_row_to_dict(r) for r in await cur.fetchall()]

    async def get_entry_devices_for_locks(self, lock_ids: list[int]) -> dict[int, list[dict[str, Any]]]:
        """Return entry devices grouped by lock_id for the given locks."""
        if not lock_ids:
            return {}
        # `placeholders` is a comma-joined string of `?` literals (one per
        # element), NOT user input. Values flow through aiosqlite's
        # parameter binding via `lock_ids`. Bandit B608 can't see this
        # through the f-string; the in-line suppression below acknowledges
        # that.
        placeholders = ",".join("?" for _ in lock_ids)
        async with self._db.execute(
            f"SELECT * FROM entry_devices WHERE lock_id IN ({placeholders}) ORDER BY lock_id, name",  # nosec B608
            lock_ids,
        ) as cur:
            rows = await cur.fetchall()
        result: dict[int, list[dict[str, Any]]] = {}
        for row in rows:
            item = _row_to_dict(row)
            result.setdefault(item["lock_id"], []).append(item)
        return result

    async def is_protect_in_use(self) -> bool:
        """Return whether a configured entry path depends on Protect events."""
        async with self._db.execute(
            """SELECT 1
                 FROM entry_devices
                WHERE type = 'protect_doorbell'
                LIMIT 1"""
        ) as cursor:
            return await cursor.fetchone() is not None

    async def add_entry_device(
        self, lock_id: int, device_type: str, name: str,
        device_id: str | None = None, entity_id: str | None = None,
    ) -> int:
        await self._db.execute(
            "INSERT OR IGNORE INTO entry_devices (lock_id, type, device_id, entity_id, name) VALUES (?, ?, ?, ?, ?)",
            (lock_id, device_type, device_id, entity_id, name),
        )
        await self._db.commit()
        # Retrieve actual row ID (last_insert_rowid is unreliable after INSERT OR IGNORE)
        if device_id:
            query = "SELECT id FROM entry_devices WHERE lock_id = ? AND type = ? AND device_id = ?"
            params = (lock_id, device_type, device_id)
        elif entity_id:
            query = "SELECT id FROM entry_devices WHERE lock_id = ? AND type = ? AND entity_id = ?"
            params = (lock_id, device_type, entity_id)
        else:
            async with self._db.execute("SELECT last_insert_rowid() AS id") as cur:
                return (await cur.fetchone())["id"]
        async with self._db.execute(query, params) as cur:
            row = await cur.fetchone()
            return row["id"] if row else 0

    async def delete_entry_device(self, device_id: int) -> None:
        await self._db.execute("DELETE FROM entry_devices WHERE id = ?", (device_id,))
        await self._db.commit()

    async def get_locks_by_entry_device(
        self,
        device_type: str,
        device_id: str | None = None,
        entity_id: str | None = None,
        *,
        include_hidden: bool = False,
    ) -> list[dict[str, Any]]:
        """Find locks linked to an entry device, excluding hidden locks by default."""
        hidden_clause = " AND (l.type != 'access_native' OR l.upstream_present = 1)"
        if not include_hidden:
            hidden_clause += " AND l.hidden = 0"
        if device_id:
            query = (
                "SELECT l.* FROM locks l JOIN entry_devices ed ON ed.lock_id = l.id "
                "WHERE ed.type = ? AND ed.device_id = ?" + hidden_clause
            )
            params = (device_type, device_id)
        elif entity_id:
            query = (
                "SELECT l.* FROM locks l JOIN entry_devices ed ON ed.lock_id = l.id "
                "WHERE ed.type = ? AND ed.entity_id = ?" + hidden_clause
            )
            params = (device_type, entity_id)
        else:
            return []
        async with self._db.execute(query, params) as cur:
            return [_row_to_dict(r) for r in await cur.fetchall()]

    # ------------------------------------------------------------------
    # Alarm Panels
    # ------------------------------------------------------------------

    async def get_all_alarm_panels(self) -> list[dict[str, Any]]:
        async with self._db.execute("SELECT * FROM alarm_panels ORDER BY name") as cur:
            return [_row_to_dict(r) for r in await cur.fetchall()]

    async def add_alarm_panel(self, entity_id: str, name: str) -> int:
        await self._db.execute(
            "INSERT OR IGNORE INTO alarm_panels (entity_id, name) VALUES (?, ?)",
            (entity_id, name),
        )
        await self._db.commit()
        async with self._db.execute(
            "SELECT id FROM alarm_panels WHERE entity_id = ?", (entity_id,)
        ) as cur:
            row = await cur.fetchone()
            return row["id"] if row else 0

    async def update_alarm_panel_code(self, panel_id: int, disarm_code_encrypted: str | None) -> None:
        await self._db.execute(
            "UPDATE alarm_panels SET disarm_code_encrypted = ? WHERE id = ?",
            (disarm_code_encrypted, panel_id),
        )
        await self._db.commit()

    async def delete_alarm_panel(self, panel_id: int) -> None:
        await self._db.execute("DELETE FROM alarm_panels WHERE id = ?", (panel_id,))
        await self._db.commit()

    # ------------------------------------------------------------------
    # Admin Log
    # ------------------------------------------------------------------

    async def log_admin_action(
        self, username: str, action: str, target: str | None = None, detail: str | None = None
    ) -> None:
        await self._db.execute(
            "INSERT INTO admin_log (username, action, target, detail) VALUES (?, ?, ?, ?)",
            (username, action, target, detail),
        )
        await self._db.commit()

    async def get_admin_log(self, limit: int = 50) -> list[dict[str, Any]]:
        async with self._db.execute(
            "SELECT * FROM admin_log ORDER BY timestamp DESC LIMIT ?", (limit,)
        ) as cursor:
            rows = await cursor.fetchall()
            return [_row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Visitors
    # ------------------------------------------------------------------

    async def add_visitor(
        self,
        unvr_visitor_id: str,
        name: str,
        start_time: str,
        end_time: str,
        location_id: str | None = None,
        location_name: str | None = None,
        pin_encrypted: str | None = None,
        unvr_schedule_id: str | None = None,
        status: int = 1,
        created_by: str | None = None,
        notes: str | None = None,
    ) -> int:
        cursor = await self._db.execute(
            """INSERT INTO visitors
               (unvr_visitor_id, name, start_time, end_time, location_id, location_name,
                pin_encrypted, unvr_schedule_id, status, created_by, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (unvr_visitor_id, name, start_time, end_time, location_id, location_name,
             pin_encrypted, unvr_schedule_id, status, created_by, notes),
        )
        await self._db.commit()
        return cursor.lastrowid

    async def get_all_visitors(self) -> list[dict[str, Any]]:
        async with self._db.execute(
            "SELECT * FROM visitors ORDER BY created_at DESC"
        ) as cursor:
            rows = await cursor.fetchall()
            return [_row_to_dict(r) for r in rows]

    async def get_active_visitors(self) -> list[dict[str, Any]]:
        """Return visitors that still require upstream status polling."""
        async with self._db.execute(
            "SELECT * FROM visitors WHERE status = 1 ORDER BY created_at DESC"
        ) as cursor:
            rows = await cursor.fetchall()
            return [_row_to_dict(r) for r in rows]

    async def get_visitor(self, visitor_id: int) -> dict[str, Any] | None:
        async with self._db.execute(
            "SELECT * FROM visitors WHERE id = ?", (visitor_id,)
        ) as cursor:
            row = await cursor.fetchone()
            return _row_to_dict(row) if row else None

    async def update_visitor_status(self, visitor_id: int, status: int) -> None:
        await self._db.execute(
            "UPDATE visitors SET status = ? WHERE id = ?", (status, visitor_id)
        )
        await self._db.commit()

    async def update_visitor_status_if_snapshot(
        self,
        visitor_id: int,
        *,
        expected_status: int,
        expected_end_time: str,
        status: int,
    ) -> bool:
        """Apply an upstream status only if the local visitor is unchanged."""
        cursor = await self._db.execute(
            "UPDATE visitors SET status = ? "
            "WHERE id = ? AND status = ? AND end_time = ?",
            (status, visitor_id, expected_status, expected_end_time),
        )
        await self._db.commit()
        return cursor.rowcount == 1

    async def update_visitor_end_time(self, visitor_id: int, end_time: str) -> None:
        await self._db.execute(
            "UPDATE visitors SET end_time = ? WHERE id = ?", (end_time, visitor_id)
        )
        await self._db.commit()

    async def update_active_visitor_end_time(
        self,
        visitor_id: int,
        end_time: str,
        *,
        expected_end_time: str,
    ) -> bool:
        """Update an active visitor only; return False if it expired concurrently."""
        cursor = await self._db.execute(
            "UPDATE visitors SET end_time = ? "
            "WHERE id = ? AND status = 1 AND end_time = ?",
            (end_time, visitor_id, expected_end_time),
        )
        await self._db.commit()
        return cursor.rowcount == 1

    async def expire_active_visitor(
        self, visitor_id: int, expected_end_time: str
    ) -> bool:
        """Expire only the unchanged active snapshot used by the sync loop."""
        cursor = await self._db.execute(
            "UPDATE visitors SET status = 4 "
            "WHERE id = ? AND status = 1 AND end_time = ?",
            (visitor_id, expected_end_time),
        )
        await self._db.commit()
        return cursor.rowcount == 1

    async def delete_visitor(self, visitor_id: int) -> None:
        await self._db.execute("DELETE FROM visitors WHERE id = ?", (visitor_id,))
        await self._db.commit()

    async def update_user_pin(self, user_id: int, pin_encrypted: str | None) -> None:
        await self._db.execute(
            "UPDATE users SET pin_encrypted = ? WHERE id = ?", (pin_encrypted, user_id)
        )
        await self._db.commit()

    # ------------------------------------------------------------------
    # Runtime State
    # ------------------------------------------------------------------

    async def is_rate_limited(self, scope: str, subject: str, now: float | None = None) -> bool:
        now = now if now is not None else time.time()
        async with self._rate_limit_lock:
            try:
                async with self._db.execute(
                    "SELECT lockout_until FROM rate_limits WHERE scope = ? AND subject = ?",
                    (scope, subject),
                ) as cur:
                    row = await cur.fetchone()
                if not row:
                    return False
                lockout_until = row["lockout_until"] or 0
                if now < lockout_until:
                    return True
                if lockout_until:
                    await self._db.execute(
                        "DELETE FROM rate_limits WHERE scope = ? AND subject = ?",
                        (scope, subject),
                    )
                    await self._db.commit()
                return False
            except Exception:
                await self._db.rollback()
                raise

    async def record_rate_limit_failure(
        self,
        scope: str,
        subject: str,
        *,
        max_attempts: int,
        window: int,
        lockout: int,
        now: float | None = None,
    ) -> bool:
        """Record a failed attempt. Returns True if the subject is now locked."""
        now = now if now is not None else time.time()
        async with self._rate_limit_lock:
            try:
                async with self._db.execute(
                    "SELECT attempts_json, lockout_until FROM rate_limits WHERE scope = ? AND subject = ?",
                    (scope, subject),
                ) as cur:
                    row = await cur.fetchone()

                existing_lockout = row["lockout_until"] if row else 0
                if existing_lockout and now < existing_lockout:
                    return True
                attempts = json.loads(row["attempts_json"]) if row and row["attempts_json"] else []
                attempts = [t for t in attempts if t > now - window]
                attempts.append(now)
                lockout_until = now + lockout if len(attempts) >= max_attempts else 0
                stored_attempts = [] if lockout_until else attempts
                await self._db.execute(
                    """
                    INSERT INTO rate_limits (scope, subject, attempts_json, lockout_until)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(scope, subject) DO UPDATE SET
                        attempts_json = excluded.attempts_json,
                        lockout_until = excluded.lockout_until
                    """,
                    (scope, subject, json.dumps(stored_attempts), lockout_until),
                )
                await self._db.commit()
                return bool(lockout_until)
            except Exception:
                await self._db.rollback()
                raise

    async def clear_rate_limit(self, scope: str, subject: str) -> None:
        async with self._rate_limit_lock:
            try:
                # Successful authenticated requests are the hot path.  Avoid
                # opening a SQLite write transaction when this subject has no
                # failure row to clear (normally the case).
                async with self._db.execute(
                    "SELECT 1 FROM rate_limits WHERE scope = ? AND subject = ?",
                    (scope, subject),
                ) as cur:
                    if await cur.fetchone() is None:
                        return
                await self._db.execute(
                    "DELETE FROM rate_limits WHERE scope = ? AND subject = ?",
                    (scope, subject),
                )
                await self._db.commit()
            except Exception:
                await self._db.rollback()
                raise

    async def consume_rate_limit(
        self,
        scope: str,
        subject: str,
        *,
        max_attempts: int,
        window: int,
        lockout: int,
        now: float | None = None,
    ) -> bool:
        """Record an action attempt. Returns True if allowed, False if locked."""
        now = now if now is not None else time.time()
        async with self._rate_limit_lock:
            try:
                async with self._db.execute(
                    "SELECT attempts_json, lockout_until FROM rate_limits WHERE scope = ? AND subject = ?",
                    (scope, subject),
                ) as cur:
                    row = await cur.fetchone()

                lockout_until = row["lockout_until"] if row else 0
                if lockout_until and now < lockout_until:
                    return False

                attempts = json.loads(row["attempts_json"]) if row and row["attempts_json"] else []
                attempts = [t for t in attempts if t > now - window]
                if len(attempts) >= max_attempts:
                    await self._db.execute(
                        """
                        INSERT INTO rate_limits (scope, subject, attempts_json, lockout_until)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(scope, subject) DO UPDATE SET
                            attempts_json = excluded.attempts_json,
                            lockout_until = excluded.lockout_until
                        """,
                        (scope, subject, json.dumps([]), now + lockout),
                    )
                    await self._db.commit()
                    return False

                attempts.append(now)
                await self._db.execute(
                    """
                    INSERT INTO rate_limits (scope, subject, attempts_json, lockout_until)
                    VALUES (?, ?, ?, 0)
                    ON CONFLICT(scope, subject) DO UPDATE SET
                        attempts_json = excluded.attempts_json,
                        lockout_until = 0
                    """,
                    (scope, subject, json.dumps(attempts)),
                )
                await self._db.commit()
                return True
            except Exception:
                await self._db.rollback()
                raise

    async def get_ui_cache(self, key: str, now: float | None = None) -> Any | None:
        now = now if now is not None else time.time()
        cached = self._ui_cache.get(key)
        if cached is None:
            return None
        value_json, expires_at = cached
        if expires_at <= now:
            self._ui_cache.pop(key, None)
            return None
        return json.loads(value_json)

    async def peek_ui_cache(
        self, key: str, now: float | None = None
    ) -> tuple[Any | None, bool]:
        """Read a UI-cache entry without evicting it, reporting freshness.

        Returns ``(value, is_fresh)``. Unlike :meth:`get_ui_cache`, an expired
        entry is returned (with ``is_fresh=False``) instead of being dropped,
        so callers can serve stale data immediately and refresh in the
        background (stale-while-revalidate). ``(None, False)`` means nothing is
        cached. Truly abandoned entries are still reclaimed by
        :meth:`prune_runtime_state`.
        """
        now = now if now is not None else time.time()
        cached = self._ui_cache.get(key)
        if cached is None:
            return None, False
        value_json, expires_at = cached
        return json.loads(value_json), expires_at > now

    async def set_ui_cache(self, key: str, value: Any, ttl: int, now: float | None = None) -> None:
        now = now if now is not None else time.time()
        self._ui_cache[key] = (json.dumps(value), now + ttl)

    async def prune_runtime_state(self, now: float | None = None) -> None:
        now = now if now is not None else time.time()
        expired_cache_keys = [
            key for key, (_, expires_at) in self._ui_cache.items()
            if expires_at <= now
        ]
        for key in expired_cache_keys:
            self._ui_cache.pop(key, None)

        async with self._rate_limit_lock:
            async with self._db.execute(
                """SELECT 1 FROM rate_limits
                   WHERE lockout_until != 0 AND lockout_until <= ?
                     AND attempts_json = '[]'
                   LIMIT 1""",
                (now,),
            ) as cur:
                has_expired_rows = await cur.fetchone() is not None
            if not has_expired_rows:
                return
            await self._db.execute(
                """DELETE FROM rate_limits
                   WHERE lockout_until != 0 AND lockout_until <= ?
                     AND attempts_json = '[]'""",
                (now,),
            )
            await self._db.commit()

    # ------------------------------------------------------------------
    # Durable hub-sync holds (survive crashes/restarts)
    # ------------------------------------------------------------------

    async def _write_hub_sync_hold(
        self, sql: str, params: tuple[Any, ...]
    ) -> None:
        """Execute one ownership transition in an isolated transaction."""
        async with self._hub_hold_lock:
            if str(self._path) == ":memory:":
                try:
                    await self._db.execute(sql, params)
                    await self._db.commit()
                except BaseException:
                    await self._db.rollback()
                    raise
                return

            isolated: Optional[aiosqlite.Connection] = None
            try:
                isolated = await aiosqlite.connect(self._path)
                await isolated.execute("PRAGMA busy_timeout = 5000")
                await isolated.execute("BEGIN IMMEDIATE")
                await isolated.execute(sql, params)
                await isolated.commit()
            except BaseException:
                if isolated is not None:
                    await isolated.rollback()
                raise
            finally:
                if isolated is not None:
                    await isolated.close()

    async def record_hub_sync_hold(
        self,
        entity_id: str,
        hub_device_id: str,
        hub_lock_id: Optional[int],
        hub_name: str,
        *,
        hub_location_id: str | None = None,
        override_type: str = "keep_unlock",
        now: float | None = None,
    ) -> None:
        """Persist ownership of an app-managed persistent Access rule.

        HubSyncManager records this *before* issuing ``keep_unlock`` or
        ``keep_lock``. A stale row causes only a harmless idempotent safety
        command; omitting it during the command's uncertain/crash window could
        strand a door open or leave its native schedule suppressed.
        """
        if override_type not in {"keep_unlock", "keep_lock"}:
            raise ValueError("override_type must be 'keep_unlock' or 'keep_lock'")
        now = now if now is not None else time.time()
        await self._write_hub_sync_hold(
            """INSERT INTO hub_sync_holds
                   (entity_id, hub_device_id, hub_lock_id, hub_location_id,
                    hub_name, override_type, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(entity_id, hub_device_id) DO UPDATE SET
                   hub_lock_id     = excluded.hub_lock_id,
                   hub_location_id = excluded.hub_location_id,
                   hub_name        = excluded.hub_name,
                   override_type   = excluded.override_type""",
            (
                entity_id,
                hub_device_id,
                hub_lock_id,
                hub_location_id,
                hub_name,
                override_type,
                now,
            ),
        )

    async def clear_hub_sync_hold(
        self, entity_id: str, hub_device_id: str
    ) -> None:
        """Forget a hold only after its hub was confirmed reset."""
        await self._write_hub_sync_hold(
            """DELETE FROM hub_sync_holds
               WHERE entity_id = ? AND hub_device_id = ?""",
            (entity_id, hub_device_id),
        )

    async def get_hub_sync_holds(self) -> list[dict[str, Any]]:
        """Return every hub hold that a new manager must fail-safe."""
        async with self._db.execute(
            """SELECT entity_id, hub_device_id, hub_lock_id, hub_location_id,
                      hub_name, override_type, created_at
               FROM hub_sync_holds
               ORDER BY entity_id, hub_device_id"""
        ) as cursor:
            rows = await cursor.fetchall()
            return [_row_to_dict(row) for row in rows]

    async def set_hub_sync_state(
        self,
        *,
        entity_id: str,
        desired_state: str,
        source: str,
        ha_state: str,
        access_state: str,
        access_rule_fingerprint: str,
        pairing_signature: str,
        now: float | None = None,
    ) -> None:
        """Persist a fully confirmed HA/Access convergence snapshot.

        The snapshot is origin metadata, not physical-command ownership.  It
        therefore shares the isolated hub-sync writer but lives outside
        ``hub_sync_holds`` so an Access-origin schedule is never reset merely
        because the app restarted.
        """
        if desired_state not in {"locked", "unlocked"}:
            raise ValueError("desired_state must be 'locked' or 'unlocked'")
        if ha_state not in {"locked", "unlocked"}:
            raise ValueError("ha_state must be 'locked' or 'unlocked'")
        if access_state not in {"locked", "unlocked"}:
            raise ValueError("access_state must be 'locked' or 'unlocked'")
        await self._write_hub_sync_hold(
            """INSERT INTO hub_sync_state
                   (entity_id, desired_state, source, ha_state, access_state,
                    access_rule_fingerprint, pairing_signature, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(entity_id) DO UPDATE SET
                   desired_state           = excluded.desired_state,
                   source                  = excluded.source,
                   ha_state                = excluded.ha_state,
                   access_state            = excluded.access_state,
                   access_rule_fingerprint = excluded.access_rule_fingerprint,
                   pairing_signature       = excluded.pairing_signature,
                   updated_at              = excluded.updated_at""",
            (
                entity_id,
                desired_state,
                source,
                ha_state,
                access_state,
                access_rule_fingerprint,
                pairing_signature,
                now if now is not None else time.time(),
            ),
        )

    async def clear_hub_sync_state(self, entity_id: str) -> None:
        """Forget reconciliation history after an entity leaves sync."""
        await self._write_hub_sync_hold(
            "DELETE FROM hub_sync_state WHERE entity_id = ?",
            (entity_id,),
        )

    async def get_hub_sync_states(self) -> list[dict[str, Any]]:
        """Return confirmed reconciliation snapshots for restart recovery."""
        async with self._db.execute(
            """SELECT entity_id, desired_state, source, ha_state, access_state,
                      access_rule_fingerprint, pairing_signature, updated_at
                 FROM hub_sync_state
                 ORDER BY entity_id"""
        ) as cursor:
            rows = await cursor.fetchall()
            return [_row_to_dict(row) for row in rows]

    # ------------------------------------------------------------------
    # Pending relocks (survive restarts)
    # ------------------------------------------------------------------

    async def _write_pending_relock(
        self, sql: str, params: tuple[Any, ...]
    ) -> int:
        """Execute one relock ownership transition atomically."""
        async with self._pending_relock_lock:
            if str(self._path) == ":memory:":
                try:
                    cursor = await self._db.execute(sql, params)
                    await self._db.commit()
                    return cursor.rowcount or 0
                except BaseException:
                    await self._db.rollback()
                    raise

            isolated: Optional[aiosqlite.Connection] = None
            try:
                isolated = await aiosqlite.connect(self._path)
                await isolated.execute("PRAGMA busy_timeout = 5000")
                await isolated.execute("BEGIN IMMEDIATE")
                cursor = await isolated.execute(sql, params)
                await isolated.commit()
                return cursor.rowcount or 0
            except BaseException:
                if isolated is not None:
                    await isolated.rollback()
                raise
            finally:
                if isolated is not None:
                    await isolated.close()

    async def add_pending_relock(
        self,
        entity_id: str,
        lock_id: Optional[int],
        lock_name: str,
        source: str,
        deadline: float,
        now: float | None = None,
    ) -> None:
        """Upsert a pending relock — survives service restart and rehydrates on startup."""
        import time
        now = now if now is not None else time.time()
        await self._write_pending_relock(
            """INSERT INTO pending_relocks (entity_id, lock_id, lock_name, source, deadline, created_at)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(entity_id) DO UPDATE SET
                   lock_id    = excluded.lock_id,
                   lock_name  = excluded.lock_name,
                   source     = excluded.source,
                   deadline   = excluded.deadline,
                   created_at = excluded.created_at""",
            (entity_id, lock_id, lock_name, source, deadline, now),
        )

    async def remove_pending_relock(self, entity_id: str) -> None:
        await self._write_pending_relock(
            "DELETE FROM pending_relocks WHERE entity_id = ?", (entity_id,)
        )

    async def remove_pending_relock_at_deadline(
        self, entity_id: str, deadline: float
    ) -> int:
        """
        Delete the pending_relock row ONLY if its deadline matches `deadline`.

        Used by rehydrate's past-due path to avoid clobbering a row that a
        concurrent schedule() may have added with a newer deadline while
        the HA lock call was in flight. Returns rowcount.
        """
        return await self._write_pending_relock(
            "DELETE FROM pending_relocks WHERE entity_id = ? AND deadline = ?",
            (entity_id, deadline),
        )

    async def replace_pending_relock_deadline(
        self, entity_id: str, expected_deadline: float, deadline: float
    ) -> bool:
        """CAS a relock deadline without ever deleting the earlier fallback."""
        changed = await self._write_pending_relock(
            "UPDATE pending_relocks SET deadline = ? "
            "WHERE entity_id = ? AND deadline = ?",
            (deadline, entity_id, expected_deadline),
        )
        return changed == 1

    async def get_pending_relocks(self) -> list[dict[str, Any]]:
        async with self._db.execute(
            "SELECT * FROM pending_relocks ORDER BY deadline"
        ) as cursor:
            rows = await cursor.fetchall()
            return [_row_to_dict(r) for r in rows]

    async def get_pending_relock(self, entity_id: str) -> Optional[dict[str, Any]]:
        """Return one persisted relock by entity id, if it still exists."""
        async with self._db.execute(
            "SELECT * FROM pending_relocks WHERE entity_id = ?", (entity_id,)
        ) as cursor:
            row = await cursor.fetchone()
            return _row_to_dict(row) if row else None

    # ------------------------------------------------------------------
    # Log retention
    # ------------------------------------------------------------------

    async def prune_logs(self, retain_days: int = 90) -> dict[str, int]:
        """Delete access_log and admin_log rows older than retain_days. Returns counts."""
        # `days` is cast to int and clamped to >= 1, so `cutoff_sql` only
        # ever contains a SQLite datetime expression with an integer
        # literal. Bandit B608 can't see through the f-string; the in-line
        # suppressions below acknowledge that.
        days = max(1, int(retain_days))
        cutoff_sql = f"datetime('now', '-{days} days')"
        result: dict[str, int] = {"access_log": 0, "admin_log": 0}

        async with self._db.execute(
            f"DELETE FROM access_log WHERE timestamp < {cutoff_sql}"  # nosec B608
        ) as cur:
            result["access_log"] = cur.rowcount or 0

        async with self._db.execute(
            f"DELETE FROM admin_log WHERE timestamp < {cutoff_sql}"  # nosec B608
        ) as cur:
            result["admin_log"] = cur.rowcount or 0

        await self._db.commit()
        return result
