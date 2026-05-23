from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import aiosqlite

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
    access_location_id  TEXT
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

CREATE INDEX IF NOT EXISTS idx_users_ulp_id          ON users(ulp_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_entry_dev_device ON entry_devices(lock_id, type, device_id) WHERE device_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_entry_dev_entity ON entry_devices(lock_id, type, entity_id) WHERE entity_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_access_rules_user   ON access_rules(user_id);
CREATE INDEX IF NOT EXISTS idx_access_rules_lock   ON access_rules(lock_id);
CREATE INDEX IF NOT EXISTS idx_access_log_timestamp ON access_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_ui_cache_expires_at ON ui_cache(expires_at);
"""


def _row_to_dict(row: aiosqlite.Row) -> dict[str, Any]:
    return dict(row)


class Database:
    def __init__(self, path: Path = DB_PATH) -> None:
        self._path = path
        self._db: Optional[aiosqlite.Connection] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(self._path)
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

            await self._db.commit()
        except Exception:
            await self._db.rollback()
            raise

    async def close(self) -> None:
        if self._db is not None:
            await self._db.close()
            self._db = None

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
        await self._db.execute(
            "INSERT INTO config (key, value) VALUES (?, ?)"
            " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
        await self._db.commit()

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
        where = "" if include_hidden else "WHERE u.hidden = 0"
        async with self._db.execute(
            f"""
            SELECT u.*, COUNT(r.id) AS rule_count
            FROM users u
            LEFT JOIN access_rules r ON r.user_id = u.id
            {where}
            GROUP BY u.id
            ORDER BY u.name
            """
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
    ) -> int:
        """Insert or update a user by ulp_id. Returns the row id."""
        if synced_at is None:
            synced_at = datetime.now(timezone.utc).isoformat()
        await self._db.execute(
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
        await self._db.commit()
        async with self._db.execute(
            "SELECT id FROM users WHERE ulp_id = ?", (ulp_id,)
        ) as cursor:
            row = await cursor.fetchone()
            return row["id"]

    async def mark_deleted_users(self, active_ulp_ids: list[str]) -> int:
        """Mark users not in active_ulp_ids as deleted_upstream. Returns count."""
        if not active_ulp_ids:
            cursor = await self._db.execute(
                "UPDATE users SET status = 'deleted_upstream'"
                " WHERE status != 'deleted_upstream'"
            )
        else:
            placeholders = ",".join("?" * len(active_ulp_ids))
            cursor = await self._db.execute(
                f"UPDATE users SET status = 'deleted_upstream'"
                f" WHERE ulp_id NOT IN ({placeholders})"
                f"   AND status != 'deleted_upstream'",
                active_ulp_ids,
            )
        await self._db.commit()
        return cursor.rowcount

    # ------------------------------------------------------------------
    # Locks
    # ------------------------------------------------------------------

    async def get_lock_count(self) -> int:
        async with self._db.execute("SELECT COUNT(*) FROM locks") as cur:
            row = await cur.fetchone()
            return row[0] if row else 0

    async def get_all_locks(self, include_hidden: bool = False) -> list[dict[str, Any]]:
        if include_hidden:
            sql = "SELECT * FROM locks ORDER BY name"
        else:
            sql = "SELECT * FROM locks WHERE hidden = 0 ORDER BY name"
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
            "SELECT * FROM locks WHERE id = ?", (lock_id,)
        ) as cursor:
            row = await cursor.fetchone()
            return _row_to_dict(row) if row else None

    async def get_lock_by_location(self, location_id: str) -> Optional[dict[str, Any]]:
        async with self._db.execute(
            "SELECT * FROM locks WHERE location_id = ?", (location_id,)
        ) as cursor:
            row = await cursor.fetchone()
            return _row_to_dict(row) if row else None

    async def upsert_native_lock(
        self,
        device_id: str,
        location_id: str,
        name: str,
        door_name: Optional[str] = None,
    ) -> int:
        """Upsert an ACCESS_NATIVE lock by location_id. Returns row id."""
        cursor = await self._db.execute(
            """INSERT INTO locks (type, device_id, location_id, name, door_name)
               VALUES ('access_native', ?, ?, ?, ?)
               ON CONFLICT(location_id) WHERE location_id IS NOT NULL DO UPDATE SET
                   device_id  = excluded.device_id,
                   name       = excluded.name,
                   door_name  = excluded.door_name
               RETURNING id""",
            (device_id, location_id, name, door_name),
        )
        row = await cursor.fetchone()
        await self._db.commit()
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

    async def update_lock_settings(
        self, lock_id: int, buzz_enabled: bool, relock_duration: int,
        access_location_id: str | None = None, relock_on_remote: bool = False,
        relock_on_device_auth: bool = False,
    ) -> None:
        await self._db.execute(
            "UPDATE locks SET buzz_enabled = ?, relock_duration = ?, access_location_id = ?, relock_on_remote = ?, relock_on_device_auth = ? WHERE id = ?",
            (1 if buzz_enabled else 0, relock_duration, access_location_id or None, 1 if relock_on_remote else 0, 1 if relock_on_device_auth else 0, lock_id),
        )
        await self._db.commit()

    async def get_locks_for_location(self, location_id: str) -> list[dict[str, Any]]:
        """Return all non-hidden locks associated with an Access location (native or linked)."""
        async with self._db.execute(
            "SELECT * FROM locks WHERE (location_id = ? OR access_location_id = ?) AND hidden = 0",
            (location_id, location_id),
        ) as cursor:
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
        now = datetime.now(timezone.utc).isoformat()
        cursor = await self._db.execute(
            """
            INSERT INTO access_rules
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
        await self._db.commit()
        return cursor.lastrowid

    async def update_rule(
        self,
        rule_id: int,
        enabled: bool,
        schedule_enabled: bool = False,
        schedule_days: Optional[str] = None,
        schedule_start: Optional[str] = None,
        schedule_end: Optional[str] = None,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
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
        now = datetime.now(timezone.utc).isoformat()
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

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        params.append(limit)

        async with self._db.execute(
            f"SELECT * FROM access_log {where} ORDER BY timestamp DESC LIMIT ?",
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
        now = datetime.now(timezone.utc).isoformat()
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
        try:
            await self._db.execute("DELETE FROM group_locks WHERE group_id = ?", (group_id,))
            for lid in lock_ids:
                await self._db.execute(
                    "INSERT INTO group_locks (group_id, lock_id) VALUES (?, ?)",
                    (group_id, lid),
                )
            await self._db.commit()
        except Exception:
            await self._db.rollback()
            raise

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
        placeholders = ",".join("?" for _ in lock_ids)
        async with self._db.execute(
            f"SELECT * FROM entry_devices WHERE lock_id IN ({placeholders}) ORDER BY lock_id, name",
            lock_ids,
        ) as cur:
            rows = await cur.fetchall()
        result: dict[int, list[dict[str, Any]]] = {}
        for row in rows:
            item = _row_to_dict(row)
            result.setdefault(item["lock_id"], []).append(item)
        return result

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

    async def get_locks_by_entry_device(self, device_type: str, device_id: str | None = None, entity_id: str | None = None) -> list[dict[str, Any]]:
        """Find locks linked to a specific entry device."""
        if device_id:
            query = "SELECT l.* FROM locks l JOIN entry_devices ed ON ed.lock_id = l.id WHERE ed.type = ? AND ed.device_id = ?"
            params = (device_type, device_id)
        elif entity_id:
            query = "SELECT l.* FROM locks l JOIN entry_devices ed ON ed.lock_id = l.id WHERE ed.type = ? AND ed.entity_id = ?"
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

    async def update_visitor_end_time(self, visitor_id: int, end_time: str) -> None:
        await self._db.execute(
            "UPDATE visitors SET end_time = ? WHERE id = ?", (end_time, visitor_id)
        )
        await self._db.commit()

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
        now = now if now is not None else __import__("time").time()
        await self._db.execute("BEGIN IMMEDIATE")
        try:
            async with self._db.execute(
                "SELECT lockout_until FROM rate_limits WHERE scope = ? AND subject = ?",
                (scope, subject),
            ) as cur:
                row = await cur.fetchone()
            if not row:
                await self._db.commit()
                return False
            lockout_until = row["lockout_until"] or 0
            if now < lockout_until:
                await self._db.commit()
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
        import time

        now = now if now is not None else time.time()
        await self._db.execute("BEGIN IMMEDIATE")
        try:
            async with self._db.execute(
                "SELECT attempts_json, lockout_until FROM rate_limits WHERE scope = ? AND subject = ?",
                (scope, subject),
            ) as cur:
                row = await cur.fetchone()

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
        await self._db.execute(
            "DELETE FROM rate_limits WHERE scope = ? AND subject = ?",
            (scope, subject),
        )
        await self._db.commit()

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
        import time

        now = now if now is not None else time.time()
        await self._db.execute("BEGIN IMMEDIATE")
        try:
            async with self._db.execute(
                "SELECT attempts_json, lockout_until FROM rate_limits WHERE scope = ? AND subject = ?",
                (scope, subject),
            ) as cur:
                row = await cur.fetchone()

            lockout_until = row["lockout_until"] if row else 0
            if lockout_until and now < lockout_until:
                await self._db.commit()
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
        import time

        now = now if now is not None else time.time()
        async with self._db.execute(
            "SELECT value_json, expires_at FROM ui_cache WHERE key = ?",
            (key,),
        ) as cur:
            row = await cur.fetchone()
        if not row:
            return None
        if row["expires_at"] <= now:
            await self._db.execute("DELETE FROM ui_cache WHERE key = ?", (key,))
            await self._db.commit()
            return None
        return json.loads(row["value_json"])

    async def set_ui_cache(self, key: str, value: Any, ttl: int, now: float | None = None) -> None:
        import time

        now = now if now is not None else time.time()
        await self._db.execute(
            """
            INSERT INTO ui_cache (key, value_json, expires_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value_json = excluded.value_json,
                expires_at = excluded.expires_at
            """,
            (key, json.dumps(value), now + ttl),
        )
        await self._db.commit()

    async def prune_runtime_state(self, now: float | None = None) -> None:
        import time

        now = now if now is not None else time.time()
        await self._db.execute("DELETE FROM ui_cache WHERE expires_at <= ?", (now,))
        await self._db.execute(
            "DELETE FROM rate_limits WHERE lockout_until != 0 AND lockout_until <= ? AND attempts_json = '[]'",
            (now,),
        )
        await self._db.commit()

    # ------------------------------------------------------------------
    # Pending relocks (survive restarts)
    # ------------------------------------------------------------------

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
        await self._db.execute(
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
        await self._db.commit()

    async def remove_pending_relock(self, entity_id: str) -> None:
        await self._db.execute("DELETE FROM pending_relocks WHERE entity_id = ?", (entity_id,))
        await self._db.commit()

    async def remove_pending_relock_at_deadline(
        self, entity_id: str, deadline: float
    ) -> int:
        """
        Delete the pending_relock row ONLY if its deadline matches `deadline`.

        Used by rehydrate's past-due path to avoid clobbering a row that a
        concurrent schedule() may have added with a newer deadline while
        the HA lock call was in flight. Returns rowcount.
        """
        async with self._db.execute(
            "DELETE FROM pending_relocks WHERE entity_id = ? AND deadline = ?",
            (entity_id, deadline),
        ) as cur:
            count = cur.rowcount or 0
        await self._db.commit()
        return count

    async def get_pending_relocks(self) -> list[dict[str, Any]]:
        async with self._db.execute(
            "SELECT * FROM pending_relocks ORDER BY deadline"
        ) as cursor:
            rows = await cursor.fetchall()
            return [_row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Log retention
    # ------------------------------------------------------------------

    async def prune_logs(self, retain_days: int = 90) -> dict[str, int]:
        """Delete access_log and admin_log rows older than retain_days. Returns counts."""
        # Clamp retain_days to safe range to make the f-string injection-safe.
        days = max(1, int(retain_days))
        cutoff_sql = f"datetime('now', '-{days} days')"
        result: dict[str, int] = {"access_log": 0, "admin_log": 0}

        async with self._db.execute(
            f"DELETE FROM access_log WHERE timestamp < {cutoff_sql}"
        ) as cur:
            result["access_log"] = cur.rowcount or 0

        async with self._db.execute(
            f"DELETE FROM admin_log WHERE timestamp < {cutoff_sql}"
        ) as cur:
            result["admin_log"] = cur.rowcount or 0

        await self._db.commit()
        return result
