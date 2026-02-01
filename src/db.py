from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from typing import Iterator

from .settings import settings

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:  # pragma: no cover - optional dependency
    psycopg = None
    dict_row = None


DB_KIND = "postgres" if settings.db_url and settings.db_url.startswith("postgres") else "sqlite"


def _ensure_db_dir() -> None:
    if DB_KIND != "sqlite":
        return
    db_dir = os.path.dirname(os.path.abspath(settings.db_path))
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)


def _translate_query(query: str) -> str:
    if DB_KIND != "postgres":
        return query
    translated = []
    in_string = False
    for char in query:
        if char == "'":
            in_string = not in_string
            translated.append(char)
            continue
        if char == "?" and not in_string:
            translated.append("%s")
        else:
            translated.append(char)
    return "".join(translated)


class CursorWrapper:
    def __init__(self, cursor):
        self._cursor = cursor

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()

    @property
    def rowcount(self) -> int:
        return self._cursor.rowcount


class ConnWrapper:
    def __init__(self, conn):
        self._conn = conn

    def execute(self, query: str, params: tuple | list = ()) -> CursorWrapper:
        q = _translate_query(query)
        cur = self._conn.execute(q, params)
        return CursorWrapper(cur)

    def executemany(self, query: str, params: list[tuple]) -> None:
        q = _translate_query(query)
        self._conn.executemany(q, params)

    def executescript(self, script: str) -> None:
        if DB_KIND == "sqlite":
            self._conn.executescript(script)
            return
        statements = [stmt.strip() for stmt in script.split(";") if stmt.strip()]
        for stmt in statements:
            self._conn.execute(stmt)

    def commit(self) -> None:
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()


def _connect() -> ConnWrapper:
    if DB_KIND == "postgres":
        if psycopg is None:
            raise RuntimeError("psycopg is required for Postgres connections")
        conn = psycopg.connect(settings.db_url, row_factory=dict_row)
        return ConnWrapper(conn)
    _ensure_db_dir()
    conn = sqlite3.connect(settings.db_path)
    conn.row_factory = sqlite3.Row
    return ConnWrapper(conn)


@contextmanager
def get_conn() -> Iterator[ConnWrapper]:
    conn = _connect()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def _column_exists(conn: ConnWrapper, table: str, column: str) -> bool:
    if DB_KIND == "postgres":
        row = conn.execute(
            "SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = ? AND column_name = ?",
            (table, column),
        ).fetchone()
        return row is not None
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return any(row[1] == column for row in rows)


def _add_column_if_missing(conn: ConnWrapper, table: str, column: str, col_type: str) -> None:
    if not _column_exists(conn, table, column):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")


def init_db() -> None:
    with get_conn() as conn:
        payload_type = "JSONB" if DB_KIND == "postgres" else "TEXT"
        conn.executescript(
            f"""
            CREATE TABLE IF NOT EXISTS orgs (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS org_memberships (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS teams (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS roles (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                name TEXT NOT NULL,
                permissions_json TEXT NOT NULL,
                inherits_from TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS team_memberships (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                team_id TEXT NOT NULL,
                role_id TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS api_keys (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                name TEXT NOT NULL,
                key_hash TEXT NOT NULL,
                scopes_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_used_at TEXT,
                revoked_at TEXT,
                expires_at TEXT
            );
            CREATE TABLE IF NOT EXISTS sso_configs (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                provider TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scim_groups (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                display_name TEXT NOT NULL,
                members_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS policies (
                id TEXT PRIMARY KEY,
                org_id TEXT,
                name TEXT NOT NULL,
                description TEXT,
                rule_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                inherits_from TEXT,
                version INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS policy_revisions (
                id TEXT PRIMARY KEY,
                policy_id TEXT NOT NULL,
                org_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                description TEXT,
                rule_json TEXT NOT NULL,
                approved_by TEXT,
                approval_signature TEXT,
                rego_text TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS resources (
                id TEXT PRIMARY KEY,
                org_id TEXT,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                attributes_json TEXT NOT NULL,
                source_system TEXT NOT NULL,
                external_id TEXT,
                ai_metadata_json TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS evaluations (
                id TEXT PRIMARY KEY,
                org_id TEXT,
                policy_id TEXT NOT NULL,
                principal TEXT NOT NULL,
                action TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                decision TEXT NOT NULL,
                rationale TEXT,
                explain_json TEXT,
                created_at TEXT NOT NULL,
                prev_hash TEXT,
                record_hash TEXT
            );
            CREATE TABLE IF NOT EXISTS evidence_exports (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                format TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                signature TEXT NOT NULL,
                content_bytes INTEGER NOT NULL,
                record_count INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS evidence_verifications (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                valid INTEGER NOT NULL,
                checked_records INTEGER NOT NULL,
                last_hash TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS evidence_attestations (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                date TEXT NOT NULL,
                record_count INTEGER NOT NULL,
                digest TEXT NOT NULL,
                signature TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS webhooks (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                url TEXT NOT NULL,
                secret TEXT,
                enabled INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS catalog_mappings (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                mapping_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS exception_requests (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                principal TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS abuse_events (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                bucket TEXT NOT NULL,
                score INTEGER NOT NULL,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS webhook_deliveries (
                id TEXT PRIMARY KEY,
                webhook_id TEXT NOT NULL,
                status_code INTEGER,
                response_body TEXT,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at TEXT,
                success INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS decision_logs (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                payload_json {payload_type} NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        _add_column_if_missing(conn, "policies", "org_id", "TEXT")
        _add_column_if_missing(conn, "policies", "inherits_from", "TEXT")
        _add_column_if_missing(conn, "policies", "version", "INTEGER")
        _add_column_if_missing(conn, "resources", "org_id", "TEXT")
        _add_column_if_missing(conn, "evaluations", "org_id", "TEXT")
        _add_column_if_missing(conn, "resources", "source_system", "TEXT")
        _add_column_if_missing(conn, "resources", "external_id", "TEXT")
        _add_column_if_missing(conn, "resources", "ai_metadata_json", "TEXT")
        _add_column_if_missing(conn, "api_keys", "scopes_json", "TEXT")
        _add_column_if_missing(conn, "api_keys", "revoked_at", "TEXT")
        _add_column_if_missing(conn, "api_keys", "expires_at", "TEXT")
        _add_column_if_missing(conn, "evaluations", "prev_hash", "TEXT")
        _add_column_if_missing(conn, "evaluations", "record_hash", "TEXT")
        _add_column_if_missing(conn, "evaluations", "explain_json", "TEXT")
        _add_column_if_missing(conn, "roles", "inherits_from", "TEXT")
        _add_column_if_missing(conn, "evidence_exports", "content_bytes", "INTEGER")
        _add_column_if_missing(conn, "webhook_deliveries", "attempts", "INTEGER")
        _add_column_if_missing(conn, "webhook_deliveries", "next_attempt_at", "TEXT")
        _add_column_if_missing(conn, "webhook_deliveries", "success", "INTEGER")


def now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


def row_to_dict(row) -> dict:
    if row is None:
        return {}
    if isinstance(row, dict):
        return row
    return dict(row)


def parse_json_field(value: str) -> dict:
    return json.loads(value) if value else {}


def dump_json_field(value: dict) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)
