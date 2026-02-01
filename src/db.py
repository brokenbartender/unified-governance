from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from typing import Iterator

from .settings import settings


def _ensure_db_dir() -> None:
    db_dir = os.path.dirname(os.path.abspath(settings.db_path))
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)


def _connect() -> sqlite3.Connection:
    _ensure_db_dir()
    conn = sqlite3.connect(settings.db_path)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    conn = _connect()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def _column_exists(conn: sqlite3.Connection, table: str, column: str) -> bool:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return any(row[1] == column for row in rows)


def _add_column_if_missing(conn: sqlite3.Connection, table: str, column: str, col_type: str) -> None:
    if not _column_exists(conn, table, column):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS orgs (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS api_keys (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                name TEXT NOT NULL,
                key_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_used_at TEXT,
                FOREIGN KEY(org_id) REFERENCES orgs(id)
            );
            CREATE TABLE IF NOT EXISTS policies (
                id TEXT PRIMARY KEY,
                org_id TEXT,
                name TEXT NOT NULL,
                description TEXT,
                rule_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS resources (
                id TEXT PRIMARY KEY,
                org_id TEXT,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                attributes_json TEXT NOT NULL,
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
                created_at TEXT NOT NULL,
                FOREIGN KEY(policy_id) REFERENCES policies(id),
                FOREIGN KEY(resource_id) REFERENCES resources(id)
            );
            """
        )
        _add_column_if_missing(conn, "policies", "org_id", "TEXT")
        _add_column_if_missing(conn, "resources", "org_id", "TEXT")
        _add_column_if_missing(conn, "evaluations", "org_id", "TEXT")


def now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


def row_to_dict(row: sqlite3.Row) -> dict:
    return dict(row)


def parse_json_field(value: str) -> dict:
    return json.loads(value) if value else {}


def dump_json_field(value: dict) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)
