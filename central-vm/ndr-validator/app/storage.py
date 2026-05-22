from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from app.config import settings

_lock = threading.RLock()
_conn: sqlite3.Connection | None = None


def init_db() -> None:
    global _conn
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    _conn = sqlite3.connect(settings.sqlite_path, check_same_thread=False)
    _conn.row_factory = sqlite3.Row
    with _lock:
        _conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                generated_at TEXT NOT NULL,
                status TEXT NOT NULL,
                score INTEGER NOT NULL,
                duration_ms REAL NOT NULL,
                payload_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_scans_generated_at ON scans(generated_at DESC);

            CREATE TABLE IF NOT EXISTS metric_state (
                key TEXT PRIMARY KEY,
                value REAL NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )
        _conn.commit()


def close_db() -> None:
    global _conn
    with _lock:
        if _conn:
            _conn.close()
            _conn = None


def _db() -> sqlite3.Connection:
    if _conn is None:
        init_db()
    assert _conn is not None
    return _conn


def save_scan(payload: dict[str, Any]) -> None:
    with _lock:
        db = _db()
        db.execute(
            "INSERT OR REPLACE INTO scans(id, generated_at, status, score, duration_ms, payload_json) VALUES (?, ?, ?, ?, ?, ?)",
            (
                payload["scan_id"],
                payload["generated_at"],
                payload["status"],
                int(payload["score"]),
                float(payload["duration_ms"]),
                json.dumps(payload, default=str),
            ),
        )
        # Keep the DB light; detailed history older than this can be exported from API if needed.
        db.execute(
            "DELETE FROM scans WHERE id NOT IN (SELECT id FROM scans ORDER BY generated_at DESC LIMIT 500)"
        )
        db.commit()


def latest_scan() -> dict[str, Any] | None:
    with _lock:
        row = _db().execute("SELECT payload_json FROM scans ORDER BY generated_at DESC LIMIT 1").fetchone()
        return json.loads(row["payload_json"]) if row else None


def history(limit: int = 100) -> list[dict[str, Any]]:
    with _lock:
        rows = _db().execute(
            "SELECT id, generated_at, status, score, duration_ms FROM scans ORDER BY generated_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]


def get_metric_value(key: str) -> float | None:
    with _lock:
        row = _db().execute("SELECT value FROM metric_state WHERE key = ?", (key,)).fetchone()
        return float(row["value"]) if row else None


def set_metric_value(key: str, value: float, updated_at: str) -> None:
    with _lock:
        _db().execute(
            "INSERT OR REPLACE INTO metric_state(key, value, updated_at) VALUES (?, ?, ?)",
            (key, float(value), updated_at),
        )
        _db().commit()
