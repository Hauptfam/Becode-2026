"""The SOAR's own state: an audit trail of every action, processed alerts, and pending approvals."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS actions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT NOT NULL,
    alert_id   INTEGER,
    alert_key  TEXT,
    playbook   TEXT,
    action     TEXT NOT NULL,
    target     TEXT,
    status     TEXT NOT NULL,     -- done | skipped | failed | dry-run | pending | approved | rejected
    detail     TEXT NOT NULL DEFAULT '',
    actor      TEXT NOT NULL DEFAULT 'mini-soar',
    params     TEXT NOT NULL DEFAULT '{}',
    source     TEXT
);
CREATE INDEX IF NOT EXISTS idx_actions_status ON actions(status);

CREATE TABLE IF NOT EXISTS processed (
    alert_key TEXT NOT NULL,
    playbook  TEXT NOT NULL,
    ts        TEXT NOT NULL,
    PRIMARY KEY (alert_key, playbook)
);

CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL);

-- One open case per host groups every alert of the same incident.
CREATE TABLE IF NOT EXISTS cases (host TEXT PRIMARY KEY, case_id TEXT NOT NULL, opened TEXT NOT NULL);
"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class Audit:
    def __init__(self, path: str | Path = "mini_soar.db") -> None:
        self.path = str(path)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    def record(self, action: str, status: str, *, alert: dict | None = None, playbook: str | None = None,
               target: str | None = None, detail: str = "", actor: str = "mini-soar",
               params: dict | None = None, source: str | None = None) -> int:
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO actions (ts, alert_id, alert_key, playbook, action, target, status, detail, actor, params, "
                "source) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (now(), alert["id"] if alert else None, alert["key"] if alert else None, playbook, action, target,
                 status, detail, actor, json.dumps(params or {}), source))
        return cur.lastrowid

    def set_status(self, action_id: int, status: str, detail: str, actor: str) -> None:
        with self.conn:
            self.conn.execute("UPDATE actions SET status = ?, detail = ?, actor = ?, ts = ? WHERE id = ?",
                              (status, detail, actor, now(), action_id))

    def get(self, action_id: int) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM actions WHERE id = ?", (action_id,)).fetchone()
        return self._row(row) if row else None

    def history(self, limit: int = 50, status: str | None = None) -> list[dict[str, Any]]:
        if status:
            rows = self.conn.execute("SELECT * FROM actions WHERE status = ? ORDER BY id DESC LIMIT ?", (status, limit))
        else:
            rows = self.conn.execute("SELECT * FROM actions ORDER BY id DESC LIMIT ?", (limit,))
        return [self._row(r) for r in rows]

    def pending(self) -> list[dict[str, Any]]:
        return [self._row(r) for r in self.conn.execute("SELECT * FROM actions WHERE status = 'pending' ORDER BY id")]

    def has_pending(self, action: str, target: str | None) -> bool:
        row = self.conn.execute("SELECT 1 FROM actions WHERE status = 'pending' AND action = ? AND target IS ?",
                                (action, target)).fetchone()
        return row is not None

    def was_processed(self, alert_key: str, playbook: str) -> bool:
        row = self.conn.execute("SELECT 1 FROM processed WHERE alert_key = ? AND playbook = ?",
                                (alert_key, playbook)).fetchone()
        return row is not None

    def mark_processed(self, alert_key: str, playbook: str) -> None:
        with self.conn:
            self.conn.execute("INSERT OR IGNORE INTO processed VALUES (?,?,?)", (alert_key, playbook, now()))

    def next_number(self, name: str) -> int:
        with self.conn:
            self.conn.execute("INSERT INTO counters VALUES (?, 1) "
                              "ON CONFLICT(name) DO UPDATE SET value = value + 1", (name,))
        return self.conn.execute("SELECT value FROM counters WHERE name = ?", (name,)).fetchone()[0]

    def case_for(self, host: str) -> str | None:
        row = self.conn.execute("SELECT case_id FROM cases WHERE host = ?", (host,)).fetchone()
        return row[0] if row else None

    def open_case(self, host: str) -> str:
        existing = self.case_for(host)
        if existing:
            return existing
        case_id = f"CASE-{self.next_number('case'):04d}"
        with self.conn:
            self.conn.execute("INSERT INTO cases VALUES (?,?,?)", (host, case_id, now()))
        return case_id

    def pending_for_host(self, host: str) -> list[dict[str, Any]]:
        return [r for r in self.pending() if (r["params"].get("alert") or {}).get("host") == host]

    @staticmethod
    def _row(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        d["params"] = json.loads(d["params"])
        return d
