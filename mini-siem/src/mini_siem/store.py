"""SQLite storage for events, alerts and enriched IOCs."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ALERT_STATUSES = ["new", "in_progress", "closed_true_positive", "closed_false_positive"]

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id         TEXT PRIMARY KEY,
    ts         REAL NOT NULL,
    timestamp  TEXT NOT NULL,
    source     TEXT NOT NULL,
    event_type TEXT,
    host       TEXT,
    message    TEXT,
    data       TEXT NOT NULL,
    raw        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_host ON events(host);

CREATE TABLE IF NOT EXISTS alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    key           TEXT UNIQUE NOT NULL,
    rule_id       TEXT NOT NULL,
    title         TEXT NOT NULL,
    description   TEXT,
    base_severity TEXT NOT NULL,
    severity      TEXT NOT NULL,
    host          TEXT,
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    event_ids     TEXT NOT NULL,
    mitre         TEXT NOT NULL,
    iocs          TEXT NOT NULL DEFAULT '[]',
    ti_verdict    TEXT,
    status        TEXT NOT NULL DEFAULT 'new',
    notes         TEXT NOT NULL DEFAULT '',
    updated_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS iocs (
    value       TEXT PRIMARY KEY,
    type        TEXT NOT NULL,
    defanged    TEXT NOT NULL,
    verdict     TEXT NOT NULL,
    score       INTEGER,
    results     TEXT NOT NULL,
    enriched_at TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class Store:
    def __init__(self, path: str | Path = "mini_siem.db") -> None:
        self.path = str(path)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    def reset(self) -> None:
        with self.conn:
            self.conn.executescript("DELETE FROM events; DELETE FROM alerts; DELETE FROM iocs;")

    # --- events ------------------------------------------------------------------------

    def add_events(self, events: Iterable[dict[str, Any]], raws: Iterable[dict[str, Any]]) -> int:
        rows = [
            (e["id"], e["ts"], e["timestamp"], e["source"], e.get("event_type"), e.get("host"),
             e.get("message"), json.dumps(e), json.dumps(raw))
            for e, raw in zip(events, raws, strict=True)
        ]
        with self.conn:
            self.conn.executemany("INSERT OR REPLACE INTO events VALUES (?,?,?,?,?,?,?,?,?)", rows)
        return len(rows)

    def all_events(self) -> list[dict[str, Any]]:
        return [json.loads(r["data"]) for r in self.conn.execute("SELECT data FROM events ORDER BY ts")]

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
        return self._event_row(row) if row else None

    def get_events(self, ids: Iterable[str]) -> list[dict[str, Any]]:
        ids = list(ids)
        if not ids:
            return []
        marks = ",".join("?" * len(ids))
        rows = self.conn.execute(f"SELECT * FROM events WHERE id IN ({marks}) ORDER BY ts", ids)
        return [self._event_row(r) for r in rows]

    def search_events(self, source: str | None = None, host: str | None = None, q: str | None = None,
                      limit: int = 200, offset: int = 0) -> tuple[list[dict[str, Any]], int]:
        where, params = [], []
        if source:
            where.append("source = ?")
            params.append(source)
        if host:
            where.append("host = ?")
            params.append(host)
        if q:
            where.append("(data LIKE ? OR raw LIKE ?)")
            params += [f"%{q}%", f"%{q}%"]
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        total = self.conn.execute(f"SELECT COUNT(*) FROM events {clause}", params).fetchone()[0]
        rows = self.conn.execute(f"SELECT * FROM events {clause} ORDER BY ts LIMIT ? OFFSET ?",
                                 [*params, limit, offset])
        return [self._event_row(r) for r in rows], total

    def distinct(self, column: str) -> list[str]:
        if column not in ("source", "host"):
            raise ValueError(column)
        rows = self.conn.execute(f"SELECT DISTINCT {column} FROM events WHERE {column} IS NOT NULL ORDER BY 1")
        return [r[0] for r in rows]

    @staticmethod
    def _event_row(row: sqlite3.Row) -> dict[str, Any]:
        return {**json.loads(row["data"]), "raw": json.loads(row["raw"])}

    # --- alerts ------------------------------------------------------------------------

    def upsert_alert(self, alert: dict[str, Any]) -> int:
        """Insert a new alert, or refresh an existing one (same rule + group) keeping its status and notes."""
        with self.conn:
            self.conn.execute(
                """INSERT INTO alerts (key, rule_id, title, description, base_severity, severity, host,
                                       first_seen, last_seen, event_ids, mitre, updated_at)
                   VALUES (:key, :rule_id, :title, :description, :severity, :severity, :host,
                           :first_seen, :last_seen, :event_ids, :mitre, :updated_at)
                   ON CONFLICT(key) DO UPDATE SET
                       title = excluded.title, description = excluded.description,
                       base_severity = excluded.base_severity,
                       severity = CASE WHEN alerts.ti_verdict IS NULL THEN excluded.severity ELSE alerts.severity END,
                       first_seen = excluded.first_seen, last_seen = excluded.last_seen,
                       event_ids = excluded.event_ids, mitre = excluded.mitre, updated_at = excluded.updated_at""",
                {**alert, "event_ids": json.dumps(alert["event_ids"]), "mitre": json.dumps(alert["mitre"]),
                 "updated_at": _now()},
            )
        return self.conn.execute("SELECT id FROM alerts WHERE key = ?", (alert["key"],)).fetchone()[0]

    def delete_alerts_except(self, keys: Iterable[str]) -> None:
        keys = list(keys)
        with self.conn:
            if keys:
                self.conn.execute(f"DELETE FROM alerts WHERE key NOT IN ({','.join('?' * len(keys))})", keys)
            else:
                self.conn.execute("DELETE FROM alerts")

    def alerts(self, status: str | None = None, severity: str | None = None,
               host: str | None = None) -> list[dict[str, Any]]:
        where, params = [], []
        for column, value in (("status", status), ("severity", severity), ("host", host)):
            if value:
                where.append(f"{column} = ?")
                params.append(value)
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        order = "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, first_seen"
        rows = self.conn.execute(f"SELECT * FROM alerts {clause} ORDER BY {order}", params)
        return [self._alert_row(r) for r in rows]

    def get_alert(self, alert_id: int) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        return self._alert_row(row) if row else None

    def update_alert_status(self, alert_id: int, status: str, notes: str | None = None) -> None:
        if status not in ALERT_STATUSES:
            raise ValueError(f"status must be one of {ALERT_STATUSES}")
        with self.conn:
            if notes is None:
                self.conn.execute("UPDATE alerts SET status = ?, updated_at = ? WHERE id = ?",
                                  (status, _now(), alert_id))
            else:
                self.conn.execute("UPDATE alerts SET status = ?, notes = ?, updated_at = ? WHERE id = ?",
                                  (status, notes, _now(), alert_id))

    def set_alert_enrichment(self, alert_id: int, iocs: list[str], ti_verdict: str, severity: str) -> None:
        with self.conn:
            self.conn.execute("UPDATE alerts SET iocs = ?, ti_verdict = ?, severity = ?, updated_at = ? WHERE id = ?",
                              (json.dumps(iocs), ti_verdict, severity, _now(), alert_id))

    @staticmethod
    def _alert_row(row: sqlite3.Row) -> dict[str, Any]:
        alert = dict(row)
        for key in ("event_ids", "mitre", "iocs"):
            alert[key] = json.loads(alert[key])
        return alert

    # --- IOCs --------------------------------------------------------------------------

    def save_ioc(self, report: dict[str, Any]) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO iocs VALUES (?,?,?,?,?,?,?)",
                (report["ioc"], report["type"], report["defanged"], report["verdict"], report["score"],
                 json.dumps(report["results"]), _now()),
            )

    def get_iocs(self, values: Iterable[str]) -> list[dict[str, Any]]:
        values = list(values)
        if not values:
            return []
        rows = self.conn.execute(f"SELECT * FROM iocs WHERE value IN ({','.join('?' * len(values))})", values)
        found = {r["value"]: {**dict(r), "results": json.loads(r["results"])} for r in rows}
        return [found[v] for v in values if v in found]

    # --- stats -------------------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        def counts(sql: str) -> dict[str, int]:
            return {r[0]: r[1] for r in self.conn.execute(sql)}

        return {
            "events": self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
            "events_by_source": counts("SELECT source, COUNT(*) FROM events GROUP BY source ORDER BY source"),
            "alerts_by_severity": counts("SELECT severity, COUNT(*) FROM alerts GROUP BY severity"),
            "alerts_by_status": counts("SELECT status, COUNT(*) FROM alerts GROUP BY status"),
            "hosts": counts("SELECT host, COUNT(*) FROM events WHERE host IS NOT NULL GROUP BY host ORDER BY host"),
        }
