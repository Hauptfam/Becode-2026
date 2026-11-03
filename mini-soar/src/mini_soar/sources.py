"""Where alerts come from: the mini-SIEM database directly, or the mini-SIEM web API.

Both sources return alerts in the same shape:

    {"id", "key", "rule_id", "title", "severity", "host", "status", "ti_verdict", "notes",
     "first_seen", "mitre", "iocs": [{"value", "type", "verdict", "defanged"}], "events": [...]}
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class SourceError(RuntimeError):
    pass


def _normalize(alert: dict[str, Any], events: list[dict], iocs: list[dict]) -> dict[str, Any]:
    by_value = {i["value"]: i for i in iocs}
    return {
        "id": alert["id"], "key": alert["key"], "rule_id": alert["rule_id"], "title": alert["title"],
        "severity": alert["severity"], "host": alert.get("host"), "status": alert.get("status", "new"),
        "ti_verdict": alert.get("ti_verdict"), "notes": alert.get("notes") or "",
        "first_seen": alert.get("first_seen"), "mitre": alert.get("mitre") or [],
        "iocs": [{"value": v, "type": by_value.get(v, {}).get("type", "unknown"),
                  "verdict": by_value.get(v, {}).get("verdict", "UNKNOWN"),
                  "defanged": by_value.get(v, {}).get("defanged", v)} for v in alert.get("iocs") or []],
        "events": events,
    }


def sort_alerts(alerts: list[dict]) -> list[dict]:
    return sorted(alerts, key=lambda a: (SEVERITY_ORDER.get(a["severity"], 9), a.get("first_seen") or "", a["id"]))


class AlertSource(ABC):
    spec: str  # how to reconnect later, e.g. "db:/path/mini_siem.db" or "api:http://127.0.0.1:5000"

    @abstractmethod
    def alerts(self) -> list[dict[str, Any]]: ...

    @abstractmethod
    def alert(self, alert_id: int) -> dict[str, Any] | None: ...

    @abstractmethod
    def add_note(self, alert_id: int, note: str, status: str | None = None) -> None:
        """Append a note to the alert (never overwrite the analyst's notes) and optionally change its status."""


class SiemDbSource(AlertSource):
    """Reads the mini-SIEM SQLite database with mini-siem's own Store class."""

    def __init__(self, db_path: str) -> None:
        try:
            from mini_siem.store import Store
        except ImportError as exc:
            raise SourceError("mini-siem is not installed (pip install -e ../mini-siem)") from exc
        self.store = Store(db_path)
        self.spec = f"db:{db_path}"

    def _full(self, alert: dict) -> dict:
        events = [{k: v for k, v in e.items()} for e in self.store.get_events(alert["event_ids"])]
        return _normalize(alert, events, self.store.get_iocs(alert["iocs"]))

    def alerts(self) -> list[dict]:
        return sort_alerts([self._full(a) for a in self.store.alerts()])

    def alert(self, alert_id: int) -> dict | None:
        a = self.store.get_alert(alert_id)
        return self._full(a) if a else None

    def add_note(self, alert_id: int, note: str, status: str | None = None) -> None:
        a = self.store.get_alert(alert_id)
        if a is None:
            raise SourceError(f"alert {alert_id} not found")
        notes = (a["notes"] + "\n" if a["notes"] else "") + note
        self.store.update_alert_status(alert_id, status or a["status"], notes)


class SiemApiSource(AlertSource):
    """Talks to a running mini-SIEM dashboard over HTTP (GET /api/alerts, POST /alerts/<id>/status)."""

    def __init__(self, base_url: str, session=None, timeout: float = 10.0) -> None:
        import requests

        self.base = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.timeout = timeout
        self.spec = f"api:{self.base}"

    def _get(self, path: str) -> Any:
        try:
            resp = self.session.get(f"{self.base}{path}", timeout=self.timeout)
        except Exception as exc:  # requests.RequestException, or the test client's errors
            raise SourceError(f"cannot reach mini-SIEM at {self.base}: {exc.__class__.__name__}") from exc
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            raise SourceError(f"mini-SIEM answered HTTP {resp.status_code} for {path}")
        return resp.json()

    def alerts(self) -> list[dict]:
        listing = self._get("/api/alerts") or []
        return sort_alerts([a for a in (self.alert(x["id"]) for x in listing) if a])

    def alert(self, alert_id: int) -> dict | None:
        data = self._get(f"/api/alerts/{alert_id}")
        if data is None:
            return None
        return _normalize(data, data.get("events", []), data.get("ioc_details", []))

    def add_note(self, alert_id: int, note: str, status: str | None = None) -> None:
        current = self._get(f"/api/alerts/{alert_id}")
        if current is None:
            raise SourceError(f"alert {alert_id} not found")
        notes = (current["notes"] + "\n" if current.get("notes") else "") + note
        resp = self.session.post(f"{self.base}/alerts/{alert_id}/status", timeout=self.timeout,
                                 data={"status": status or current["status"], "notes": notes})
        if resp.status_code not in (200, 302, 303):
            raise SourceError(f"could not update alert {alert_id}: HTTP {resp.status_code}")


def open_source(spec: str) -> AlertSource:
    """'db:PATH' or 'api:URL' (a bare URL starting with http also works)."""
    if spec.startswith("db:"):
        return SiemDbSource(spec[3:])
    if spec.startswith("api:"):
        return SiemApiSource(spec[4:])
    if spec.startswith(("http://", "https://")):
        return SiemApiSource(spec)
    return SiemDbSource(spec)
