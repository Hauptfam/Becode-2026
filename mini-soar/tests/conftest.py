from __future__ import annotations

import json
from pathlib import Path

import pytest

from mini_soar.actions import Allowlist, Context
from mini_soar.audit import Audit
from mini_soar.engine import Soar

ROOT = Path(__file__).resolve().parents[1]
RESPONSES = json.loads((ROOT / "data" / "paper_lantern_responses.json").read_text(encoding="utf-8"))
SIEM_LOGS = (ROOT / "data" / RESPONSES["siem_dataset"]).resolve()


@pytest.fixture
def siem_db(tmp_path) -> str:
    """A mini-SIEM database with the Paper Lantern logs ingested, detected and enriched offline."""
    from mini_siem.engine import detect, enrich_alerts, ingest, read_input
    from mini_siem.rules import load_rules
    from mini_siem.store import Store

    path = tmp_path / "mini_siem.db"
    store = Store(path)
    records, assets = read_input(SIEM_LOGS)
    ingest(store, records, assets)
    detect(store, load_rules())
    intel = (SIEM_LOGS.parent / json.loads(SIEM_LOGS.read_text())["threat_intel_dataset"]).resolve()
    enrich_alerts(store, offline_dataset=intel)
    store.close()
    return str(path)


@pytest.fixture
def soar(tmp_path) -> Soar:
    return Soar(Audit(tmp_path / "soar.db"), tmp_path / "out", webhook_url="")


def make_alert(**overrides) -> dict:
    alert = {"id": 1, "key": "MS-X|WS1", "rule_id": "MS-X", "title": "Test alert", "severity": "high",
             "host": "WS1", "status": "new", "ti_verdict": "MALICIOUS", "notes": "", "first_seen": "2026-10-28T08:00:00Z",
             "mitre": [], "events": [],
             "iocs": [{"value": "91.215.85.142", "type": "ipv4", "verdict": "MALICIOUS", "defanged": "91[.]215[.]85[.]142"}]}
    alert.update(overrides)
    return alert


class FakeSource:
    """In-memory alert source that records notes like the mini-SIEM would."""

    spec = "fake:"

    def __init__(self, alerts):
        self.data = {a["id"]: a for a in alerts}

    def alerts(self):
        return list(self.data.values())

    def alert(self, alert_id):
        return self.data.get(alert_id)

    def add_note(self, alert_id, note, status=None):
        a = self.data[alert_id]
        a["notes"] = (a["notes"] + "\n" if a["notes"] else "") + note
        if status:
            a["status"] = status


@pytest.fixture
def ctx_factory(tmp_path):
    audit = Audit(tmp_path / "ctx.db")

    def factory(alert=None, **kw):
        return Context(alert=alert or make_alert(), playbook="PB-T Test", audit=audit, out_dir=tmp_path / "out",
                       source=kw.pop("source", None), allowlist=kw.pop("allowlist", Allowlist.load()), **kw)
    return factory
