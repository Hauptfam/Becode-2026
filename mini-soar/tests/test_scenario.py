"""End-to-end test on the Paper Lantern incident: mini-SIEM alerts -> mini-SOAR playbooks.

data/paper_lantern_responses.json says, for every alert, which playbook must handle it and which response
actions must happen, plus the final blocklists, the approvals left for an analyst, and what must never be blocked.
"""

from __future__ import annotations

import json

import pytest
from conftest import RESPONSES

from mini_siem.store import Store
from mini_soar.sources import SiemDbSource

EXPECTED = {a["rule"]: a for a in RESPONSES["alerts"]}
RESPONSE_ACTIONS = {"block_ioc", "isolate_host", "purge_email"}


@pytest.fixture
def handled(soar, siem_db):
    source = SiemDbSource(siem_db)
    summary = soar.run(source)
    return soar, source, summary, siem_db


def _rule_of(soar, row):
    return row["alert_key"].split("|")[0] if row["alert_key"] else None


def test_alerts_processed_in_expected_order(handled):
    _, _, summary, _ = handled
    assert [rule for _, rule, _ in summary.handled] == RESPONSES["processing_order"]


@pytest.mark.parametrize("rule", list(EXPECTED))
def test_each_alert_gets_the_expected_playbook_and_actions(handled, rule):
    soar, _, summary, _ = handled
    expected = EXPECTED[rule]
    playbook = next(pb for _, r, pb in summary.handled if r == rule)
    assert playbook.startswith(expected["expected_playbook"]), expected["role"]

    rows = [r for r in soar.audit.history(1000) if _rule_of(soar, r) == rule and r["action"] in RESPONSE_ACTIONS]
    for exp in expected["expected_actions"]:
        matching = [r for r in rows if r["action"] == exp["action"] and r["target"] == exp["target"]]
        if exp["status"] == "not run":
            assert not matching, exp
        else:
            assert [r["status"] for r in matching] == [exp["status"]], exp
    assert len(rows) == len([e for e in expected["expected_actions"] if e["status"] != "not run"])


def test_final_blocklists(handled):
    soar, *_ = handled
    for kind, values in RESPONSES["expected_blocklists"].items():
        path = soar.out_dir / "blocklists" / f"{kind}.txt"
        lines = [line.split("#")[0].strip() for line in path.read_text().splitlines() if line and not line.startswith("#")]
        assert lines == values, kind


def test_nothing_on_the_never_block_list_is_blocked(handled):
    soar, *_ = handled
    blocked = " ".join(p.read_text() for p in (soar.out_dir / "blocklists").glob("*.txt"))
    for item in RESPONSES["must_never_be_blocked_automatically"]:
        assert f"\n{item['value']} " not in blocked, item["why"]


def test_pending_approvals(handled):
    soar, *_ = handled
    pending = [(p["action"], p["target"]) for p in soar.audit.pending()]
    assert pending == [(a["action"], a["target"]) for a in RESPONSES["expected_pending_approvals"]]


def test_one_case_for_the_incident(handled):
    soar, *_ = handled
    cases = list((soar.out_dir / "cases").glob("*.md"))
    assert len(cases) == RESPONSES["expected_cases"]
    text = cases[0].read_text()
    assert text.count("## Alert #") == len(EXPECTED)
    for p in soar.audit.pending():
        assert f"mini-soar approve {p['id']}" in text


def test_siem_alerts_are_updated(handled):
    _, _, _, siem_db = handled
    store = Store(siem_db)
    for alert in store.alerts():
        expected = EXPECTED[alert["rule_id"]]
        assert alert["status"] == expected["expected_siem_status"], alert["rule_id"]
        assert "[mini-soar" in alert["notes"]


def test_second_run_does_nothing(handled):
    soar, source, _, _ = handled
    before = len(soar.audit.history(1000))
    again = soar.run(source)
    assert again.handled == [] and len(soar.audit.history(1000)) == before


def test_approve_and_reject(handled):
    soar, _, _, siem_db = handled
    isolate, purge, block_vps = soar.audit.pending()
    status, detail = soar.approve(isolate["id"], "mateo")
    assert status == "approved" and "SIMULATED" in detail
    record = json.loads((soar.out_dir / "edr_actions.jsonl").read_text())
    assert record["host"] == "FIN-WS-07" and record["approved_by"] == "mateo"

    soar.reject(block_vps["id"], "mateo", "shared hosting, monitor instead")
    assert "185.81.157.24" not in (soar.out_dir / "blocklists" / "ips.txt").read_text()

    rows = {r["id"]: r for r in soar.audit.history(1000)}
    assert rows[isolate["id"]]["actor"] == "mateo" and rows[block_vps["id"]]["status"] == "rejected"
    assert [p["id"] for p in soar.audit.pending()] == [purge["id"]]
    notes = Store(siem_db).get_alert(isolate["alert_id"])["notes"]
    assert "isolate_host FIN-WS-07 approved by mateo" in notes
    with pytest.raises(ValueError, match="not waiting"):
        soar.approve(isolate["id"], "mateo")
