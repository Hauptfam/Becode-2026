import pytest
from conftest import FakeSource, make_alert

from mini_soar.actions import ACTIONS
from mini_soar.playbooks import Playbook, PlaybookError, load_playbooks, select_playbook

KNOWN = set(ACTIONS)


def test_builtin_playbooks_load_in_priority_order():
    books = load_playbooks(known_actions=KNOWN)
    assert [b.id for b in books] == ["PB-01", "PB-02", "PB-03"]
    assert all(b.description for b in books)


@pytest.mark.parametrize(("data", "message"), [
    ({"id": "X", "name": "x", "trigger": {}, "steps": [{"action": "launch_missiles"}]}, "unknown action"),
    ({"id": "X", "name": "x", "trigger": {"colour": "red"}, "steps": [{"action": "notify"}]}, "unknown trigger"),
    ({"id": "X", "name": "x", "trigger": {}, "steps": [{"action": "notify", "approval": "maybe"}]}, "approval"),
    ({"id": "X", "name": "x", "trigger": {}, "steps": []}, "no steps"),
    ({"id": "X", "trigger": {}, "steps": [{"action": "notify"}]}, "missing 'name'"),
])
def test_invalid_playbooks(data, message):
    with pytest.raises(PlaybookError, match=message):
        Playbook.from_dict(data, known_actions=KNOWN)


def test_duplicate_ids(tmp_path):
    for name in ("a.yml", "b.yml"):
        (tmp_path / name).write_text("id: X\nname: x\ntrigger: {}\nsteps:\n  - action: notify\n")
    with pytest.raises(PlaybookError, match="duplicate"):
        load_playbooks(tmp_path, KNOWN)


@pytest.mark.parametrize(("alert", "expected"), [
    (make_alert(rule_id="MS-001", ti_verdict="MALICIOUS"), "PB-01"),    # phishing wins over generic containment
    (make_alert(severity="medium", ti_verdict="MALICIOUS"), "PB-02"),
    (make_alert(ti_verdict="SUSPICIOUS"), "PB-03"),
    (make_alert(ti_verdict="NONE"), "PB-03"),
    (make_alert(ti_verdict="CLEAN"), None),
])
def test_playbook_selection(alert, expected):
    book = select_playbook(load_playbooks(known_actions=KNOWN), alert)
    assert (book.id if book else None) == expected


def test_run_skips_closed_and_unenriched_alerts(soar):
    source = FakeSource([make_alert(id=1, status="closed_true_positive"), make_alert(id=2, key="k2", ti_verdict=None),
                         make_alert(id=3, key="k3", ti_verdict="CLEAN")])
    summary = soar.run(source)
    reasons = {i: why for i, _, why in summary.skipped}
    assert summary.handled == []
    assert "closed" in reasons[1] and "not enriched" in reasons[2] and "no playbook" in reasons[3]


def test_dry_run_changes_nothing(soar):
    source = FakeSource([make_alert()])
    summary = soar.run(source, dry_run=True)
    assert summary.actions["dry-run"] > 0 and summary.actions["done"] == 0
    assert not soar.out_dir.exists() and source.data[1]["notes"] == ""
    assert soar.run(source).handled   # a dry run does not mark the alert as handled
