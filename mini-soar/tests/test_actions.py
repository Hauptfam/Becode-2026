import json

import pytest
from conftest import FakeSource, make_alert

from mini_soar.actions import ACTIONS, Allowlist, refresh_case_footer


@pytest.mark.parametrize(("value", "kind", "reason"), [
    ("10.20.4.17", "ipv4", "internal/private address"),
    ("192.168.1.10", "ipv4", "internal/private address"),
    ("1.1.1.1", "ipv4", "on the allowlist"),
    ("intranet.lumenfreight.example", "domain", "on the allowlist"),
    ("https://lumenfreight.example/login", "url", "on the allowlist"),
    ("http://10.20.0.50/driver.cab", "url", "internal/private address"),
    ("91.215.85.142", "ipv4", None),
    ("evil.example", "domain", None),
    ("notlumenfreight.example", "domain", None),   # suffix match must respect the dot
])
def test_allowlist(value, kind, reason):
    assert Allowlist.load().reason(value, kind) == reason


def test_block_writes_once_and_respects_allowlist(ctx_factory):
    alert = make_alert(iocs=[
        {"value": "91.215.85.142", "type": "ipv4", "verdict": "MALICIOUS", "defanged": "x"},
        {"value": "1.1.1.1", "type": "ipv4", "verdict": "MALICIOUS", "defanged": "x"},
        {"value": "185.81.157.24", "type": "ipv4", "verdict": "SUSPICIOUS", "defanged": "x"},
    ])
    ctx = ctx_factory(alert)
    block = ACTIONS["block_ioc"]
    assert block.targets(ctx, {"verdicts": ["MALICIOUS"]}) == ["91.215.85.142", "1.1.1.1"]
    assert block.precheck(ctx, "1.1.1.1", {}) == "never blocked: on the allowlist"
    assert block.precheck(ctx, "91.215.85.142", {}) is None
    assert block.execute(ctx, "91.215.85.142", {})[0] == "done"
    assert block.precheck(ctx, "91.215.85.142", {}) == "already blocked"
    lines = [line for line in (ctx.out_dir / "blocklists" / "ips.txt").read_text().splitlines() if not line.startswith("#")]
    assert len(lines) == 1 and lines[0].startswith("91.215.85.142  # MALICIOUS")


def test_block_files_per_type(ctx_factory):
    alert = make_alert(iocs=[{"value": "a" * 64, "type": "sha256", "verdict": "MALICIOUS", "defanged": "a" * 64},
                             {"value": "evil.example", "type": "domain", "verdict": "MALICIOUS", "defanged": "x"}])
    ctx = ctx_factory(alert)
    for target in ("a" * 64, "evil.example"):
        ACTIONS["block_ioc"].execute(ctx, target, {})
    assert {p.name for p in (ctx.out_dir / "blocklists").iterdir()} == {"hashes.txt", "domains.txt"}


def test_isolate_is_simulated_and_not_repeated(ctx_factory):
    ctx = ctx_factory()
    isolate = ACTIONS["isolate_host"]
    assert isolate.targets(ctx, {}) == ["WS1"]
    status, detail = isolate.execute(ctx, "WS1", {}, approved_by="mateo")
    record = json.loads((ctx.out_dir / "edr_actions.jsonl").read_text())
    assert status == "done" and "SIMULATED" in detail
    assert record["simulated"] is True and record["approved_by"] == "mateo"
    assert isolate.precheck(ctx, "WS1", {}) == "host already isolated"
    assert isolate.targets(ctx_factory(make_alert(host=None)), {}) == []


def test_purge_targets_come_from_email_events(ctx_factory):
    events = [{"source": "email", "sender": "a@evil.example", "raw": {"message_id": "<m1@evil.example>"}},
              {"source": "proxy", "raw": {"url": "x"}}]
    assert ACTIONS["purge_email"].targets(ctx_factory(make_alert(events=events)), {}) == ["<m1@evil.example>"]


def test_notify_writes_outbox_without_webhook(ctx_factory):
    ctx = ctx_factory()
    status, _ = ACTIONS["notify"].execute(ctx, "notifications.log", {})
    text = (ctx.out_dir / "notifications.log").read_text()
    assert status == "done" and "[HIGH] MS-X" in text
    assert "91[.]215[.]85[.]142" in text and "91.215.85.142" not in text   # IOCs are defanged in chat messages


class FakeWebhook:
    def __init__(self, status=204, fail=False):
        self.status, self.fail, self.sent = status, fail, None

    def post(self, url, json=None, timeout=None):
        import requests

        if self.fail:
            raise requests.ConnectionError("down")
        assert timeout
        self.sent = (url, json)
        return type("R", (), {"status_code": self.status})()


@pytest.mark.parametrize(("url", "key"), [("https://discord.com/api/webhooks/1/x", "content"),
                                          ("https://hooks.slack.com/services/T/B/x", "text")])
def test_notify_webhook_payload(ctx_factory, url, key):
    hook = FakeWebhook()
    ctx = ctx_factory(webhook_url=url, session=hook)
    assert ACTIONS["notify"].targets(ctx, {}) == ["webhook"]
    status, _ = ACTIONS["notify"].execute(ctx, "webhook", {})
    assert status == "done" and key in hook.sent[1] and "MS-X" in hook.sent[1][key]


def test_notify_webhook_failures(ctx_factory):
    url = "https://discord.com/api/webhooks/1/x"
    down = ctx_factory(webhook_url=url, session=FakeWebhook(fail=True))
    assert ACTIONS["notify"].execute(down, "webhook", {})[0] == "failed"
    assert ACTIONS["notify"].execute(ctx_factory(webhook_url=url, session=FakeWebhook(500)), "webhook", {})[0] == "failed"


def test_update_alert_appends_and_only_moves_new_alerts(ctx_factory):
    alert = make_alert(notes="Analyst: checked with the user")
    source = FakeSource([alert])
    ctx = ctx_factory(alert, source=source)
    ctx.results = [{"id": 1, "action": "block_ioc", "target": "91.215.85.142", "status": "done", "detail": ""}]
    ACTIONS["update_alert"].execute(ctx, "1", {"status": "in_progress"})
    assert source.data[1]["notes"].startswith("Analyst: checked with the user\n[mini-soar")
    assert "blocked 1 IOC(s) (91.215.85.142)" in source.data[1]["notes"]
    assert source.data[1]["status"] == "in_progress"

    closed = make_alert(id=2, status="closed_false_positive")
    source2 = FakeSource([closed])
    ACTIONS["update_alert"].execute(ctx_factory(closed, source=source2), "2", {"status": "in_progress"})
    assert source2.data[2]["status"] == "closed_false_positive"   # never reopens an analyst's decision


def test_cases_group_alerts_per_host(ctx_factory):
    first, second = ctx_factory(make_alert(id=1)), ctx_factory(make_alert(id=2, title="Second alert"))
    t1 = ACTIONS["create_ticket"].targets(first, {})[0]
    ACTIONS["create_ticket"].execute(first, t1, {})
    t2 = ACTIONS["create_ticket"].targets(second, {})[0]
    status, detail = ACTIONS["create_ticket"].execute(second, t2, {})
    assert t1 == t2 == "CASE-0001" and "added to case" in detail
    text = (first.out_dir / "cases" / "CASE-0001.md").read_text()
    assert text.count("## Alert #") == 2 and text.count("## Waiting for an analyst") == 1
    other = ctx_factory(make_alert(id=3, host="WS2"))
    assert ACTIONS["create_ticket"].targets(other, {}) == ["CASE-0002"]


def test_case_footer_lists_pending_approvals(ctx_factory):
    ctx = ctx_factory()
    case = ACTIONS["create_ticket"].targets(ctx, {})[0]
    ACTIONS["create_ticket"].execute(ctx, case, {})
    action_id = ctx.audit.record("isolate_host", "pending", alert=ctx.alert, target="WS1",
                                 params={"alert": {"host": "WS1"}})
    refresh_case_footer(ctx.audit, ctx.out_dir, "WS1")
    assert f"mini-soar approve {action_id}" in (ctx.out_dir / "cases" / f"{case}.md").read_text()
