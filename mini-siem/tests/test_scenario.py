"""End-to-end test on the theoretical "Paper Lantern" log dataset (data/paper_lantern_logs.json).

Same idea as ioc-enricher/tests/test_scenario.py: every event in the dataset says which rules it must
trigger ("expected_rules", [] = must stay silent), and "expected_alerts" says what the analyst should
see after detection and after threat-intel enrichment.
"""

from __future__ import annotations

import pytest
from conftest import INTEL_PATH, LOGS, LOGS_PATH

from ioc_enricher.offline import DatasetSession, load_dataset, offline_providers
from mini_siem import engine
from mini_siem.engine import detect, enrich_alerts, ingest, read_input
from mini_siem.rules import load_rules

EVENTS = {e["id"]: e for e in LOGS["events"]}
EXPECTED_ALERTS = {a["rule"]: a for a in LOGS["expected_alerts"]}


@pytest.fixture
def detected(store):
    records, assets = read_input(LOGS_PATH)
    result = ingest(store, records, assets)
    assert result.errors == []
    detect(store, load_rules())
    return store


def rules_by_event(store):
    hits: dict[str, set[str]] = {}
    for alert in store.alerts():
        for event_id in alert["event_ids"]:
            hits.setdefault(event_id, set()).add(alert["rule_id"])
    return hits


# --- Ingestion ----------------------------------------------------------------------------------

def test_every_event_is_ingested_and_attributed_to_a_host(detected):
    events = detected.all_events()
    assert len(events) == len(EVENTS) == 43
    assert {e["source"] for e in events} == {"email", "proxy", "dns", "firewall", "edr"}
    assert all(e.get("host") for e in events), "asset inventory should resolve every event to a host"


def test_timestamps_from_all_formats_line_up_in_one_timeline(detected):
    victim = [e["id"] for e in detected.search_events(host="FIN-WS-07", limit=100)[0]]
    attack_chain = ["mail-02", "proxy-03", "proxy-04", "edr-07", "edr-08", "edr-09", "fw-02", "proxy-08", "edr-10", "edr-11"]
    assert [i for i in victim if i in attack_chain] == attack_chain


# --- Detection: one test per dataset event ---------------------------------------------------------

@pytest.mark.parametrize("event_id", list(EVENTS))
def test_event_triggers_exactly_the_expected_rules(detected, event_id):
    expected = set(EVENTS[event_id]["expected_rules"])
    actual = rules_by_event(detected).get(event_id, set())
    assert actual == expected, EVENTS[event_id]["role"]


def test_alerts_match_expected_alerts(detected):
    alerts = {a["rule_id"]: a for a in detected.alerts()}
    assert set(alerts) == set(EXPECTED_ALERTS)
    for rule_id, exp in EXPECTED_ALERTS.items():
        a = alerts[rule_id]
        assert a["host"] == exp["host"], rule_id
        assert a["event_ids"] == exp["events"], rule_id
        assert a["severity"] == exp["severity"], rule_id
        assert a["ti_verdict"] is None  # not enriched yet


def test_benign_host_has_no_alerts(detected):
    """HR-WS-02 generates look-alike traffic (Teams, .js from a CDN, internal IP download) but no alert."""
    assert detected.alerts(host="HR-WS-02") == []


def test_redetecting_keeps_analyst_work(detected):
    alert = detected.alerts()[0]
    detected.update_alert_status(alert["id"], "in_progress", "checking with the user")
    detect(detected, load_rules())
    again = detected.get_alert(alert["id"])
    assert again["status"] == "in_progress" and again["notes"] == "checking with the user"
    assert len(detected.alerts()) == len(EXPECTED_ALERTS)


# --- Enrichment with ioc-enricher (offline threat-intel dataset) --------------------------------------

def test_enrichment_verdicts_and_escalation(detected):
    summary = enrich_alerts(detected, offline_dataset=INTEL_PATH)
    assert summary["escalated"] == sum(1 for a in EXPECTED_ALERTS.values()
                                       if a["severity_after_enrichment"] != a["severity"])
    for alert in detected.alerts():
        exp = EXPECTED_ALERTS[alert["rule_id"]]
        assert alert["ti_verdict"] == exp["ti_verdict"], alert["rule_id"]
        assert alert["severity"] == exp["severity_after_enrichment"], alert["rule_id"]
        assert alert["base_severity"] == exp["severity"], alert["rule_id"]


def test_c2_alert_carries_the_c2_ip_verdict(detected):
    enrich_alerts(detected, offline_dataset=INTEL_PATH)
    c2 = next(a for a in detected.alerts() if a["rule_id"] == "MS-006")
    assert c2["iocs"] == ["91.215.85.142"]
    ioc = detected.get_iocs(c2["iocs"])[0]
    assert ioc["verdict"] == "MALICIOUS" and ioc["defanged"] == "91[.]215[.]85[.]142"


def test_internal_ips_are_never_sent_to_threat_intel(detected, monkeypatch):
    session = DatasetSession(load_dataset(INTEL_PATH))
    monkeypatch.setattr("ioc_enricher.offline.offline_providers",
                        lambda ds, session_=session: offline_providers(ds, session=session))
    enrich_alerts(detected, offline_dataset=INTEL_PATH)
    queried = {ioc for _, ioc in session.calls}
    assert queried, "the fake internet should have been called"
    assert not any(ioc.startswith(("10.", "192.168.", "172.16.")) for ioc in queried)


def test_enrichment_is_cached(detected):
    first = enrich_alerts(detected, offline_dataset=INTEL_PATH)
    second = enrich_alerts(detected, offline_dataset=INTEL_PATH)
    assert first["looked_up"] == first["iocs"] > 0
    assert second["looked_up"] == 0
    assert enrich_alerts(detected, offline_dataset=INTEL_PATH, refresh=True)["looked_up"] == first["iocs"]


def test_iocs_come_from_alert_events_only():
    events = [{"src_ip": "10.20.4.17", "dst_ip": "91.215.85.142", "url": "http://evil.example/a",
               "domain": "evil.example", "sha256": "a" * 64, "message": "ignored 8.8.8.8"}]
    assert engine.iocs_from_events(events) == ["evil.example", "http://evil.example/a", "91.215.85.142", "a" * 64]
