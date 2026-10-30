import pytest

from mini_siem.web import create_app


@pytest.fixture
def client(loaded_store):
    app = create_app(loaded_store.path)
    app.config["TESTING"] = True
    return app.test_client()


def test_alert_queue(client):
    page = client.get("/alerts").get_data(as_text=True)
    assert "Alert queue" in page
    assert page.count('class="bar bar-critical"') == 3
    assert "Regular outbound connections to the same host" in page


def test_alert_filters(client):
    page = client.get("/alerts?severity=medium").get_data(as_text=True)
    assert "MS-007" in page and "MS-006" not in page


def test_alert_detail_shows_defanged_iocs_and_attack(client, loaded_store):
    c2 = next(a for a in loaded_store.alerts() if a["rule_id"] == "MS-006")
    page = client.get(f"/alerts/{c2['id']}").get_data(as_text=True)
    assert "91[.]215[.]85[.]142" in page and "MALICIOUS" in page
    assert "https://attack.mitre.org/techniques/T1071/001/" in page
    assert "Events (8)" in page


def test_triage_status_update(client, loaded_store):
    alert = loaded_store.alerts()[0]
    resp = client.post(f"/alerts/{alert['id']}/status",
                       data={"status": "closed_true_positive", "notes": "Confirmed C2, host isolated"})
    assert resp.status_code == 302
    updated = loaded_store.get_alert(alert["id"])
    assert updated["status"] == "closed_true_positive" and updated["notes"] == "Confirmed C2, host isolated"
    assert client.post(f"/alerts/{alert['id']}/status", data={"status": "bogus"}).status_code == 400


def test_event_search(client):
    page = client.get("/events?q=91.215.85.142").get_data(as_text=True)
    assert "9 events" in page   # 8 beacons + 1 blocked attempt
    page = client.get("/events?source=email").get_data(as_text=True)
    assert "3 events" in page


def test_host_timeline_and_rules(client):
    page = client.get("/hosts/FIN-WS-07").get_data(as_text=True)
    assert page.index("Overdue invoice") < page.index("svc_update.exe loaded")
    assert client.get("/hosts/NOPE").status_code == 404
    rules = client.get("/rules").get_data(as_text=True)
    assert rules.count("MS-00") >= 8 and "T1566.002" in rules


def test_json_api(client, loaded_store):
    alerts = client.get("/api/alerts").get_json()
    assert len(alerts) == 8
    detail = client.get(f"/api/alerts/{alerts[0]['id']}").get_json()
    assert detail["events"] and "ioc_details" in detail
    assert client.get("/api/alerts/999").status_code == 404


def test_pages_escape_log_content(client, store, tmp_path):
    """Log data is attacker-controlled: it must never be rendered as HTML."""
    from mini_siem.engine import ingest

    ingest(store, [("email", {"timestamp": "2026-10-28T10:00:00Z", "sender": "x@evil.example",
                              "recipient": "a@b.example", "subject": "<script>alert(1)</script>"})])
    app = create_app(store.path)
    page = app.test_client().get("/events?q=script").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page
