import pytest

from mini_siem.parsers import AssetInventory, ParseError, parse_record, parse_timestamp


@pytest.mark.parametrize("value", [
    "2026-10-28T08:44:02Z",
    "2026-10-28T09:44:02+01:00",
    "28/Oct/2026:08:44:02 +0000",
    "2026-10-28 08:44:02",
    1793177042.0,
])
def test_timestamps_all_become_the_same_utc_instant(value):
    assert parse_timestamp(value).isoformat() == "2026-10-28T08:44:02+00:00"


@pytest.mark.parametrize("value", [None, "", "yesterday", "28-10-2026"])
def test_bad_timestamps_are_rejected(value):
    with pytest.raises(ParseError):
        parse_timestamp(value)


def test_email():
    e = parse_record("email", {"timestamp": "2026-10-28T08:41:07Z", "sender": "Billing@Evil.Example",
                               "recipient": "j.doe@corp.example", "subject": "Invoice",
                               "urls": ["https://evil.example/x"]})
    assert e["sender_domain"] == "evil.example"
    assert e["url_count"] == 1 and e["domain"] == "evil.example"


def test_proxy_with_domain_and_with_bare_ip():
    e = parse_record("proxy", {"time": "28/Oct/2026:08:44:19 +0000", "client_ip": "10.0.0.5",
                               "url": "https://evil.example/a.pdf.js", "status": 200})
    assert e["domain"] == "evil.example" and "dst_ip" not in e
    e = parse_record("proxy", {"time": "28/Oct/2026:08:44:19 +0000", "client_ip": "10.0.0.5",
                               "url": "http://185.81.157.24/m/stage2.bin"})
    assert e["dst_ip"] == "185.81.157.24" and "domain" not in e


def test_firewall_and_dns():
    fw = parse_record("firewall", {"timestamp": "2026-10-28 08:46:10", "src": "10.0.0.5", "sport": 1,
                                   "dst": "91.215.85.142", "dport": 443, "proto": "tcp", "action": "allow"})
    assert fw["dst_ip"] == "91.215.85.142" and fw["dst_port"] == 443
    dns = parse_record("dns", {"ts": 1793177041.0, "client": "10.0.0.5", "query": "Evil.Example.", "answers": []})
    assert dns["domain"] == "evil.example"


def test_edr_hashes_come_from_the_file_for_file_events():
    e = parse_record("edr", {"@timestamp": "2026-10-28T08:45:06Z", "hostname": "WS1", "event_type": "file_create",
                             "process": {"name": "WScript.exe", "sha256": "a" * 64},
                             "file": {"path": "C:\\Users\\Public\\x.exe", "sha256": "b" * 64, "signed": False}})
    assert e["process_name"] == "wscript.exe"
    assert e["sha256"] == "b" * 64 and e["file_name"] == "x.exe"
    assert e["signed"] is False  # False must survive cleaning


def test_asset_inventory_maps_ip_and_mailbox_to_host():
    assets = AssetInventory([{"hostname": "FIN-WS-07", "ip": "10.20.4.17", "user": "j.doe",
                              "email": "j.doe@corp.example"}])
    fw = parse_record("firewall", {"timestamp": "2026-10-28 08:46:10", "src": "10.20.4.17", "dst": "1.1.1.1"}, assets)
    mail = parse_record("email", {"timestamp": "2026-10-28T08:41:07Z", "sender": "a@b.example",
                                  "recipient": "J.Doe@corp.example"}, assets)
    assert fw["host"] == mail["host"] == "FIN-WS-07"
    assert fw["user"] == "j.doe"


def test_unknown_source():
    with pytest.raises(ParseError):
        parse_record("syslog", {})
