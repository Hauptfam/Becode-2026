import json

from conftest import LOGS_PATH

from mini_siem import cli


def test_demo_without_server(tmp_path, capsys):
    db = str(tmp_path / "demo.db")
    assert cli.main(["--db", db, "demo", "--no-serve"]) == 0
    out = capsys.readouterr().out
    assert "43 events" in out and "8 alerts" in out and "5 alerts escalated" in out


def test_step_by_step_workflow(tmp_path, capsys):
    db = str(tmp_path / "siem.db")
    assert cli.main(["--db", db, "ingest", str(LOGS_PATH)]) == 0
    assert cli.main(["--db", db, "detect"]) == 0
    intel = (LOGS_PATH.parent / json.loads(LOGS_PATH.read_text())["threat_intel_dataset"]).resolve()
    assert cli.main(["--db", db, "enrich", "--offline-dataset", str(intel)]) == 0
    capsys.readouterr()
    assert cli.main(["--db", db, "alerts", "--json"]) == 0
    alerts = json.loads(capsys.readouterr().out)
    assert len(alerts) == 8 and sum(a["severity"] == "critical" for a in alerts) == 3


def test_ingest_plain_json_lines(tmp_path, capsys):
    logs = tmp_path / "fw.json"
    logs.write_text('{"timestamp": "2026-10-28 08:00:00", "src": "10.0.0.1", "dst": "1.1.1.1"}\n'
                    '{"timestamp": "2026-10-28 08:00:05", "src": "10.0.0.1", "dst": "8.8.8.8"}\n')
    db = str(tmp_path / "siem.db")
    assert cli.main(["--db", db, "ingest", str(logs)]) == 1            # source is required
    assert cli.main(["--db", db, "ingest", "--source", "firewall", str(logs)]) == 0
    assert "2 events" in capsys.readouterr().out


def test_bad_records_are_skipped_not_fatal(tmp_path, capsys):
    logs = tmp_path / "proxy.json"
    logs.write_text(json.dumps([{"time": "garbage", "url": "x"},
                                {"time": "28/Oct/2026:08:00:00 +0000", "client_ip": "10.0.0.1",
                                 "url": "https://a.example/"}]))
    assert cli.main(["--db", str(tmp_path / "s.db"), "ingest", "--source", "proxy", str(logs)]) == 0
    captured = capsys.readouterr()
    assert "1 events" in captured.out and "skipped record 1" in captured.err


def test_custom_rules_folder(tmp_path, capsys):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "r.yml").write_text("id: X-1\ntitle: Any DNS query\nseverity: low\nlogsource: dns\n"
                                 "mitre: []\ndetection:\n  s: {event_type: dns_query}\n  condition: s\n")
    db = str(tmp_path / "s.db")
    cli.main(["--db", db, "ingest", str(LOGS_PATH)])
    assert cli.main(["--db", db, "--rules", str(rules), "detect"]) == 0
    assert "X-1 Any DNS query" in capsys.readouterr().out


def test_demo_with_missing_dataset(tmp_path, capsys):
    assert cli.main(["--db", str(tmp_path / "d.db"), "demo", "--no-serve", "--logs", str(tmp_path / "nope.json")]) == 1
    assert "scenario not found" in capsys.readouterr().err
