"""The SOAR talking to a running mini-SIEM over its web API, and the command line."""

from __future__ import annotations

import pytest
from conftest import RESPONSES

from mini_siem.store import Store
from mini_siem.web import create_app
from mini_soar import cli
from mini_soar.sources import SiemApiSource, SourceError


class FlaskSession:
    """Lets SiemApiSource call the mini-SIEM Flask app in-process, as if over HTTP."""

    def __init__(self, client, base):
        self.client, self.base = client, base

    def get(self, url, timeout=None):
        assert timeout
        resp = self.client.get(url.replace(self.base, ""))
        return type("R", (), {"status_code": resp.status_code, "json": staticmethod(lambda: resp.get_json())})()

    def post(self, url, data=None, timeout=None):
        assert timeout
        return self.client.post(url.replace(self.base, ""), data=data)


def test_run_through_the_web_api(soar, siem_db):
    base = "http://127.0.0.1:5000"
    app = create_app(siem_db)
    source = SiemApiSource(base, session=FlaskSession(app.test_client(), base))
    summary = soar.run(source)
    assert [rule for _, rule, _ in summary.handled] == RESPONSES["processing_order"]
    ips = (soar.out_dir / "blocklists" / "ips.txt").read_text()
    assert "91.215.85.142" in ips
    alerts = {a["rule_id"]: a for a in Store(siem_db).alerts()}
    assert alerts["MS-006"]["status"] == "in_progress" and "[mini-soar" in alerts["MS-006"]["notes"]


def test_unreachable_siem():
    import requests

    with pytest.raises(SourceError, match="cannot reach"):
        SiemApiSource("http://127.0.0.1:9").alerts()
    assert requests  # imported to make sure the real HTTP stack is used


def run(capsys, *argv):
    code = cli.main(list(argv))
    return code, capsys.readouterr()


def test_cli_demo_and_approval_workflow(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("SOAR_WEBHOOK_URL", raising=False)
    db, out = str(tmp_path / "soar.db"), str(tmp_path / "out")
    code, cap = run(capsys, "--db", db, "--out", out, "demo")
    assert code == 0 and "8 alert(s) handled" in cap.out and "isolate_host" in cap.out

    code, cap = run(capsys, "--db", db, "--out", out, "pending")
    first = int(cap.out.split()[0].lstrip("#"))
    code, cap = run(capsys, "--db", db, "--out", out, "approve", str(first), "--by", "mateo")
    assert code == 0 and "approved" in cap.out
    code, cap = run(capsys, "--db", db, "--out", out, "approve", str(first), "--by", "mateo")
    assert code == 1 and "not waiting" in cap.err

    code, cap = run(capsys, "--db", db, "--out", out, "history", "--status", "approved")
    assert "mateo" in cap.out
    code, cap = run(capsys, "--db", db, "--out", out, "playbooks")
    assert "PB-01" in cap.out and "[needs approval]" in cap.out


def test_cli_dry_run(tmp_path, capsys, siem_db):
    out = tmp_path / "out"
    code, cap = run(capsys, "--db", str(tmp_path / "s.db"), "--out", str(out), "run", "--siem", siem_db, "--dry-run")
    assert code == 0 and "DRY RUN" in cap.out
    assert not out.exists()
    assert all("[mini-soar" not in a["notes"] for a in Store(siem_db).alerts())


def test_cli_bad_playbooks_folder(tmp_path, capsys):
    (tmp_path / "bad.yml").write_text("id: X\nname: x\ntrigger: {}\nsteps:\n  - action: format_disk\n")
    code, cap = run(capsys, "--db", str(tmp_path / "s.db"), "--playbooks", str(tmp_path), "playbooks")
    assert code == 1 and "unknown action" in cap.err
