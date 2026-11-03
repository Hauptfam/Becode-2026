"""The full pipeline: engine, applicability, risk register, PDF, JSON, SBOM and CLI."""

from __future__ import annotations

import json

from conftest import ROOT
from pypdf import PdfReader

from compliance_check import cli
from compliance_check.engine import risk_level, run, validate_references
from compliance_check.frameworks import FRAMEWORKS
from compliance_check.model import REGISTRY, Status
from compliance_check.pdf import write_pdf
from compliance_check.repo import Repo
from compliance_check.sbom import osv_query, to_cyclonedx


def test_every_reference_is_described():
    assert validate_references() == []


def test_check_ids_are_unique_and_cover_all_frameworks():
    ids = [s.id for s in REGISTRY]
    assert len(ids) == len(set(ids))
    covered = {fw for s in REGISTRY for fw in s.references}
    assert covered == set(FRAMEWORKS)


def test_risk_matrix():
    assert risk_level("likely", "high") == (9, "High")
    assert risk_level("possible", "medium") == (4, "Medium")
    assert risk_level("unlikely", "low") == (1, "Low")


def test_scan_of_this_repository():
    report = run(Repo(ROOT))
    assert len(report.findings) == len(REGISTRY)
    assert not [f.check_id for f in report.findings if "could not run" in f.summary]
    # Facts about this repository that should not change by accident:
    by_id = {f.check_id: f for f in report.findings}
    assert by_id["SEC-01"].status == Status.PASS          # no secrets
    assert by_id["AI-01"].status == Status.NA             # no AI
    assert FRAMEWORKS["AIACT"].applicability_level == "Not applicable"
    assert FRAMEWORKS["GDPR"].applicability_level == "Applies"   # the SIEM processes personal data
    assert "mini-siem" in report.personal_data
    # Risks only come from failed or partial controls, sorted from highest to lowest
    assert all(by_id[r["check_id"]].status in (Status.FAIL, Status.WARN) for r in report.risks)
    assert [r["score"] for r in report.risks] == sorted((r["score"] for r in report.risks), reverse=True)


def test_pdf_report(tmp_path):
    report = run(Repo(ROOT))
    path = tmp_path / "report.pdf"
    write_pdf(report, str(path))
    reader = PdfReader(str(path))
    text = " ".join(page.extract_text() for page in reader.pages)
    assert len(reader.pages) >= 10
    for heading in ("Executive summary", "Scope and applicability", "Results by framework", "Detailed findings",
                    "Risk register", "Organisational requirements", "Software bill of materials"):
        assert heading in text, heading
    for fw in FRAMEWORKS.values():
        assert fw.name in text, fw.name
    assert reader.metadata.title.startswith("Compliance readiness report")


def test_pdf_escapes_repository_content(tmp_path, repo_factory):
    """File names and code come from the scanned repo: they must not break or inject into the PDF markup."""
    repo = repo_factory({"app/pyproject.toml": '[project]\nname = "a<b>&c"\nversion = "1"\ndependencies = ["x"]\n',
                         "tests/data/a.json": '{"e": "<b>x</b>@gmail.com"}'})
    write_pdf(run(repo), str(tmp_path / "r.pdf"))
    assert (tmp_path / "r.pdf").stat().st_size > 10_000


def test_sbom_is_cyclonedx():
    bom = to_cyclonedx(Repo(ROOT))
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.5"
    names = {c["name"].lower() for c in bom["components"]}
    assert {"requests", "flask", "reportlab"} <= names


class FakeOSV:
    def __init__(self, payload=None, fail=False):
        self.payload, self.fail, self.sent = payload, fail, None

    def post(self, url, json=None, timeout=None):
        import requests

        if self.fail:
            raise requests.ConnectionError("offline")
        self.sent = json
        payload = self.payload

        class R:
            def raise_for_status(self):
                pass

            def json(self):
                return payload
        return R()


def test_osv_lookup():
    comps = [{"name": "flask", "version": "0.12"}, {"name": "requests", "version": "2.32.3"}]
    session = FakeOSV({"results": [{"vulns": [{"id": "GHSA-562c-5r94-xh97"}]}, {}]})
    assert osv_query(comps, session=session) == ["flask 0.12: GHSA-562c-5r94-xh97"]
    assert session.sent["queries"][0] == {"package": {"name": "flask", "ecosystem": "PyPI"}, "version": "0.12"}
    assert osv_query(comps, session=FakeOSV(fail=True)) is None


def test_cli_writes_all_outputs(tmp_path, capsys):
    pdf, js, bom = tmp_path / "r.pdf", tmp_path / "r.json", tmp_path / "bom.json"
    code = cli.main([str(ROOT), "--pdf", str(pdf), "--json", str(js), "--sbom", str(bom), "-q"])
    assert code == cli.EXIT_OK
    assert pdf.exists() and json.loads(bom.read_text())["bomFormat"] == "CycloneDX"
    data = json.loads(js.read_text())
    assert set(data["frameworks"]) == set(FRAMEWORKS) and data["findings"]
    assert "Readiness" in capsys.readouterr().out


def test_cli_fail_on(tmp_path, repo_factory):
    repo = repo_factory({"a.py": "eval(x)\n"})
    assert cli.main([str(repo.root), "--no-pdf", "-q", "--fail-on", "fail"]) == cli.EXIT_FAILED
    assert cli.main([str(tmp_path / "missing"), "--no-pdf"]) == cli.EXIT_ERROR


def test_every_category_has_a_report_position():
    from compliance_check.engine import CATEGORY_ORDER

    assert {s.category for s in REGISTRY} <= set(CATEGORY_ORDER)
