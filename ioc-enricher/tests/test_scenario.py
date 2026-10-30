"""End-to-end test on a theoretical incident ("Paper Lantern").

The dataset in tests/data/ contains:
  * paper_lantern_report.txt: a fictional incident report with defanged IOCs, as an analyst would receive it
  * paper_lantern_dataset.json: invented API responses for every IOC, plus the verdict an analyst would expect

The real provider classes run unchanged; only the HTTP layer is replaced by a fake
"internet" that answers from the dataset. This checks the whole pipeline:
extraction -> refanging -> provider requests -> response parsing -> scoring -> verdict -> output.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import pytest
from conftest import FakeResponse

from ioc_enricher import cli
from ioc_enricher.enrich import Verdict, enrich
from ioc_enricher.ioc import extract, parse
from ioc_enricher.output import render_markdown
from ioc_enricher.providers import RDAP, AbuseIPDB, Status, URLhaus, VirusTotal

DATA = Path(__file__).parent / "data"
DATASET = json.loads((DATA / "paper_lantern_dataset.json").read_text(encoding="utf-8"))
REPORT_PATH = DATA / DATASET["report_file"]
INDICATORS = {item["value"]: item for item in DATASET["indicators"]}
NOW = datetime.fromisoformat(DATASET["now"])
API_KEY = "test-key"


class ScenarioInternet:
    """Fake requests.Session: works out which provider and IOC a request is for,
    then answers with the dataset entry (or a realistic 'not found')."""

    def __init__(self) -> None:
        self.headers: dict[str, str] = {}
        self.calls: list[tuple[str, str]] = []  # (provider, ioc)

    def request(self, method, url, **kwargs):
        provider, ioc = self._identify(url, kwargs)
        self.calls.append((provider, ioc))
        entry = INDICATORS.get(ioc, {}).get("responses", {}).get(provider)
        if entry is None:
            # URLhaus answers 200 + "no_results"; the others answer 404.
            if provider == "urlhaus":
                return FakeResponse(200, {"query_status": "no_results"})
            return FakeResponse(404)
        return FakeResponse(entry.get("status", 200), entry["body"])

    @staticmethod
    def _identify(url: str, kwargs: dict) -> tuple[str, str]:
        parsed = urlparse(url)
        last = parsed.path.rstrip("/").rsplit("/", 1)[-1]
        if parsed.hostname == "www.virustotal.com":
            if "/urls/" in parsed.path:  # VT identifies URLs by unpadded base64
                last = base64.urlsafe_b64decode(last + "=" * (-len(last) % 4)).decode()
            return "virustotal", last
        if parsed.hostname == "api.abuseipdb.com":
            return "abuseipdb", kwargs["params"]["ipAddress"]
        if parsed.hostname == "urlhaus-api.abuse.ch":
            return "urlhaus", next(iter(kwargs["data"].values()))
        if parsed.hostname == "rdap.org":
            return "rdap", last
        raise AssertionError(f"unexpected outbound request to {url}")


def scenario_providers(internet: ScenarioInternet):
    return [
        VirusTotal(API_KEY, session=internet),
        AbuseIPDB(API_KEY, session=internet),
        URLhaus(API_KEY, session=internet),
        RDAP(session=internet, now=NOW),
    ]


@pytest.fixture(scope="module")
def run():
    """Extract IOCs from the report and enrich them once for the whole module."""
    internet = ScenarioInternet()
    iocs = extract(REPORT_PATH.read_text(encoding="utf-8"))
    reports = enrich(iocs, scenario_providers(internet))
    return {"internet": internet, "reports": {r.ioc.value: r for r in reports}, "order": [i.value for i in iocs]}


# --- Dataset sanity ----------------------------------------------------------------

@pytest.mark.parametrize("item", DATASET["indicators"], ids=lambda i: i["value"][:40])
def test_dataset_values_are_normalised(item):
    ioc = parse(item["value"])
    assert ioc is not None and ioc.value == item["value"]
    assert ioc.type.value == item["type"]


# --- Extraction ----------------------------------------------------------------------

def test_extracts_exactly_the_dataset_iocs_in_report_order(run):
    """Every IOC is found, nothing extra (file names like INV-2026-1043.pdf.js or
    fin-ws-07_triage.zip, or the domain inside a URL, must not be picked up)."""
    assert run["order"] == list(INDICATORS)


# --- Verdicts ------------------------------------------------------------------------

@pytest.mark.parametrize("item", DATASET["indicators"], ids=lambda i: f"{i['expected']['verdict']}:{i['value'][:40]}")
def test_verdict_matches_analyst_expectation(run, item):
    report = run["reports"][item["value"]]
    assert report.verdict == Verdict(item["expected"]["verdict"]), item["role"]
    assert report.score == item["expected"]["score"], item["role"]


def test_verdict_distribution(run):
    counts = {}
    for report in run["reports"].values():
        counts[report.verdict] = counts.get(report.verdict, 0) + 1
    assert counts == {Verdict.MALICIOUS: 5, Verdict.SUSPICIOUS: 1, Verdict.CLEAN: 2,
                      Verdict.PRIVATE: 1, Verdict.UNKNOWN: 1}


# --- Analyst-safety and resilience -----------------------------------------------------

def test_internal_ip_is_never_sent_outside(run):
    assert all(ioc != "10.20.4.17" for _, ioc in run["internet"].calls)
    assert run["reports"]["10.20.4.17"].results == []


def test_rate_limit_does_not_break_the_verdict(run):
    results = {r.provider: r for r in run["reports"]["185.81.157.24"].results}
    assert results["VirusTotal"].status == Status.ERROR
    assert "rate limited" in results["VirusTotal"].summary
    assert results["AbuseIPDB"].status == Status.OK  # other sources still count


def test_newly_registered_domain_is_flagged(run):
    rdap = next(r for r in run["reports"]["invoice-portal-secure.example"].results if r.provider == "RDAP/WHOIS")
    assert rdap.details["age_days"] == 5
    assert "newly registered" in rdap.summary


def test_providers_only_receive_types_they_support(run):
    calls = run["internet"].calls
    assert ("urlhaus", "25e0fbf1e994a30ddbbb1d7d0eefa74cf814bcf8") not in calls  # URLhaus has no SHA1 lookup
    assert not any(p == "abuseipdb" and parse(ioc).type.value != "ipv4" for p, ioc in calls)
    assert not any(p == "rdap" and parse(ioc).type.is_hash for p, ioc in calls)


def test_threat_label_and_family_reach_the_analyst(run):
    summaries = " ".join(r.summary for r in run["reports"][
        "47c564b1a948b0ce4aef199ff63a53ee11c3fc3c073c6499250032c75ae418f9"].results)
    assert "trojan.paperlantern/loader" in summaries
    assert "PaperLantern" in summaries


def test_markdown_ticket_is_fully_defanged(run):
    md = render_markdown(list(run["reports"].values()))
    assert "hxxps://invoice-portal-secure[.]example/view/INV-2026-1043.html" in md
    assert "91[.]215[.]85[.]142" in md
    assert "http://" not in md and "https://invoice-portal" not in md


# --- Full CLI run, as an analyst would type it ---------------------------------------------

def test_cli_end_to_end(monkeypatch, capsys):
    internet = ScenarioInternet()
    monkeypatch.setattr(cli, "default_providers", lambda timeout: scenario_providers(internet))

    exit_code = cli.main(["--extract", "-f", str(REPORT_PATH), "-o", "json", "--fail-on", "malicious"])

    assert exit_code == cli.EXIT_FLAGGED  # malicious IOCs found -> escalate
    reports = json.loads(capsys.readouterr().out)["reports"]
    assert {r["ioc"]: r["verdict"] for r in reports} == {
        value: item["expected"]["verdict"] for value, item in INDICATORS.items()
    }
