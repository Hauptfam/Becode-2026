import json

import pytest

from ioc_enricher import cli
from ioc_enricher.enrich import Report, Verdict, enrich
from ioc_enricher.ioc import IOCType, parse
from ioc_enricher.providers import Provider, ProviderResult, Status


class StubProvider(Provider):
    """Returns a fixed score per IOC value, so verdict logic can be tested in isolation."""

    requires_key = False

    def __init__(self, name, scores, types=frozenset(IOCType)):
        super().__init__()
        self.name = name
        self.scores = scores
        self.supported_types = types
        self.seen = []

    def _lookup(self, ioc):
        self.seen.append(ioc.value)
        if ioc.value not in self.scores:
            return ProviderResult(self.name, Status.NOT_FOUND)
        return ProviderResult(self.name, Status.OK, score=self.scores[ioc.value], summary=f"score {self.scores[ioc.value]}")


def report_with(*scores):
    return Report(parse("8.8.8.8"), [ProviderResult(f"p{i}", Status.OK, score=s) for i, s in enumerate(scores)])


@pytest.mark.parametrize(
    ("scores", "verdict"),
    [
        ((95,), Verdict.MALICIOUS),
        ((40,), Verdict.SUSPICIOUS),
        ((0, 10), Verdict.CLEAN),
        ((None,), Verdict.UNKNOWN),
        ((), Verdict.UNKNOWN),
        ((40, 30), Verdict.SUSPICIOUS),   # 40 + 10 agreement bonus = 50
        ((60, 40, 30), Verdict.MALICIOUS),  # 60 + 20 bonus = 80
    ],
)
def test_verdicts(scores, verdict):
    assert report_with(*scores).verdict == verdict


def test_score_ignores_errors_and_caps_at_100():
    report = report_with(100, 90, 80)
    report.results.append(ProviderResult("bad", Status.ERROR, score=None))
    assert report.score == 100


def test_enrich_skips_private_ips_and_keeps_order():
    stub = StubProvider("stub", {"1.1.1.1": 0, "evil.com": 90})
    iocs = [parse("evil.com"), parse("10.0.0.1"), parse("1.1.1.1")]
    reports = enrich(iocs, [stub])
    assert [r.ioc.value for r in reports] == ["evil.com", "10.0.0.1", "1.1.1.1"]
    assert [r.verdict for r in reports] == [Verdict.MALICIOUS, Verdict.PRIVATE, Verdict.CLEAN]
    assert "10.0.0.1" not in stub.seen


def test_enrich_only_calls_supporting_providers():
    ip_only = StubProvider("ip", {}, types=frozenset({IOCType.IPV4}))
    enrich([parse("evil.com"), parse("1.2.3.4")], [ip_only])
    assert ip_only.seen == ["1.2.3.4"]


# --- CLI ----------------------------------------------------------------------------

@pytest.fixture
def stub_cli(monkeypatch):
    stub = StubProvider("stub", {"evil.com": 90, "8.8.8.8": 0})
    monkeypatch.setattr(cli, "default_providers", lambda timeout: [stub])
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True, raising=False)
    return stub


def test_cli_text_output(stub_cli, capsys):
    assert cli.main(["evil[.]com", "8.8.8.8", "--no-color"]) == 0
    out = capsys.readouterr().out
    assert "[MALICIOUS 90] evil[.]com" in out
    assert "[CLEAN 0] 8[.]8[.]8[.]8" in out
    assert "2 IOC(s) checked" in out


def test_cli_json_output(stub_cli, capsys):
    cli.main(["evil.com", "-o", "json"])
    data = json.loads(capsys.readouterr().out)
    assert data["reports"][0]["verdict"] == "MALICIOUS"
    assert data["reports"][0]["defanged"] == "evil[.]com"


def test_cli_csv_and_markdown(stub_cli, capsys):
    cli.main(["evil.com", "-o", "csv"])
    assert "evil.com,evil[.]com,domain,MALICIOUS,90" in capsys.readouterr().out
    cli.main(["evil.com", "-o", "md"])
    assert "| `evil[.]com` | domain | MALICIOUS | 90 |" in capsys.readouterr().out


def test_cli_fail_on(stub_cli):
    assert cli.main(["evil.com", "--fail-on", "malicious"]) == cli.EXIT_FLAGGED
    assert cli.main(["8.8.8.8", "--fail-on", "suspicious"]) == cli.EXIT_OK


def test_cli_reads_file_with_comments(stub_cli, tmp_path, capsys):
    f = tmp_path / "iocs.txt"
    f.write_text("# incident 42\nevil[.]com  # C2\n\nnonsense value\nevil.com\n")
    cli.main(["-f", str(f), "-o", "json"])
    captured = capsys.readouterr()
    assert len(json.loads(captured.out)["reports"]) == 1  # deduplicated
    assert "skipped: nonsense value" in captured.err


def test_cli_extract_mode(stub_cli, tmp_path, capsys):
    f = tmp_path / "report.txt"
    f.write_text("The actor used evil[.]com and dropped stage2.exe")
    cli.main(["-x", "-f", str(f), "-o", "json"])
    reports = json.loads(capsys.readouterr().out)["reports"]
    assert [r["ioc"] for r in reports] == ["evil.com"]


def test_cli_no_valid_input(stub_cli, capsys):
    assert cli.main(["hello"]) == cli.EXIT_USAGE
    assert "no valid IOCs" in capsys.readouterr().err


def test_cli_writes_output_file(stub_cli, tmp_path):
    out = tmp_path / "results.csv"
    cli.main(["evil.com", "-o", "csv", "--out", str(out)])
    assert out.read_text().startswith("ioc,defanged,type,verdict,score")
