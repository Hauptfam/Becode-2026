"""Show the "Paper Lantern" test dataset and run the tool on it, offline.

Usage (from the ioc-enricher folder, with the virtual environment active):
    python tests/show_scenario.py            # everything
    python tests/show_scenario.py --details  # also print every field each source returned

It uses the same fake "internet" as tests/test_scenario.py, so no API keys or network are needed.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from test_scenario import (  # noqa: E402
    DATASET,
    INDICATORS,
    REPORT_PATH,
    ScenarioInternet,
    scenario_providers,
)

from ioc_enricher.enrich import enrich  # noqa: E402
from ioc_enricher.ioc import extract, parse  # noqa: E402
from ioc_enricher.output import render_text, use_color  # noqa: E402

PROVIDER_LABELS = {"virustotal": "VirusTotal", "abuseipdb": "AbuseIPDB", "urlhaus": "URLhaus", "rdap": "RDAP/WHOIS"}


def title(text: str, color: bool) -> str:
    bar = "=" * len(text)
    return f"\033[1;36m{text}\n{bar}\033[0m" if color else f"{text}\n{bar}"


def describe_response(provider: str, entry: dict) -> str:
    """One-line, human-readable summary of an invented API response."""
    if entry.get("status", 200) != 200:
        return f"HTTP {entry['status']} (error)"
    body = entry["body"]
    if provider == "virustotal":
        stats = body["data"]["attributes"]["last_analysis_stats"]
        return f"{stats.get('malicious', 0)}/{sum(stats.values())} engines malicious"
    if provider == "abuseipdb":
        d = body["data"]
        return f"confidence {d['abuseConfidenceScore']}%, {d['totalReports']} reports"
    if provider == "urlhaus":
        if "url_status" in body:
            return f"URL listed ({body['url_status']})"
        if "signature" in body:
            return f"known payload ({body['signature']})"
        return f"host listed, {body.get('url_count', '?')} malware URL(s)"
    if provider == "rdap":
        events = {e["eventAction"]: e["eventDate"][:10] for e in body.get("events", [])}
        return f"registered {events['registration']}" if "registration" in events else f"owner {body.get('name')}"
    return "data"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--details", action="store_true", help="print every field each source returned")
    args = parser.parse_args()

    if os.name == "nt":
        os.system("")  # turns on ANSI colors in older Windows consoles
    color = use_color()

    # 1. The input an analyst receives -------------------------------------------------
    print(title(f"1. Incident report ({REPORT_PATH.name})", color))
    print(REPORT_PATH.read_text(encoding="utf-8"))

    # 2. The theoretical dataset ---------------------------------------------------------
    print(title(f"2. Dataset: invented threat-intel answers ({len(INDICATORS)} IOCs)", color))
    print(f"Fixed 'current date' for WHOIS age checks: {DATASET['now'][:10]}\n")
    for n, item in enumerate(DATASET["indicators"], 1):
        print(f"[{n:>2}] {parse(item['value']).defanged}  ({item['type']})")
        print(f"     Role:     {item['role']}")
        responses = item["responses"]
        if not responses:
            print("     Sources:  none (no source knows it)")
        for key, entry in responses.items():
            print(f"     {PROVIDER_LABELS[key] + ':':<12}{describe_response(key, entry)}")
        expected = item["expected"]
        score = "-" if expected["score"] is None else expected["score"]
        print(f"     Expected: {expected['verdict']} (score {score})\n")

    # 3. What the tool does with it ------------------------------------------------------
    print(title("3. Tool output: ioc-enricher --extract -f paper_lantern_report.txt", color))
    reports = enrich(extract(REPORT_PATH.read_text(encoding="utf-8")), scenario_providers(ScenarioInternet()))
    print(render_text(reports, color=color, verbose=args.details))
    print()

    # 4. Expected vs actual -------------------------------------------------------------
    print(title("4. Expected vs actual", color))
    failures = 0
    found = {r.ioc.value: r for r in reports}
    for value, item in INDICATORS.items():
        report = found.get(value)
        exp_v, exp_s = item["expected"]["verdict"], item["expected"]["score"]
        got_v = report.verdict.value if report else "NOT EXTRACTED"
        got_s = report.score if report else None
        ok = got_v == exp_v and got_s == exp_s
        failures += not ok
        mark = "PASS" if ok else "FAIL"
        if color:
            mark = f"\033[1;32m{mark}\033[0m" if ok else f"\033[1;31m{mark}\033[0m"
        print(f"[{mark}] {parse(value).defanged[:60]:<62} expected {exp_v:<10} got {got_v}")
    extra = set(found) - set(INDICATORS)
    for value in extra:
        failures += 1
        print(f"[FAIL] {value}: extracted but not in the dataset")

    print(f"\n{len(INDICATORS) - failures}/{len(INDICATORS)} indicators match the analyst's expectation.")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
