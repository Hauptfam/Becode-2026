# ioc-enricher

[![CI](https://github.com/Hauptfam/Becode-2026/actions/workflows/ioc-enricher-ci.yml/badge.svg)](https://github.com/Hauptfam/Becode-2026/actions/workflows/ioc-enricher-ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A command-line tool that takes the indicators of compromise (IOCs) from an alert (IP addresses, domains, URLs, file hashes) and checks them against several threat-intelligence sources at once, then gives a single verdict per indicator.

It automates one of the most repetitive steps of SOC Tier 1 triage: opening VirusTotal, AbuseIPDB, URLhaus and WHOIS in separate tabs and pasting the same indicator into each of them.

## Features

- **Four sources in parallel**: VirusTotal, AbuseIPDB, abuse.ch URLhaus and RDAP (the modern WHOIS, no key needed).
- **One verdict per IOC**: `MALICIOUS`, `SUSPICIOUS`, `CLEAN`, `UNKNOWN`, or `PRIVATE`, with a 0 to 100 score.
- **Handles defanged input**: `hxxp://evil[.]com`, `1.2.3[.]4`, `evil(dot)com` are refanged automatically, and output is always defanged so it's safe to paste into tickets.
- **Extract mode**: give it a threat report, phishing email or log file and it pulls out every IOC (and ignores file names like `invoice.pdf.exe`).
- **Ticket-ready output**: colored terminal view, JSON, CSV, or a Markdown table you can paste straight into an incident ticket.
- **Pipeline friendly**: reads stdin, and `--fail-on malicious` returns exit code 2 so it can be used in scripts and SOAR playbooks.
- **Analyst-safe defaults**: private/internal IPs are never sent to external services, and newly registered domains (< 30 days) are flagged as suspicious.
- **Works without keys**: missing API keys just skip that source.

## Example

```text
$ ioc-enricher 44d88612fea8a8f36de82e1278abb02f "hxxp://login-micros0ft-secure[.]example/auth" 8.8.8.8 10.20.30.40

[MALICIOUS 100] 44d88612fea8a8f36de82e1278abb02f  (md5)
  VirusTotal   62/76 engines flag as malicious (virus.eicar/test)
  URLhaus      payload not listed

[SUSPICIOUS 60] hxxp://login-micros0ft-secure[.]example/auth  (url)
  VirusTotal   3/96 engines flag as malicious, 1 suspicious
  URLhaus      URL not listed

[CLEAN 0] 8[.]8[.]8[.]8  (ipv4)
  VirusTotal   0/94 engines flag as malicious
  AbuseIPDB    confidence 0%, 41 reports in 90d
  URLhaus      host not listed
  RDAP/WHOIS   Google LLC, US

[PRIVATE] 10[.]20[.]30[.]40  (ipv4)
  internal / non-routable address, external lookups skipped

4 IOC(s) checked: 1 malicious, 1 suspicious, 1 clean, 1 private
```

*(Numbers above are illustrative. The MD5 is the harmless EICAR antivirus test file.)*

## Installation

```bash
git clone https://github.com/Hauptfam/Becode-2026.git
cd Becode-2026/ioc-enricher
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
```

### API keys

All keys are free. Copy the example file and fill in the ones you have:

```bash
cp .env.example .env
```

| Source | Variable | Free tier | Get a key |
|---|---|---|---|
| VirusTotal | `VT_API_KEY` | 4 requests/min, 500/day | https://www.virustotal.com/gui/join-us |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | 1,000 checks/day | https://www.abuseipdb.com/register |
| URLhaus | `URLHAUS_API_KEY` | free | https://auth.abuse.ch/ |
| RDAP | none | | |

`.env` is in `.gitignore`, so your keys never get committed.

## Usage

```bash
# Check a few indicators (defanged is fine)
ioc-enricher 185.220.101.4 evil[.]com e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

# A list of IOCs, one per line (# comments allowed), saved as CSV
ioc-enricher -f examples/sample_indicators.txt -o csv --out results.csv

# Pull every IOC out of a threat report and get a Markdown table for the ticket
ioc-enricher --extract -f examples/threat_report.txt -o md

# Show every field and a link to each source
ioc-enricher -v 8.8.8.8

# Offline mode: answers come from a threat-intel dataset file (labs, demos, no API keys)
ioc-enricher -x -f tests/data/paper_lantern_report.txt --offline-dataset tests/data/paper_lantern_dataset.json

# Use in a script: exit code 2 if anything is malicious
cat alert.log | ioc-enricher --extract --fail-on malicious || echo "escalate!"
```

| Option | Description |
|---|---|
| `-f FILE` | Read IOCs from a file (`-` for stdin) |
| `-x, --extract` | Treat input as free text and extract IOCs from it |
| `-o text\|json\|csv\|md` | Output format |
| `--out PATH` | Write to a file instead of the terminal |
| `-v` | Verbose: all details and source links |
| `--fail-on malicious\|suspicious` | Exit code 2 if an IOC reaches that verdict |
| `--workers N` | Parallel lookups (default 8) |
| `--offline-dataset JSON` | Answer from a dataset file instead of the real APIs |

## How the verdict is computed

Each source returns a score from 0 to 100:

| Source | Scoring |
|---|---|
| VirusTotal | 10+ engines → 100, 5+ → 85, 2+ → 60, 1 engine or 2 "suspicious" → 30. A single detection is often a false positive. |
| AbuseIPDB | Its abuse confidence score, as is. |
| URLhaus | Listed and online → 95, listed but offline → 70 to 80, known payload → 95. |
| RDAP | Domain registered less than 30 days ago → 40. Otherwise informational only. |

The final score is the **highest** score, plus 10 for each additional source that also scores 30 or more (sources agreeing is stronger evidence). ≥ 70 is `MALICIOUS`, ≥ 30 is `SUSPICIOUS`, below that `CLEAN`. With no data at all it's `UNKNOWN`: absence of evidence is not evidence of absence.

> ⚠️ A `CLEAN` verdict means "no source knows it as bad", not "safe". Brand-new infrastructure often has no reputation yet. Always look at the context of the alert.

## Project structure

```
src/ioc_enricher/
├── ioc.py            # type detection, refang/defang, extraction from text
├── enrich.py         # parallel lookups + verdict logic
├── output.py         # text / JSON / CSV / Markdown rendering
├── cli.py            # command-line interface
├── offline.py        # offline mode: answers from a dataset file
└── providers/
    ├── base.py       # shared HTTP + error handling (401, 404, 429...)
    ├── virustotal.py
    ├── abuseipdb.py
    ├── urlhaus.py
    └── rdap.py
tests/                # 101 tests incl. an end-to-end incident scenario, no network needed
```

Adding a new source means writing one class with a `_lookup()` method. See `providers/abuseipdb.py` for the simplest example.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

Tests use a fake HTTP session, so they run offline and never consume API quota.

### Scenario test: "Paper Lantern"

📄 **Full dataset with every IOC, source answer and score calculation: [docs/paper-lantern-dataset.md](docs/paper-lantern-dataset.md)**

`tests/test_scenario.py` runs the whole tool on a **fictional incident** (phishing email → malicious script → loader → C2), the way an analyst would use it:

- `tests/data/paper_lantern_report.txt` is the incident report, with defanged IOCs mixed into normal text and file names.
- `tests/data/paper_lantern_dataset.json` holds invented API responses for each of the 10 IOCs, plus the verdict an analyst would expect and why.

The real provider classes run unchanged against a fake "internet" that answers from the dataset. The test checks that:

| Check | Example from the scenario |
|---|---|
| Every IOC is extracted, nothing extra | `INV-2026-1043.pdf.js` and `fin-ws-07_triage.zip` are ignored |
| Each verdict matches the analyst's expectation | C2 IP → MALICIOUS, decoy PDF → CLEAN, new DLL → UNKNOWN |
| Internal IPs never leave the network | `10.20.4.17` is never sent to any provider |
| One failing source doesn't break triage | VirusTotal rate-limits on `185.81.157.24`, AbuseIPDB still gives SUSPICIOUS |
| Weak signals add up | A 5-day-old domain with 1 VT hit, also listed on URLhaus → MALICIOUS |
| Benign infrastructure isn't flagged | `1.1.1.1` (connectivity check) → CLEAN |
| Output is safe to paste into a ticket | The Markdown table is fully defanged |
| The CLI escalates | `--fail-on malicious` exits with code 2 |

All names, domains (`.example`/`.test` are reserved and never resolve) and threat-intel results in this scenario are made up.

To **see the dataset and the tool's verdicts** in your terminal, without running pytest:

```bash
python tests/show_scenario.py            # report, invented API answers, tool output, expected vs actual
python tests/show_scenario.py --details  # also every field each source returned
```

## Roadmap

- [ ] Local cache (SQLite) to save API quota on repeated lookups
- [ ] More sources: AlienVault OTX, GreyNoise, Shodan, ThreatFox
- [ ] MITRE ATT&CK tags from VirusTotal sandbox reports
- [ ] Send results to TheHive / MISP
- [x] Used by [mini-siem](../mini-siem/) to enrich SIEM alerts

## Disclaimer

For defensive and educational use. Respect each provider's terms of service and rate limits, and never submit sensitive internal data (internal hostnames, customer URLs with tokens) to public services.

## License

MIT
