# compliance-check

[![CI](https://github.com/Hauptfam/Becode-2026/actions/workflows/compliance-check-ci.yml/badge.svg)](https://github.com/Hauptfam/Becode-2026/actions/workflows/compliance-check-ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A scanner that checks a code repository against the technical requirements of seven European regulations and standards, and writes a **PDF report** with the evidence, a risk register and a checklist of what must be verified by hand.

| Framework | What it is |
|---|---|
| **NIS2** | Directive (EU) 2022/2555: cybersecurity of essential and important entities |
| **DORA** | Regulation (EU) 2022/2554: digital operational resilience of the financial sector |
| **CRA** | Regulation (EU) 2024/2847, Cyber Resilience Act: security of products with digital elements |
| **ISO/IEC 27001:2022** | Information security management systems (Annex A controls) |
| **ISO/IEC 27005:2022** | Information security risk management |
| **AI Act** | Regulation (EU) 2024/1689, as amended by Regulation (EU) 2026/1744 |
| **GDPR** | Regulation (EU) 2016/679: personal data protection |

It was built to assess the other projects in this repository ([ioc-enricher](../ioc-enricher/) and [mini-siem](../mini-siem/)), but works on any Python repository.

> ⚠️ **This is a technical readiness check, not a compliance certificate.** Compliance depends on who uses the software and how, on contracts, governance and training, which no code scan can see. The report says so on every page and lists those organisational requirements separately.

## What it checks

38 automated checks, each mapped to the exact articles, annex points or controls it gives evidence for:

| Area | Examples |
|---|---|
| Secrets & cryptography | Hard-coded API keys and tokens, `.env` files in git, disabled TLS verification, HTTP calls without timeouts |
| Supply chain | Versioned dependencies, SBOM, known vulnerabilities (OSV.dev), Dependabot, CI actions pinned to a commit, CI token permissions |
| Secure development | Tests and linting in CI, security scanners, `eval`/`pickle`/`shell=True`/unsafe YAML, SQL injection, swallowed errors, pull-request reviews |
| Web application | HTML escaping, CSRF tokens, authentication, security headers, debug mode |
| Logging | Security logging and audit trail |
| Personal data (GDPR) | Which projects process personal data, privacy documentation, filtering before third-party lookups, retention, encryption at rest, fictional test data, disclosed data recipients |
| Resilience | Backup and restore |
| Documentation & vulnerability handling | READMEs, SECURITY.md, support period, change log, licences |
| Risk & incidents | Threat model / risk assessment, incident response procedure |
| AI Act | Whether the code contains an AI system at all (ML/LLM libraries, model files) |

Checks read the code's syntax tree rather than searching text where possible. For example, the SQL check recognises a column name checked against a fixed allow-list as safe, and the web checks only run on modules that really import a web framework.

## The report

The PDF has eight parts:

1. **Executive summary**: results per framework (chart), top priorities, what is already in place
2. **Scope and applicability**: whether each framework applies to this project and why, with key dates (for example, the CRA's 24-hour reporting duty since 11 September 2026)
3. **Results by framework**: every referenced article or control, with the checks behind it
4. **Detailed findings**: each check's result, evidence (file and line) and recommendation
5. **Risk register** (ISO/IEC 27005): every gap scored on likelihood x impact, with a heat map and treatment
6. **Organisational checklist**: what must be checked by hand (management approval, incident reporting to the CCB, GDPR records, DPIA, contracts, ...)
7. **Appendices**: software bill of materials, method and limitations, sources

## Installation

```bash
cd compliance-check
python -m venv .venv
source .venv/bin/activate          # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

## Usage

```bash
compliance-check ..                                   # scan the whole repository, write compliance-report.pdf
compliance-check .. --pdf report.pdf --json report.json --sbom sbom.cdx.json
compliance-check .. --online                          # also query OSV.dev for known vulnerabilities
compliance-check .. --no-pdf --fail-on fail           # in CI: exit code 2 if any check fails
```

The terminal shows every check and a summary per framework:

```text
Secrets & cryptography
  [PASS] SEC-01   No secrets hard-coded in the repository
  ...
Framework                Relation               Readiness
  NIS2                   Indirect               53%
  Cyber Resilience Act   Likely out of scope    54%
  AI Act                 Not applicable         -
  GDPR                   Applies                57%
```

**Readiness** is the share of automatically verifiable controls that are in place (a partial control counts half). It is a way to track progress, not a compliance percentage.

Every push to GitHub also produces a fresh report: open the **Actions** tab, then the latest *compliance-check CI* run, and download the `compliance-report` artifact.

## Tests

```bash
pytest
```

Each check is tested on small fake repositories built during the test (one that passes, one that fails), plus a full scan of this repository that generates and reads back the PDF. No test needs the network.

## Limitations

- Heuristics can miss problems or flag safe code: confirm each FAIL and WARN by reading its evidence.
- GitHub settings (branch protection, secret scanning, private vulnerability reporting) aren't visible from a clone.
- Applicability depends on facts outside the code: commercial activity, sector, company size, real data processed.
- The legal facts (dates, article numbers) were checked on 31 October 2026 and live in [`frameworks.py`](src/compliance_check/frameworks.py). Laws change, so review that file before relying on a report.
- Not legal advice, a certification audit or a conformity assessment.

## License

MIT
