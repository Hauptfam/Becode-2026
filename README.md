# Becode-2026
Repository for cybersecurity projects

## Projects

| Project | Description |
|---|---|
| [ioc-enricher](ioc-enricher/) | CLI that enriches IPs, domains, URLs and file hashes with VirusTotal, AbuseIPDB, URLhaus and RDAP, and gives one verdict per IOC for SOC triage |
| [mini-siem](mini-siem/) | A small SIEM with a web dashboard: parses 5 log sources, detects attacks with Sigma-style rules mapped to MITRE ATT&CK, and enriches alerts with ioc-enricher |
| [compliance-check](compliance-check/) | Scans the repository against NIS2, DORA, the Cyber Resilience Act, ISO/IEC 27001 and 27005, the AI Act and GDPR, and writes a PDF report with evidence, a risk register and an organisational checklist |

Both projects share a fictional test incident, **Paper Lantern** (phishing email → malicious script → loader → C2 beaconing): the IOC dataset is in [`ioc-enricher/docs`](ioc-enricher/docs/paper-lantern-dataset.md) and the log dataset in [`mini-siem/docs`](mini-siem/docs/paper-lantern-logs.md).
