# Becode-2026
Repository for cybersecurity projects

## Projects

| Project | Description |
|---|---|
| [ioc-enricher](ioc-enricher/) | CLI that enriches IPs, domains, URLs and file hashes with VirusTotal, AbuseIPDB, URLhaus and RDAP, and gives one verdict per IOC for SOC triage |
| [mini-siem](mini-siem/) | A small SIEM with a web dashboard: parses 5 log sources, detects attacks with Sigma-style rules mapped to MITRE ATT&CK, and enriches alerts with ioc-enricher |
| [mini-soar](mini-soar/) | A small SOAR that acts on mini-siem alerts with YAML playbooks: blocklists, one incident case per host, Discord/Slack notifications, analyst approvals for risky actions, and an audit trail |

Together, ioc-enricher, mini-siem and mini-soar form a small detection-and-response pipeline: **logs → detection → threat-intel enrichment → automated response → analyst decision**. They share a fictional test incident, **Paper Lantern** (phishing email → malicious script → loader → C2 beaconing), seen as indicators ([ioc-enricher](ioc-enricher/docs/paper-lantern-dataset.md)), as logs ([mini-siem](mini-siem/docs/paper-lantern-logs.md)) and as responses ([mini-soar](mini-soar/docs/paper-lantern-responses.md)).

🎤 **Presenting these projects?** See the [interview walkthrough](WALKTHROUGH.md): a 30-second pitch, a 10-minute demo script, design choices and likely questions. To run the whole demo automatically on Windows: `.\demo.ps1`
