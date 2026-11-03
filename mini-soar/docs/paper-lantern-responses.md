# Test dataset: "Paper Lantern" responses

This page documents the theoretical dataset used by **mini-soar** ([`data/paper_lantern_responses.json`](../data/paper_lantern_responses.json)). It is the third view of the same fictional incident:

| Project | Dataset | One item is... | Expected result |
|---|---|---|---|
| [ioc-enricher](../../ioc-enricher/docs/paper-lantern-dataset.md) | `paper_lantern_dataset.json` | an indicator | its verdict |
| [mini-siem](../../mini-siem/docs/paper-lantern-logs.md) | `paper_lantern_logs.json` | a log event | the rules it triggers |
| **mini-soar** | `paper_lantern_responses.json` | an alert | the playbook and the response actions |

> ⚠️ Everything is fictional: the company, hosts, indicators and threat-intel results are invented.

## How the SOAR decides

1. Alerts are processed **most severe first**, then by time: MS-002, MS-004, MS-006, MS-001, MS-003, MS-005, MS-008, MS-007.
2. The first matching playbook handles each alert: **PB-01** for the phishing email (rule MS-001), **PB-02** when threat intel says an indicator is MALICIOUS, **PB-03** for everything else.
3. Only **MALICIOUS** indicators are blocked automatically. **SUSPICIOUS** ones need an analyst's approval. **UNKNOWN** ones are never blocked: they go to the analyst (and a sandbox).
4. Actions that disrupt people, isolating a computer or deleting emails, always wait for an analyst.
5. Because of the order, later alerts find indicators **already blocked** and approvals **already requested**: the SOAR never does the same thing twice.

## Expected response per alert

| # | Alert | Role | Playbook | Response actions | SIEM status after |
|---|---|---|---|---|---|
| 1 | **MS-002** | Script disguised as a PDF downloaded from the phishing domain (critical, domain MALICIOUS) | PB-02 Contain malware / C2 | ✅ done `block_ioc` `invoice-portal-secure.example`<br>🚫 not run `block_ioc` `https://invoice-portal-secure.example/down...`: URL verdict is UNKNOWN: only MALICIOUS indicators are blocked automatically<br>⏳ pending `isolate_host` `FIN-WS-07`: isolation stops the user from working: an analyst decides | in progress |
| 2 | **MS-004** | Script wrote the loader to disk (critical, hash MALICIOUS) | PB-02 Contain malware / C2 | ✅ done `block_ioc` `47c564b1a948b0ce4aef199ff63a53ee11c3fc3c07...`<br>⏭️ skipped `isolate_host` `FIN-WS-07`: approval already requested by the MS-002 alert | in progress |
| 3 | **MS-006** | C2 beaconing (critical, IP MALICIOUS) | PB-02 Contain malware / C2 | ✅ done `block_ioc` `91.215.85.142`<br>⏭️ skipped `isolate_host` `FIN-WS-07`: approval already requested | in progress |
| 4 | **MS-001** | The phishing email (high, domain and link MALICIOUS) | PB-01 Phishing response | ⏭️ skipped `block_ioc` `invoice-portal-secure.example`: already blocked by the MS-002 alert<br>✅ done `block_ioc` `https://invoice-portal-secure.example/view...`<br>⏳ pending `purge_email` `<7f3a@invoice-portal-secure.example>`: deleting mail from every mailbox needs an analyst | in progress |
| 5 | **MS-003** | wscript.exe ran the script (high, no external indicator) | PB-03 Analyst review | ⏭️ skipped `block_ioc` : no suspicious indicator | new |
| 6 | **MS-005** | Unsigned loader started (high, hash MALICIOUS) | PB-02 Contain malware / C2 | ⏭️ skipped `block_ioc` `47c564b1a948b0ce4aef199ff63a53ee11c3fc3c07...`: already blocked<br>⏭️ skipped `isolate_host` `FIN-WS-07`: approval already requested | in progress |
| 7 | **MS-008** | Second stage downloaded from a VPS (medium, IP SUSPICIOUS) | PB-03 Analyst review | ⏳ pending `block_ioc` `185.81.157.24`: SUSPICIOUS only: block after an analyst approves | new |
| 8 | **MS-007** | Unknown DLL loaded (medium, hash UNKNOWN) | PB-03 Analyst review | ⏭️ skipped `block_ioc` : UNKNOWN is not blocked; send it to a sandbox | new |

Every alert also gets the same three automatic steps: it is added to case **CASE-0001** (one case for the whole incident on FIN-WS-07), a notification is sent, and a note is written into the alert in the SIEM.

## Final state

**Blocklists** (written automatically):

| File | Indicators |
|---|---|
| `domains.txt` | `invoice-portal-secure.example` |
| `urls.txt` | `https://invoice-portal-secure.example/view/INV-2026-1043.html` |
| `ips.txt` | `91.215.85.142` |
| `hashes.txt` | `47c564b1a948b0ce4aef199ff63a53ee11c3fc3c073c6499250032c75ae418f9` |

**Waiting for an analyst:**

| Action | Target |
|---|---|
| `isolate_host` | `FIN-WS-07` |
| `purge_email` | `<7f3a@invoice-portal-secure.example>` |
| `block_ioc` | `185.81.157.24` |

**Must never be blocked automatically:**

| Indicator | Why |
|---|---|
| `10.20.4.17` | internal address of the victim workstation |
| `1.1.1.1` | public DNS resolver on the allowlist (the loader's connectivity check) |
| `lumenfreight.example` | our own domain, on the allowlist |
| `185.81.157.24` | only SUSPICIOUS: needs an analyst |
| `https://invoice-portal-secure.example/download/INV-2026-1043.pdf.js` | verdict UNKNOWN |
| `25e0fbf1e994a30ddbbb1d7d0eefa74cf814bcf8` | verdict UNKNOWN |

## What the tests check

- Every alert goes to the expected playbook, in the expected order.
- Every response action has the expected result (done, pending, skipped), and actions marked "not run" never happen.
- The blocklists contain exactly the expected indicators, and nothing from the never-block list.
- Exactly three approvals are pending; approving the isolation writes the simulated EDR request and a note in the SIEM, and rejecting the VPS block leaves it unblocked.
- One case groups the 8 alerts and lists the open approvals.
- Confirmed alerts move to *In progress* in the SIEM; uncertain ones stay *New*.
- A second run changes nothing.
- The same results come out when the SOAR talks to the mini-SIEM through its web API.

## Run it yourself

```bash
mini-soar demo                        # the whole scenario
pytest tests/test_scenario.py -v      # check it against this dataset
```
