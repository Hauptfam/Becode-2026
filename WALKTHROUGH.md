# Interview walkthrough

How to present this repository in a SOC analyst interview: a 30-second pitch, a 10-minute live demo with what to say at each step, the design choices worth highlighting, and answers to the questions interviewers usually ask.

📄 **Visual version:** [WALKTHROUGH.pdf](WALKTHROUGH.pdf) explains each step with diagrams, real outputs and screenshots: what you run, what happens inside the tools, what you see, why it matters, and what to say.

| Part | Time | Goal |
|---|---|---|
| [The pitch](#1-the-30-second-pitch) | 30 s | Say what you built and why it matters for a SOC |
| [The demo](#3-the-demo-script) | 8-10 min | Show one incident flowing through the whole pipeline |
| [Design choices](#4-design-choices-worth-mentioning) | when asked | Show you thought like an analyst, not just a coder |
| [Questions](#5-questions-you-will-probably-get) | when asked | Answer with confidence |

## ⚡ The automated version

Instead of typing the commands, run one script from the `Becode-2026` folder:

```powershell
.\demo.ps1 -Name your-name
```

On the first run it creates a `.venv` folder and installs the three projects (about a minute). Then it plays the five steps of [section 3](#3-the-demo-script). For each step it shows the command, runs it, and prints the points to make, then waits for **Enter** so you can talk. It starts the dashboard in the background, opens your browser on the right page at each step, approves and rejects the SOAR's requests with your name, and stops the dashboard at the end.

| Option | Effect |
|---|---|
| `-Name mateo` | Your name in the approval audit trail |
| `-NoPause` | Run straight through, without waiting (good for a rehearsal) |
| `-NoBrowser` | Don't open the browser (if you prefer to click yourself) |
| `-SkipTests` | Skip step 5 |
| `-Port 8080` | Use another port (it also picks the next free port automatically if 5000 is busy) |
| `-Setup` | Reinstall the projects, for example after a `git pull` |

Type **q** then Enter at any pause to stop. On Mac or Linux, install the projects (section 2), then run `python demo.py`, which takes the same options in lowercase (`--name`, `--no-pause`, ...).

If PowerShell refuses to run the script, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, or start it with `powershell -ExecutionPolicy Bypass -File .\demo.ps1`.

The rest of this guide explains each step, so read it at least once: the script runs the demo, but you are the one who has to explain it.

---

## 1. The 30-second pitch

> "To prepare for SOC work, I built a small detection-and-response pipeline in Python. A **SIEM** collects logs from five sources and detects attacks with rules mapped to MITRE ATT&CK. Each alert's indicators are checked by my **IOC enrichment tool** against VirusTotal, AbuseIPDB and URLhaus. Then a **SOAR** runs playbooks: it blocks confirmed malicious indicators, opens an incident case and notifies the team, but anything disruptive, like isolating a computer, waits for an analyst's approval. Everything is tested on a fictional phishing-to-C2 incident, including benign traffic that looks suspicious and must not raise alerts."

Then offer: *"Would you like me to show it running? It takes about ten minutes."*

---

## 2. Before the interview

Do this the day before, not five minutes before.

**One environment for all three projects** (PowerShell, from the `Becode-2026` folder):

```powershell
git pull
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .\ioc-enricher -e .\mini-siem -e ".\mini-soar[dev]"
```

**Dry run the whole demo once** (section 3), then reset it by running `mini-soar demo` again: it starts from a clean state every time.

**Have open, ready to share:**
- Two PowerShell windows, both in `Becode-2026` with `.venv` activated (one will run the dashboard)
- The GitHub repository page
- This file, for your own notes

**For an online interview:** share one window at a time, increase the terminal font size (Ctrl + mouse wheel), and close notifications.

---

## 3. The demo script

The story you tell: *a finance employee at a fictional company receives a fake invoice email, opens a script disguised as a PDF, a malware loader is installed and starts calling its command-and-control server. Let's follow it through the pipeline.*

### Step 1: Threat-intel enrichment (1-2 min)

```powershell
cd ioc-enricher
ioc-enricher -x -f tests\data\paper_lantern_report.txt --offline-dataset tests\data\paper_lantern_dataset.json
```

You get one verdict per indicator: 5 malicious, 1 suspicious, 2 clean, 1 unknown, 1 private.

**What to say:**
- "`-x` extracts every indicator from a free-text incident report, even defanged ones like `hxxp://evil[.]com`, and ignores file names like `invoice.pdf.js`."
- "Output is always defanged, so it's safe to paste into a ticket."
- Point at **`10[.]20[.]4[.]17` PRIVATE**: "Internal IPs are never sent to external services. That would leak information about the network."
- Point at **`1[.]1[.]1[.]1` CLEAN**: "The malware used a public DNS resolver to check its connection. It appears in the incident, but it's not malicious. Blocking it would break DNS for the company."
- Point at **UNKNOWN**: "Unknown doesn't mean safe. This DLL is brand new, so no source knows it yet. In a real SOC it would go to a sandbox."
- "Here I'm using an offline dataset so the demo doesn't need API keys. With keys in a `.env` file, it queries the real services."

### Step 2: Detection and automated response (1 min)

```powershell
cd ..\mini-soar
mini-soar demo
```

This builds the SIEM database (43 log events → 8 alerts → enrichment), then runs the SOAR playbooks.

**What to say:**
- "The SIEM ingested logs from five sources, each with its own format and timestamp style, and raised 8 alerts."
- "Five alerts were escalated, because threat intel confirmed one of their indicators as malicious."
- "The SOAR handled all 8. It blocked 4 confirmed indicators automatically, and left **3 decisions for a human**: isolating the computer, deleting the phishing email from every mailbox, and blocking an IP that threat intel only rated *suspicious*."

### Step 3: The analyst's view in the SIEM (3-4 min)

In the **second window**:

```powershell
mini-siem --db mini-soar\soar-output\mini_siem.db serve
```

Open **http://127.0.0.1:5000**.

1. **Alert queue.** "Confirmed alerts are *In progress*: the SOAR has acted on them. The uncertain ones stay *New* for an analyst. Severity shows *was high* when enrichment raised it."
2. **Click the beaconing alert** (*Regular outbound connections...*). "This rule doesn't look at one event. It looks for at least 6 connections to the same IP in 15 minutes **at regular intervals**, because malware calls home on a timer. Here are the 8 firewall logs, the IP's verdict from each source, the ATT&CK techniques, and the SOAR's note in the triage box."
3. **Click the host `FIN-WS-07`.** "The host timeline tells the whole attack from top to bottom: phishing email, download, script execution, loader, beaconing, second stage, then isolation. Each alert sits next to the event that caused it."
4. **Rules page.** "8 rules in a Sigma-like YAML format, each with its ATT&CK mapping and its known false positives."

**The point to make here:** "Another workstation generates traffic designed to look suspicious: Teams connections that are frequent but irregular, a JavaScript library from a CDN, a printer driver from an internal IP, a logon script run by `wscript.exe`. None of it raises an alert, and the tests check that."

### Step 4: Human in the loop (1-2 min)

Back in the **first window** (in `mini-soar`):

```powershell
mini-soar pending
mini-soar approve 2 --by your-name
mini-soar reject 31 --by your-name --reason "shared hosting, monitor instead"
mini-soar history --status approved
```

Refresh the alert *Download of a script disguised...* in the browser: the approval appears in its notes.

**What to say:**
- "Isolating a computer stops someone from working, so it needs a human decision. The isolation is simulated here, because there's no real EDR."
- "I rejected the IP block because it was only *suspicious*: a shared hosting IP can also serve legitimate sites."
- "Everything goes into an audit trail: what was done, to what, by whom and when."
- Optionally open `soar-output\cases\CASE-0001.md`: "One case groups all 8 alerts of the incident, instead of 8 separate tickets."

### Step 5: How it's tested (30 s)

```powershell
cd ..\mini-siem
pytest -q
```

"115 tests in the SIEM alone, 271 across the three projects, all offline. The main test checks every one of the 43 log events against the rules it should trigger, including the ones that must stay silent. GitHub Actions runs them on every push."

---

## 4. Design choices worth mentioning

These show analyst thinking, which is what the interviewer is really evaluating.

| Choice | Why |
|---|---|
| Internal IPs are never sent to threat-intel services | Data minimisation (GDPR) and not leaking the network layout |
| The verdict needs several signals | One VirusTotal detection out of 90 is often a false positive; agreeing sources raise the score |
| The beaconing rule checks *regularity*, not just volume | Volume alone would flag Teams, Windows Update, any chatty app |
| Only MALICIOUS is blocked automatically | Blocking on suspicion breaks legitimate services; UNKNOWN goes to an analyst |
| Disruptive actions need approval | Isolating a host or deleting mail affects people and the business |
| An allowlist protects critical services | Blocking a public DNS resolver or your own domain would cause an outage |
| The SOAR never overwrites analyst notes or reopens closed alerts | Automation supports analysts, it doesn't override them |
| Test datasets include false-positive traps | A rule that catches the attack but also fires on normal traffic is useless in a SOC |
| All test data is fictional, on reserved domains | No real personal data in a public repository |

---

## 5. Questions you will probably get

**"What's the difference between a SIEM and a SOAR?"**
The SIEM collects and correlates logs and raises alerts: it *sees*. The SOAR takes alerts and runs playbooks that enrich, contain and document: it *acts*. In my project, the SIEM detects the beaconing, and the SOAR blocks the C2 IP and asks an analyst to approve isolating the computer.

**"What is MITRE ATT&CK and how did you use it?"**
A public knowledge base of attacker tactics and techniques, observed in real attacks. Each of my rules is mapped to a technique, for example T1071.001 (web protocols for C2) for beaconing, so an analyst immediately knows which stage of an attack an alert represents.

**"How do you deal with false positives?"**
Three ways: precise rules (the beaconing regularity check, excluding internal destinations, filtering signed binaries), combining several sources before calling something malicious, and testing rules against benign look-alike traffic. In a real SOC I'd also tune rules based on the alerts analysts close as false positives.

**"What is an IOC? Why defang it?"**
An indicator of compromise: an IP, domain, URL or file hash linked to malicious activity. Defanging (`hxxp://evil[.]com`) makes it non-clickable, so nobody opens a malicious link by accident from a ticket or a chat message.

**"Why not block everything that's suspicious?"**
Because blocking has a cost. A suspicious IP may be shared hosting that also serves legitimate sites. Blocking it could break a business application, so an analyst should decide.

**"Walk me through how you'd triage this phishing alert."**
Check the sender domain (age, reputation, lookalike of a real brand), the links and attachments in threat intel, whether the user clicked (proxy logs) or ran something (EDR), and whether other users received the same email. Then contain (block the domain, remove the emails, isolate if something ran), and document. That's exactly the path the demo follows.

**"What would you improve?"** Be honest, it's a strength:
- Add authentication and CSRF protection to the dashboard before more than one person uses it
- Add a data-retention command: the SIEM keeps logs forever, which GDPR doesn't allow with real data
- Add a SECURITY.md and Dependabot for vulnerability management
- Connect the simulated actions to real tools, such as a firewall API, an EDR or TheHive for cases

**"Did you build this alone?"** Answer honestly. If you used an AI assistant or tutorials, say so and explain what *you* decided and understood: the detection logic, the false-positive traps, why disruptive actions need approval. Interviewers care much more that you can explain and modify the code than how the first draft was written.

---

## 6. Know your code

Before the interview, be ready to open these files and explain them in a few sentences:

| File | What to be able to explain |
|---|---|
| [`mini-siem/src/mini_siem/rules/MS-006_c2_beaconing.yml`](mini-siem/src/mini_siem/rules/MS-006_c2_beaconing.yml) | How the beaconing rule works and why `max_jitter` matters |
| [`mini-siem/src/mini_siem/rules/MS-003_script_host_downloaded_script.yml`](mini-siem/src/mini_siem/rules/MS-003_script_host_downloaded_script.yml) | Why the NETLOGON logon script doesn't trigger it |
| [`ioc-enricher/src/ioc_enricher/enrich.py`](ioc-enricher/src/ioc_enricher/enrich.py) | How the verdict and score are computed |
| [`mini-soar/src/mini_soar/playbooks/PB-02_contain_malware.yml`](mini-soar/src/mini_soar/playbooks/PB-02_contain_malware.yml) | Which steps are automatic and which need approval |
| [`mini-siem/data/paper_lantern_logs.json`](mini-siem/data/paper_lantern_logs.json) | The format of the test dataset (`role`, `expected_rules`) |

A good exercise: change one value (for example `min_count: 6` to `min_count: 10` in the beaconing rule), run the tests, and explain why they fail.

---

## 7. If something goes wrong during the demo

| Problem | Fix |
|---|---|
| `... is not recognized` | The environment isn't active: `.venv\Scripts\Activate.ps1` |
| Browser says *connection refused* | The dashboard isn't running, or you pressed Ctrl+C: start `mini-siem ... serve` again |
| `Address already in use` | Add `--port 8080` and open http://127.0.0.1:8080 |
| Approval IDs differ | Run `mini-soar pending` and use the IDs it shows (`demo.ps1` finds them by itself) |
| `demo.ps1` fails on `soar-output` (file in use) | A dashboard from an earlier run is still open on that database: close that PowerShell window, then retry |
| Anything else | Stay calm, switch to the screenshots in the [mini-siem](mini-siem/README.md) and [mini-soar](mini-soar/README.md) READMEs and explain from there |

Having a fallback ready is a good habit to show in itself: incident response is about staying calm when things don't go as planned.
