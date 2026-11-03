"""Automated interview demo: the Paper Lantern incident through ioc-enricher -> mini-siem -> mini-soar.

Usage (after the projects are installed; on Windows, demo.ps1 installs them for you):
    python demo.py                    # step by step, pausing between steps
    python demo.py --name mateo       # your name in the approval audit trail
    python demo.py --no-pause         # run straight through (rehearsal, CI)

See WALKTHROUGH.md for the full script of what to say.
"""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
IOC = ROOT / "ioc-enricher"
SIEM = ROOT / "mini-siem"
SOAR = ROOT / "mini-soar"
SIEM_DB = SOAR / "soar-output" / "mini_siem.db"
SOAR_DB = SOAR / "mini_soar.db"
SEP = os.sep

USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ
if os.name == "nt":
    os.system("")  # turns on ANSI colours in older Windows consoles


def color(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


def title(number: int, text: str, minutes: str) -> None:
    line = "=" * 72
    print("\n" + color(line, "36"))
    print(color(f" STEP {number}/5  {text}", "1;36") + color(f"   (~{minutes})", "2"))
    print(color(line, "36"))


def say(*points: str) -> None:
    print(color("\n  What to say:", "1;33"))
    for p in points:
        print(color(f"   - {p}", "33"))


def command(display: str) -> None:
    print("\n" + color(f"  $ {display}", "1;32") + "\n")


class Demo:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.dashboard: subprocess.Popen | None = None
        self.dashboard_log = None
        self.port = args.port

    # --- helpers ---------------------------------------------------------------------------------

    def pause(self, message: str = "Press Enter for the next step (q + Enter to quit)") -> None:
        if self.args.no_pause:
            return
        answer = input(color(f"\n  >> {message}... ", "2"))
        if answer.strip().lower() == "q":
            raise KeyboardInterrupt

    def run(self, display: str, module_args: list[str], cwd: Path) -> int:
        command(display)
        result = subprocess.run([sys.executable, "-m", *module_args], cwd=cwd, check=False)
        if result.returncode not in (0,):
            print(color(f"\n  (exit code {result.returncode})", "31"))
        return result.returncode

    def open(self, path: str) -> None:
        url = f"http://127.0.0.1:{self.port}{path}"
        print(color(f"  Browser: {url}", "36"))
        if not self.args.no_browser:
            webbrowser.open(url)

    # --- steps ------------------------------------------------------------------------------------

    def step1_enrichment(self) -> None:
        title(1, "Threat-intel enrichment with ioc-enricher", "1-2 min")
        print("  A fictional incident report contains indicators, some written defanged.")
        self.run(f"ioc-enricher -x -f tests{SEP}data{SEP}paper_lantern_report.txt "
                 f"--offline-dataset tests{SEP}data{SEP}paper_lantern_dataset.json",
                 ["ioc_enricher", "-x", "-f", str(Path("tests", "data", "paper_lantern_report.txt")),
                  "--offline-dataset", str(Path("tests", "data", "paper_lantern_dataset.json"))], IOC)
        say("-x pulls every indicator out of free text, even defanged ones, and ignores file names.",
            "Output is always defanged, so it is safe to paste into a ticket.",
            "10[.]20[.]4[.]17 is PRIVATE: internal IPs are never sent to external services.",
            "1[.]1[.]1[.]1 is CLEAN: the malware used a public DNS resolver to test its connection.",
            "UNKNOWN does not mean safe: a brand-new DLL would go to a sandbox.",
            "Offline dataset here, so no API keys are needed; with keys it queries the real services.")
        self.pause()

    def step2_detect_and_respond(self) -> None:
        title(2, "Detection (mini-siem) and automated response (mini-soar)", "1 min")
        print("  43 log events from 5 sources -> 8 alerts -> enrichment -> playbooks.")
        code = self.run("mini-soar demo", ["mini_soar", "demo"], SOAR)
        if code:
            raise SystemExit("The mini-soar demo failed: run demo.ps1 -Setup (or reinstall the projects) and retry.")
        say("The SIEM raised 8 alerts; 5 were escalated because threat intel confirmed an indicator.",
            "The SOAR blocked 4 confirmed indicators automatically.",
            "It left 3 decisions for a human: isolate the computer, delete the phishing email,",
            "and block an IP that threat intel only rated SUSPICIOUS.")
        self.pause()

    def step3_dashboard(self) -> None:
        title(3, "The analyst's view in the mini-SIEM dashboard", "3-4 min")
        self.start_dashboard()
        from mini_siem.store import Store

        alerts = {a["rule_id"]: a["id"] for a in Store(SIEM_DB).alerts()}
        self.open("/alerts")
        say("Confirmed alerts are 'In progress' (the SOAR acted); uncertain ones stay 'New' for an analyst.",
            "'was high' means threat-intel enrichment raised the severity.")
        self.pause("Press Enter to open the C2 beaconing alert")
        self.open(f"/alerts/{alerts.get('MS-006', 1)}")
        say("The rule needs 6+ connections to one IP in 15 minutes AT REGULAR INTERVALS: malware calls home on a timer.",
            "Here: the 8 firewall logs, what each threat-intel source says, the ATT&CK techniques, the SOAR's note.")
        self.pause("Press Enter to open the host timeline")
        self.open("/hosts/FIN-WS-07")
        say("The whole attack from top to bottom: email, download, script, loader, beaconing, second stage.",
            "Another workstation produces look-alike benign traffic (Teams, a CDN script, a logon script):",
            "none of it raises an alert, and the tests check that.")
        self.pause("Press Enter to open the rules page")
        self.open("/rules")
        say("8 rules in a Sigma-like YAML format, each mapped to MITRE ATT&CK with its known false positives.")
        self.pause()

    def step4_human_in_the_loop(self) -> None:
        title(4, "Human in the loop: approve and reject the SOAR's requests", "1-2 min")
        from mini_soar.audit import Audit

        self.run("mini-soar pending", ["mini_soar", "pending"], SOAR)
        pending = {p["action"]: p for p in Audit(SOAR_DB).pending()}
        isolate, block = pending.get("isolate_host"), pending.get("block_ioc")
        self.pause("Press Enter to approve the host isolation")
        if isolate:
            self.run(f"mini-soar approve {isolate['id']} --by {self.args.name}",
                     ["mini_soar", "approve", str(isolate["id"]), "--by", self.args.name], SOAR)
        if block:
            self.run(f'mini-soar reject {block["id"]} --by {self.args.name} --reason "shared hosting, monitor instead"',
                     ["mini_soar", "reject", str(block["id"]), "--by", self.args.name,
                      "--reason", "shared hosting, monitor instead"], SOAR)
        self.run("mini-soar history --status approved", ["mini_soar", "history", "--status", "approved"], SOAR)
        if isolate:
            self.open(f"/alerts/{isolate['alert_id']}")
        print(color(f"  Incident case: mini-soar{SEP}soar-output{SEP}cases{SEP}CASE-0001.md", "36"))
        say("Isolating a computer stops someone working, so a human decides (simulated here: no real EDR).",
            "The IP was only SUSPICIOUS: shared hosting can also serve legitimate sites, so I rejected the block.",
            "Everything is in an audit trail: what, on which target, by whom, when. The approval is in the SIEM note.",
            "One case groups the 8 alerts of the incident instead of 8 separate tickets.")
        self.pause()

    def step5_tests(self) -> None:
        title(5, "How it is tested", "30 s")
        if self.args.skip_tests:
            print("  (skipped)")
            return
        self.run("pytest -q", ["pytest", "-q", "-p", "no:cacheprovider"], SIEM)
        say("115 tests in the SIEM, 271 across the three projects, all offline.",
            "The main test checks each of the 43 log events against the rules it should trigger,",
            "including the ones that must stay silent. GitHub Actions runs them on every push.")

    # --- dashboard --------------------------------------------------------------------------------

    def start_dashboard(self) -> None:
        for candidate in range(self.args.port, self.args.port + 10):
            with socket.socket() as s:
                if s.connect_ex(("127.0.0.1", candidate)) != 0:
                    self.port = candidate
                    break
        else:
            raise SystemExit(f"Ports {self.args.port}-{self.args.port + 9} are all busy.")
        if self.port != self.args.port:
            print(color(f"  Port {self.args.port} is busy, using {self.port} instead.", "33"))
        self.dashboard_log = open(SOAR / "soar-output" / "dashboard.log", "w", encoding="utf-8")
        command(f"mini-siem --db mini-soar{SEP}soar-output{SEP}mini_siem.db serve --port {self.port}   (in the background)")
        self.dashboard = subprocess.Popen(
            [sys.executable, "-m", "mini_siem", "--db", str(SIEM_DB), "serve", "--port", str(self.port)],
            cwd=ROOT, stdout=self.dashboard_log, stderr=subprocess.STDOUT)
        url = f"http://127.0.0.1:{self.port}/alerts"
        for _ in range(60):
            if self.dashboard.poll() is not None:
                raise SystemExit(f"The dashboard stopped: see mini-soar{SEP}soar-output{SEP}dashboard.log")
            try:
                with urllib.request.urlopen(url, timeout=1) as resp:
                    if resp.status == 200:
                        print(color(f"  Dashboard running on http://127.0.0.1:{self.port}", "32"))
                        return
            except (urllib.error.URLError, OSError):
                time.sleep(0.5)
        raise SystemExit("The dashboard did not start in 30 seconds.")

    def stop_dashboard(self) -> None:
        if self.dashboard and self.dashboard.poll() is None:
            self.dashboard.terminate()
            try:
                self.dashboard.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.dashboard.kill()
            print(color("  Dashboard stopped.", "2"))
        if self.dashboard_log:
            self.dashboard_log.close()

    # --- main -------------------------------------------------------------------------------------

    def main(self) -> int:
        print(color("\n  PAPER LANTERN: one incident through the whole pipeline", "1"))
        print("  A finance employee opens a fake invoice email, runs a script disguised as a PDF,")
        print("  and a malware loader starts calling its command-and-control server.")
        print(color("  Pitch: logs -> detection -> threat-intel enrichment -> automated response -> analyst decision", "2"))
        self.pause("Press Enter to start")
        try:
            self.step1_enrichment()
            self.step2_detect_and_respond()
            self.step3_dashboard()
            self.step4_human_in_the_loop()
            self.step5_tests()
            print("\n" + color("  Demo complete.", "1;32"))
            if self.dashboard and not self.args.no_pause:
                self.pause("Press Enter to stop the dashboard and finish")
        except KeyboardInterrupt:
            print("\n  Demo stopped.")
        finally:
            self.stop_dashboard()
        return 0


def check_installed() -> bool:
    missing = []
    for module in ("ioc_enricher", "mini_siem", "mini_soar", "pytest"):
        try:
            __import__(module)
        except ImportError:
            missing.append(module)
    if missing:
        print(f"Missing: {', '.join(missing)}.")
        print("On Windows, run .\\demo.ps1 (it installs everything). Otherwise, from this folder:")
        print('  pip install -e ./ioc-enricher -e ./mini-siem -e "./mini-soar[dev]"')
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Automated interview demo of the Becode-2026 projects.")
    p.add_argument("--name", default="analyst", help="analyst name recorded in approvals (default: analyst)")
    p.add_argument("--port", type=int, default=5000, help="dashboard port (default: 5000, next free one if busy)")
    p.add_argument("--no-pause", action="store_true", help="don't wait between steps")
    p.add_argument("--no-browser", action="store_true", help="don't open the browser")
    p.add_argument("--skip-tests", action="store_true", help="skip step 5 (pytest)")
    args = p.parse_args(argv)
    if not check_installed():
        return 1
    return Demo(args).main()


if __name__ == "__main__":
    raise SystemExit(main())
