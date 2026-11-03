"""Response actions. Each action lists its targets, can refuse a target before anything happens (precheck),
and executes on one target at a time. Actions that would touch real infrastructure (isolating a host,
purging an email) are simulated: they write what they would do to a JSON Lines file.
"""

from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from .audit import Audit, now
from .sources import AlertSource

BUILTIN_ALLOWLIST = Path(__file__).parent / "allowlist.yml"
BLOCKLIST_FILES = {"ipv4": "ips", "ipv6": "ips", "domain": "domains", "url": "urls",
                   "md5": "hashes", "sha1": "hashes", "sha256": "hashes"}


# --- Context shared by the steps of one playbook run ---------------------------------------------------

@dataclass
class Allowlist:
    domains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    cidrs: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: str | Path = BUILTIN_ALLOWLIST) -> Allowlist:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        return cls([d.lower() for d in data.get("domains", [])], data.get("ips", []), data.get("cidrs", []))

    def reason(self, value: str, ioc_type: str) -> str | None:
        """Why this indicator must never be blocked, or None."""
        host = value
        if ioc_type == "url":
            host = (urlparse(value).hostname or "").lower()
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None
        if ip is not None:
            if not ip.is_global:
                return "internal/private address"
            if str(ip) in self.ips or any(ip in ipaddress.ip_network(c, strict=False) for c in self.cidrs):
                return "on the allowlist"
            return None
        if ioc_type in ("domain", "url") and any(host == d or host.endswith("." + d) for d in self.domains):
            return "on the allowlist"
        return None


@dataclass
class Context:
    alert: dict[str, Any]
    playbook: str
    audit: Audit
    out_dir: Path
    source: AlertSource | None
    allowlist: Allowlist
    dry_run: bool = False
    webhook_url: str | None = None
    session: Any = None
    results: list[dict[str, str]] = field(default_factory=list)
    ticket: str | None = None

    def write_line(self, filename: str, record: dict) -> Path:
        path = self.out_dir / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
        return path


# --- Actions ---------------------------------------------------------------------------------------------

class Action:
    name = "action"
    description = ""

    def targets(self, ctx: Context, params: dict) -> list[str]:
        return [str(ctx.alert["id"])]

    def precheck(self, ctx: Context, target: str, params: dict) -> str | None:
        """Return a reason to skip this target, or None."""
        return None

    def execute(self, ctx: Context, target: str, params: dict, approved_by: str | None = None) -> tuple[str, str]:
        raise NotImplementedError


class BlockIoc(Action):
    name = "block_ioc"
    description = "Add indicators to blocklist files (one per type) that a firewall, proxy or EDR can import."

    def targets(self, ctx, params):
        verdicts = set(params.get("verdicts", ["MALICIOUS"]))
        return [i["value"] for i in ctx.alert["iocs"] if i["verdict"] in verdicts]

    def _ioc(self, ctx, target):
        return next((i for i in ctx.alert["iocs"] if i["value"] == target),
                    {"value": target, "type": "unknown", "verdict": "UNKNOWN"})

    def _file(self, ctx, ioc) -> Path | None:
        kind = BLOCKLIST_FILES.get(ioc["type"])
        return ctx.out_dir / "blocklists" / f"{kind}.txt" if kind else None

    def precheck(self, ctx, target, params):
        ioc = self._ioc(ctx, target)
        reason = ctx.allowlist.reason(target, ioc["type"])
        if reason:
            return f"never blocked: {reason}"
        path = self._file(ctx, ioc)
        if path is None:
            return f"no blocklist for type {ioc['type']}"
        if path.exists() and any(line.split("#")[0].strip() == target for line in path.read_text().splitlines()):
            return "already blocked"
        return None

    def execute(self, ctx, target, params, approved_by=None):
        ioc = self._ioc(ctx, target)
        path = self._file(ctx, ioc)
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text(f"# mini-soar {path.stem} blocklist: one indicator per line, comments after '#'\n")
        by = f", approved by {approved_by}" if approved_by else ""
        with path.open("a", encoding="utf-8") as f:
            f.write(f"{target}  # {ioc['verdict']}, {ctx.alert['rule_id']} alert #{ctx.alert['id']}, {now()}{by}\n")
        return "done", f"added to blocklists/{path.name} ({ioc['verdict']})"


class IsolateHost(Action):
    name = "isolate_host"
    description = "SIMULATED: ask the EDR to cut the host off the network."

    def targets(self, ctx, params):
        return [ctx.alert["host"]] if ctx.alert.get("host") else []

    def precheck(self, ctx, target, params):
        path = ctx.out_dir / "edr_actions.jsonl"
        if path.exists() and any(json.loads(line).get("host") == target for line in path.read_text().splitlines()):
            return "host already isolated"
        return None

    def execute(self, ctx, target, params, approved_by=None):
        ctx.write_line("edr_actions.jsonl", {"ts": now(), "simulated": True, "action": "isolate", "host": target,
                                             "alert_id": ctx.alert["id"], "rule": ctx.alert["rule_id"],
                                             "approved_by": approved_by})
        return "done", "SIMULATED: isolation request written to edr_actions.jsonl (no real EDR connected)"


class PurgeEmail(Action):
    name = "purge_email"
    description = "SIMULATED: delete the phishing email from every mailbox."

    def targets(self, ctx, params):
        ids = []
        for event in ctx.alert["events"]:
            raw = event.get("raw") or {}
            if event.get("source") == "email" and raw.get("message_id") and raw["message_id"] not in ids:
                ids.append(raw["message_id"])
        return ids

    def execute(self, ctx, target, params, approved_by=None):
        sender = next((e.get("sender") for e in ctx.alert["events"] if e.get("source") == "email"), None)
        ctx.write_line("mail_actions.jsonl", {"ts": now(), "simulated": True, "action": "purge", "message_id": target,
                                              "sender": sender, "alert_id": ctx.alert["id"], "approved_by": approved_by})
        return "done", "SIMULATED: purge request written to mail_actions.jsonl (no real mail server connected)"


FOOTER = "<!-- mini-soar: open approvals (rewritten on every update) -->"


def case_host(alert: dict) -> str:
    return alert.get("host") or f"alert-{alert['id']}"


def refresh_case_footer(audit: Audit, out_dir: Path, host: str) -> None:
    """Rewrite the 'open approvals' part of a host's case so it always shows the current state."""
    case_id = audit.case_for(host)
    if not case_id:
        return
    path = out_dir / "cases" / f"{case_id}.md"
    if not path.exists():
        return
    body = path.read_text(encoding="utf-8").split(FOOTER)[0].rstrip() + "\n"
    pending = audit.pending_for_host(host)
    lines = [FOOTER, "", "## Waiting for an analyst", ""]
    lines += [f"- [ ] **{p['action']} {p['target']}** (alert #{p['alert_id']}): "
              f"`mini-soar approve {p['id']}` or `mini-soar reject {p['id']}`" for p in pending] or ["- nothing"]
    lines += ["", "## Next steps", "",
              "- [ ] Confirm the scope: other hosts or users affected? (mini-SIEM event search)",
              "- [ ] Decide on every pending approval above",
              "- [ ] Close each alert in the mini-SIEM as true or false positive, then close this case", ""]
    path.write_text(body + "\n" + "\n".join(lines), encoding="utf-8")


class CreateTicket(Action):
    name = "create_ticket"
    description = ("Open one incident case per host (Markdown) and add each alert to it, with its IOCs, events, "
                   "automated actions and open approvals.")

    def targets(self, ctx, params):
        if ctx.dry_run:
            return [ctx.audit.case_for(case_host(ctx.alert)) or "CASE-(new)"]
        return [ctx.audit.open_case(case_host(ctx.alert))]

    def execute(self, ctx, target, params, approved_by=None):
        a = ctx.alert
        path = ctx.out_dir / "cases" / f"{target}.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        new_case = not path.exists()
        if new_case:
            header = [f"# {target}: incident on {case_host(a)}", "",
                      f"Opened {now()} by mini-soar. Every alert about this host is added below.", ""]
            path.write_text("\n".join(header) + "\n", encoding="utf-8")
        mitre = ", ".join(m["id"] + " " + m.get("name", "") for m in a["mitre"]) or "-"
        lines = [f"## Alert #{a['id']}: {a['title']}", "",
                 f"- **Rule:** {a['rule_id']}, severity **{a['severity']}**, threat intel **{a.get('ti_verdict')}**",
                 f"- **First seen:** {a.get('first_seen')}",
                 f"- **Playbook:** {ctx.playbook}",
                 f"- **MITRE ATT&CK:** {mitre}", "",
                 "| Indicator (defanged) | Type | Verdict |", "|---|---|---|"]
        lines += [f"| `{i['defanged']}` | {i['type']} | {i['verdict']} |" for i in a["iocs"]] or ["| none | | |"]
        lines += ["", "Events:", ""]
        lines += [f"- `{e.get('timestamp', '')}` {e.get('source', '')}: {e.get('message', '')}" for e in a["events"][:20]]
        lines += ["", "Automated response:", ""]
        lines += [f"- **{r['action']}** {r['target']}: {r['status']} ({r['detail']})" for r in ctx.results] or ["- none"]
        body = path.read_text(encoding="utf-8").split(FOOTER)[0].rstrip() + "\n\n"
        path.write_text(body + "\n".join(lines) + "\n", encoding="utf-8")
        ctx.ticket = target
        refresh_case_footer(ctx.audit, ctx.out_dir, case_host(a))
        return "done", f"{'case opened' if new_case else 'alert added to case'}: cases/{path.name}"


class Notify(Action):
    name = "notify"
    description = "Send a chat message (Discord or Slack webhook in SOAR_WEBHOOK_URL), or write it to notifications.log."

    def targets(self, ctx, params):
        return ["webhook" if ctx.webhook_url else "notifications.log"]

    def message(self, ctx, params) -> str:
        a = ctx.alert
        icon = {"critical": "\U0001F534", "high": "\U0001F7E0", "medium": "\U0001F7E1"}.get(a["severity"], "⚪")
        parts = [f"{icon} [{a['severity'].upper()}] {a['rule_id']} {a['title']} on {a.get('host') or '?'}",
                 f"Threat intel: {a.get('ti_verdict')}"]
        bad = [i["defanged"] for i in a["iocs"] if i["verdict"] in ("MALICIOUS", "SUSPICIOUS")]
        if bad:
            parts.append("IOCs: " + ", ".join(bad))
        done = [r for r in ctx.results if r["action"] == "block_ioc" and r["status"] == "done"]
        if done:
            parts.append(f"Blocked: {len(done)}")
        pending = [f"{r['action']} {r['target']} (#{r['id']})" for r in ctx.results if r["status"] == "pending"]
        if pending:
            parts.append("Waiting for approval: " + ", ".join(pending))
        if ctx.ticket:
            parts.append(f"Ticket: {ctx.ticket}")
        return " | ".join(parts)

    def execute(self, ctx, target, params, approved_by=None):
        text = self.message(ctx, params)
        if target != "webhook":
            path = ctx.out_dir / "notifications.log"
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as f:
                f.write(f"{now()}  {text}\n")
            return "done", "written to notifications.log (set SOAR_WEBHOOK_URL to send it to Discord or Slack)"
        import requests

        host = urlparse(ctx.webhook_url).hostname or ""
        payload = {"content": text} if "discord" in host else {"text": text}
        session = ctx.session or requests.Session()
        try:
            resp = session.post(ctx.webhook_url, json=payload, timeout=10)
        except requests.RequestException as exc:
            return "failed", f"webhook unreachable ({exc.__class__.__name__})"
        if resp.status_code >= 400:
            return "failed", f"webhook answered HTTP {resp.status_code}"
        return "done", f"sent to {'Discord' if 'discord' in host else 'Slack'} webhook"


class UpdateAlert(Action):
    name = "update_alert"
    description = "Write a summary of the automated response into the alert's notes in the mini-SIEM."

    def execute(self, ctx, target, params, approved_by=None):
        if ctx.source is None:
            return "skipped", "no SIEM connection"
        done = [r["target"] for r in ctx.results if r["action"] == "block_ioc" and r["status"] == "done"]
        pending = [f"{r['action']} {r['target']} (#{r['id']})" for r in ctx.results if r["status"] == "pending"]
        parts = [f"blocked {len(done)} IOC(s){' (' + ', '.join(done) + ')' if done else ''}"]
        if ctx.ticket:
            parts.append(f"ticket {ctx.ticket}")
        if pending:
            parts.append("waiting for analyst approval: " + ", ".join(pending))
        if params.get("note"):
            parts.append(params["note"])
        status = params.get("status") if ctx.alert.get("status") == "new" else None
        note = f"[mini-soar {now()}] {ctx.playbook}: " + "; ".join(parts) + "."
        ctx.source.add_note(ctx.alert["id"], note, status=status)
        return "done", f"note added{', status set to ' + status if status else ''}"


ACTIONS: dict[str, Action] = {a.name: a for a in (BlockIoc(), IsolateHost(), PurgeEmail(), CreateTicket(), Notify(),
                                                  UpdateAlert())}


def webhook_from_env() -> str | None:
    return os.environ.get("SOAR_WEBHOOK_URL") or None
