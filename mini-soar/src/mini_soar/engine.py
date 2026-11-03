"""Run playbooks over SIEM alerts, and handle analyst approvals."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .actions import ACTIONS, Allowlist, Context, case_host, refresh_case_footer, webhook_from_env
from .audit import Audit, now
from .playbooks import Playbook, load_playbooks, select_playbook
from .sources import AlertSource, SourceError, open_source


@dataclass
class RunSummary:
    handled: list[tuple[int, str, str]] = field(default_factory=list)   # (alert id, rule, playbook)
    skipped: list[tuple[int, str, str]] = field(default_factory=list)   # (alert id, rule, reason)
    actions: Counter = field(default_factory=Counter)                   # status -> count

    def lines(self) -> list[str]:
        out = [f"  #{i:<3} {rule:<7} -> {pb}" for i, rule, pb in self.handled]
        out += [f"  #{i:<3} {rule:<7}    skipped: {why}" for i, rule, why in self.skipped]
        return out


def _snapshot(alert: dict[str, Any]) -> dict[str, Any]:
    """What an approval needs later, even if the SIEM is not reachable then."""
    keep = ("id", "key", "rule_id", "title", "severity", "host", "ti_verdict", "first_seen", "mitre", "iocs")
    snap = {k: alert.get(k) for k in keep}
    snap["events"] = [e for e in alert["events"] if e.get("source") == "email"]
    return snap


class Soar:
    def __init__(self, audit: Audit, out_dir: str | Path, playbooks: list[Playbook] | None = None,
                 allowlist: Allowlist | None = None, webhook_url: str | None = None, session: Any = None) -> None:
        self.audit = audit
        self.out_dir = Path(out_dir)
        self.playbooks = playbooks if playbooks is not None else load_playbooks(known_actions=set(ACTIONS))
        self.allowlist = allowlist or Allowlist.load()
        self.webhook_url = webhook_url if webhook_url is not None else webhook_from_env()
        self.session = session

    def _context(self, alert: dict, playbook: str, source: AlertSource | None, dry_run: bool = False) -> Context:
        return Context(alert=alert, playbook=playbook, audit=self.audit, out_dir=self.out_dir, source=source,
                       allowlist=self.allowlist, dry_run=dry_run, webhook_url=self.webhook_url, session=self.session)

    # --- automatic run -------------------------------------------------------------------------------------

    def run(self, source: AlertSource, dry_run: bool = False) -> RunSummary:
        summary = RunSummary()
        for alert in source.alerts():
            if alert["status"].startswith("closed"):
                summary.skipped.append((alert["id"], alert["rule_id"], "already closed by an analyst"))
                continue
            if alert.get("ti_verdict") is None:
                summary.skipped.append((alert["id"], alert["rule_id"], "not enriched yet (run: mini-siem enrich)"))
                continue
            book = select_playbook(self.playbooks, alert)
            if book is None:
                summary.skipped.append((alert["id"], alert["rule_id"], "no playbook matches"))
                continue
            if self.audit.was_processed(alert["key"], book.id):
                summary.skipped.append((alert["id"], alert["rule_id"], f"already handled by {book.id}"))
                continue
            label = f"{book.id} {book.name}"
            ctx = self._context(alert, label, source, dry_run)
            for step in book.steps:
                self._run_step(ctx, step, source, summary)
            if not dry_run:
                self.audit.mark_processed(alert["key"], book.id)
            summary.handled.append((alert["id"], alert["rule_id"], label))
        return summary

    def _run_step(self, ctx: Context, step, source: AlertSource, summary: RunSummary) -> None:
        action = ACTIONS[step.action]
        targets = action.targets(ctx, step.params)
        if not targets:
            self._log(ctx, summary, action.name, None, "skipped", "nothing to act on")
            return
        for target in targets:
            reason = action.precheck(ctx, target, step.params)
            if reason:
                self._log(ctx, summary, action.name, target, "skipped", reason)
            elif ctx.dry_run:
                self._log(ctx, summary, action.name, target, "dry-run",
                          "would ask for approval" if step.approval else "would run")
            elif step.approval:
                if self.audit.has_pending(action.name, target):
                    self._log(ctx, summary, action.name, target, "skipped", "approval already requested")
                else:
                    self._log(ctx, summary, action.name, target, "pending", "waiting for an analyst",
                              params={**step.params, "alert": _snapshot(ctx.alert)}, source=source.spec)
            else:
                try:
                    status, detail = action.execute(ctx, target, step.params)
                except (OSError, SourceError, ValueError) as exc:
                    status, detail = "failed", f"{exc.__class__.__name__}: {exc}"
                self._log(ctx, summary, action.name, target, status, detail)

    def _log(self, ctx: Context, summary: RunSummary, action: str, target: str | None, status: str, detail: str,
             params: dict | None = None, source: str | None = None) -> None:
        action_id = self.audit.record(action, status, alert=ctx.alert, playbook=ctx.playbook, target=target,
                                      detail=detail, params=params, source=source)
        ctx.results.append({"id": action_id, "action": action, "target": target or "-", "status": status, "detail": detail})
        summary.actions[status] += 1

    # --- human in the loop ------------------------------------------------------------------------------------

    def _pending(self, action_id: int) -> dict:
        row = self.audit.get(action_id)
        if row is None:
            raise ValueError(f"no action #{action_id}")
        if row["status"] != "pending":
            raise ValueError(f"action #{action_id} is not waiting for approval (status: {row['status']})")
        return row

    def _note(self, row: dict, text: str) -> str:
        if not row.get("source"):
            return ""
        try:
            open_source(row["source"]).add_note(row["alert_id"], f"[mini-soar {now()}] {text}")
        except (SourceError, OSError) as exc:
            return f" (SIEM not updated: {exc})"
        return ""

    def approve(self, action_id: int, analyst: str) -> tuple[str, str]:
        row = self._pending(action_id)
        params = dict(row["params"])
        alert = params.pop("alert")
        ctx = self._context(alert, row["playbook"], None)
        action = ACTIONS[row["action"]]
        reason = action.precheck(ctx, row["target"], params)
        if reason:
            status, detail = "approved", f"approved by {analyst}, nothing to do: {reason}"
        else:
            result, detail = action.execute(ctx, row["target"], params, approved_by=analyst)
            status = "approved" if result == "done" else result
            detail = f"approved by {analyst}: {detail}"
        detail += self._note(row, f"{row['action']} {row['target']} {detail}")
        self.audit.set_status(action_id, status, detail, analyst)
        refresh_case_footer(self.audit, self.out_dir, case_host(alert))
        return status, detail

    def reject(self, action_id: int, analyst: str, reason: str = "") -> str:
        row = self._pending(action_id)
        detail = f"rejected by {analyst}{': ' + reason if reason else ''}"
        detail += self._note(row, f"{row['action']} {row['target']} {detail}")
        self.audit.set_status(action_id, "rejected", detail, analyst)
        refresh_case_footer(self.audit, self.out_dir, case_host(row["params"]["alert"]))
        return detail
