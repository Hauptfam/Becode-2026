"""Command line: mini-soar run | watch | pending | approve | reject | history | playbooks | demo."""

from __future__ import annotations

import argparse
import contextlib
import io
import shutil
import sys
import time
from pathlib import Path

from . import __version__
from .actions import ACTIONS, Allowlist
from .audit import Audit
from .engine import Soar
from .playbooks import BUILTIN_PLAYBOOKS, PlaybookError, load_playbooks
from .sources import SourceError, open_source

EPILOG = """\
typical workflow:
  mini-soar demo                                      # self-contained demo on the Paper Lantern incident
  mini-soar run --siem http://127.0.0.1:5000          # act on alerts from a running mini-SIEM dashboard
  mini-soar run --siem ../mini-siem/mini_siem.db      # ...or straight from its database
  mini-soar pending                                   # actions waiting for an analyst
  mini-soar approve 2 --by mateo                      # run one of them
  mini-soar history                                   # audit trail of everything the SOAR did

Notifications go to notifications.log, or to Discord/Slack if SOAR_WEBHOOK_URL is set.
"""


def _soar(args) -> Soar:
    playbooks = load_playbooks(args.playbooks or BUILTIN_PLAYBOOKS, known_actions=set(ACTIONS))
    allowlist = Allowlist.load(args.allowlist) if args.allowlist else Allowlist.load()
    return Soar(Audit(args.db), args.out, playbooks=playbooks, allowlist=allowlist)


def _source_spec(value: str) -> str:
    if value.startswith(("http://", "https://", "api:", "db:")):
        return value
    return f"db:{Path(value).resolve()}"


def _print_run(summary, dry_run: bool) -> None:
    print("\n".join(summary.lines()) or "  no alerts")
    counts = ", ".join(f"{n} {s}" for s, n in sorted(summary.actions.items())) or "no actions"
    print(f"\n{'DRY RUN (nothing executed): ' if dry_run else ''}{len(summary.handled)} alert(s) handled: {counts}")


def cmd_run(args) -> int:
    soar = _soar(args)
    summary = soar.run(open_source(_source_spec(args.siem)), dry_run=args.dry_run)
    _print_run(summary, args.dry_run)
    if summary.actions.get("pending"):
        print("Analyst approval needed: mini-soar pending")
    return 0


def cmd_watch(args) -> int:
    soar = _soar(args)
    source = open_source(_source_spec(args.siem))
    print(f"watching {source.spec} every {args.interval}s (Ctrl+C to stop)")
    try:
        while True:
            summary = soar.run(source)
            if summary.handled:
                print(time.strftime("%H:%M:%S"))
                _print_run(summary, False)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("stopped")
    return 0


def cmd_pending(args) -> int:
    rows = _soar(args).audit.pending()
    if not rows:
        print("nothing is waiting for approval")
    for r in rows:
        alert = r["params"].get("alert", {})
        print(f"#{r['id']:<4} {r['action']:<13} {r['target']}\n      alert #{r['alert_id']} {alert.get('rule_id')} "
              f"{alert.get('title')} ({alert.get('severity')}, {alert.get('host')})")
    if rows:
        print("\nmini-soar approve ID --by NAME   |   mini-soar reject ID --by NAME --reason TEXT")
    return 0


def cmd_approve(args) -> int:
    try:
        status, detail = _soar(args).approve(args.id, args.by)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"#{args.id} {status}: {detail}")
    return 0


def cmd_reject(args) -> int:
    try:
        detail = _soar(args).reject(args.id, args.by, args.reason or "")
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"#{args.id} {detail}")
    return 0


def cmd_history(args) -> int:
    rows = list(reversed(_soar(args).audit.history(args.limit, args.status)))
    for r in rows:
        target = (r["target"] or "-")[:44]
        print(f"#{r['id']:<4} {r['ts']}  {r['action']:<13} {target:<45} {r['status']:<9} {r['actor']:<10} "
              f"{r['detail'][:80]}")
    if not rows:
        print("no actions recorded yet")
    return 0


def cmd_playbooks(args) -> int:
    for b in _soar(args).playbooks:
        trigger = ", ".join(f"{k}={'/'.join(v)}" for k, v in b.trigger.items())
        print(f"{b.id}  {b.name}  (priority {b.priority})\n      when: {trigger}")
        for s in b.steps:
            print(f"      - {s.action}{'  [needs approval]' if s.approval else ''}")
    return 0


def cmd_demo(args) -> int:
    try:
        from mini_siem import cli as siem_cli
    except ImportError:
        print("error: the demo needs mini-siem and ioc-enricher (pip install -e ../ioc-enricher -e ../mini-siem)",
              file=sys.stderr)
        return 1
    out = Path(args.out)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    Path(args.db).unlink(missing_ok=True)
    siem_db = out / "mini_siem.db"

    print("[1/3] mini-SIEM: ingest, detect and enrich the Paper Lantern logs")
    with contextlib.redirect_stdout(io.StringIO()):
        code = siem_cli.main(["--db", str(siem_db), "demo", "--no-serve"])
    if code:
        print("error: the mini-SIEM demo failed", file=sys.stderr)
        return code
    print("[2/3] mini-SOAR: run the playbooks")
    soar = _soar(args)
    summary = soar.run(open_source(f"db:{siem_db.resolve()}"))
    _print_run(summary, False)
    print("\n[3/3] waiting for an analyst:")
    cmd_pending(args)
    print(f"\nOutputs in {out}/: blocklists/, cases/, notifications.log")
    print(f"See the SOAR notes in the dashboard:  mini-siem --db {siem_db} serve")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mini-soar", description="Automated response playbooks for mini-SIEM alerts.",
                                epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--db", default="mini_soar.db", help="SOAR state and audit trail (default: mini_soar.db)")
    p.add_argument("--out", default="soar-output", help="folder for blocklists, cases and logs (default: soar-output)")
    p.add_argument("--playbooks", type=Path, help="folder of playbook YAML files (default: built-in)")
    p.add_argument("--allowlist", type=Path, help="allowlist YAML (default: built-in)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    for name, func, helptext in (("run", cmd_run, "run the playbooks once"),
                                 ("watch", cmd_watch, "run the playbooks every N seconds")):
        s = sub.add_parser(name, help=helptext)
        s.add_argument("--siem", default="../mini-siem/mini_siem.db",
                       help="mini-SIEM database path or dashboard URL (default: ../mini-siem/mini_siem.db)")
        if name == "run":
            s.add_argument("--dry-run", action="store_true", help="show what would happen, change nothing")
        else:
            s.add_argument("--interval", type=int, default=30)
        s.set_defaults(func=func)

    sub.add_parser("pending", help="list actions waiting for approval").set_defaults(func=cmd_pending)
    s = sub.add_parser("approve", help="approve and run a pending action")
    s.add_argument("id", type=int)
    s.add_argument("--by", required=True, help="analyst name, recorded in the audit trail")
    s.set_defaults(func=cmd_approve)
    s = sub.add_parser("reject", help="reject a pending action")
    s.add_argument("id", type=int)
    s.add_argument("--by", required=True)
    s.add_argument("--reason")
    s.set_defaults(func=cmd_reject)
    s = sub.add_parser("history", help="show the audit trail")
    s.add_argument("--limit", type=int, default=100)
    s.add_argument("--status", help="only this status (done, skipped, pending, approved, rejected, failed)")
    s.set_defaults(func=cmd_history)
    sub.add_parser("playbooks", help="list the playbooks").set_defaults(func=cmd_playbooks)
    sub.add_parser("demo", help="run the Paper Lantern scenario end to end").set_defaults(func=cmd_demo)
    return p


def main(argv: list[str] | None = None) -> int:
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (PlaybookError, SourceError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
