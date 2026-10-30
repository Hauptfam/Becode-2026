"""Command-line interface: mini-siem ingest | detect | enrich | alerts | serve | demo | reset."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .engine import detect, enrich_alerts, enrichment_available, ingest, read_input
from .parsers import PARSERS, ParseError
from .rules import BUILTIN_RULES, RuleError, load_rules
from .store import Store

PACKAGE_ROOT = Path(__file__).resolve().parents[2]          # .../mini-siem
DEMO_LOGS = PACKAGE_ROOT / "data" / "paper_lantern_logs.json"

EPILOG = """\
typical workflow:
  mini-siem demo                                   # load the Paper Lantern scenario and open the dashboard
  mini-siem ingest data/paper_lantern_logs.json    # or your own logs: --source proxy my_proxy.jsonl
  mini-siem detect
  mini-siem enrich                                 # uses VT_API_KEY / ABUSEIPDB_API_KEY / URLHAUS_API_KEY
  mini-siem serve                                  # http://127.0.0.1:5000
"""


def _store(args) -> Store:
    return Store(args.db)


def _rules(args):
    return load_rules(args.rules or BUILTIN_RULES)


def _intel_dataset_for(logs_path: Path) -> Path | None:
    """A scenario dataset can point to the threat-intel dataset that goes with it."""
    try:
        data = json.loads(logs_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    ref = data.get("threat_intel_dataset") if isinstance(data, dict) else None
    if not ref:
        return None
    path = (logs_path.parent / ref).resolve()
    return path if path.exists() else None


def cmd_ingest(args) -> int:
    store = _store(args)
    total = 0
    for path in args.files:
        try:
            records, assets = read_input(path, args.source)
        except (OSError, ParseError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        result = ingest(store, records, assets)
        total += result.ingested
        sources = ", ".join(f"{n} {s}" for s, n in sorted(result.by_source.items()))
        print(f"{path}: {result.ingested} events ({sources})")
        for err in result.errors:
            print(f"  skipped {err}", file=sys.stderr)
    print(f"total: {total} events in {args.db}")
    return 0


def cmd_detect(args) -> int:
    alerts = detect(_store(args), _rules(args))
    print(f"{len(alerts)} alert(s)")
    for a in alerts:
        print(f"  [{a['severity'].upper():<8}] {a['rule_id']} {a['title']} ({a['host']}, {len(a['event_ids'])} events)")
    return 0


def cmd_enrich(args) -> int:
    if not enrichment_available():
        print("error: ioc-enricher is not installed (pip install -e ../ioc-enricher)", file=sys.stderr)
        return 1
    summary = enrich_alerts(_store(args), offline_dataset=args.offline_dataset, refresh=args.refresh)
    print(f"{summary['mode']} enrichment: {summary['iocs']} IOC(s) in {summary['alerts']} alert(s), "
          f"{summary['looked_up']} looked up, {summary['escalated']} alert(s) escalated")
    return 0


def cmd_alerts(args) -> int:
    alerts = _store(args).alerts(status=args.status)
    if args.json:
        print(json.dumps(alerts, indent=2))
        return 0
    for a in alerts:
        ti = a["ti_verdict"] or "-"
        print(f"#{a['id']:<3} [{a['severity'].upper():<8}] {a['rule_id']} {a['title']} "
              f"| {a['host']} | TI: {ti} | {a['status']}")
    if not alerts:
        print("no alerts")
    return 0


def cmd_serve(args) -> int:
    from .web import create_app

    app = create_app(args.db, _rules(args))
    print(f"mini-SIEM dashboard: http://{args.host}:{args.port}  (Ctrl+C to stop)")
    app.run(host=args.host, port=args.port, debug=False)
    return 0


def cmd_demo(args) -> int:
    logs = Path(args.logs)
    if not logs.exists():
        print(f"error: scenario not found: {logs}\n"
              "Install from the repository with 'pip install -e .', or pass --logs PATH", file=sys.stderr)
        return 1
    store = _store(args)
    store.reset()
    print(f"[1/4] ingest   {logs.name}")
    records, assets = read_input(logs)
    result = ingest(store, records, assets)
    print(f"      {result.ingested} events from {len(result.by_source)} sources")
    print("[2/4] detect")
    alerts = detect(store, _rules(args))
    print(f"      {len(alerts)} alerts")
    intel = Path(args.offline_dataset) if args.offline_dataset else _intel_dataset_for(logs)
    if enrichment_available() and intel:
        summary = enrich_alerts(store, offline_dataset=intel)
        print(f"[3/4] enrich   offline threat intel from {intel.name}: {summary['iocs']} IOCs, "
              f"{summary['escalated']} alerts escalated")
    else:
        print("[3/4] enrich   skipped (ioc-enricher or the threat-intel dataset not found)")
    store.close()
    if args.no_serve:
        print("[4/4] done     run 'mini-siem serve' to open the dashboard")
        return 0
    print("[4/4] serve")
    return cmd_serve(args)


def cmd_reset(args) -> int:
    _store(args).reset()
    print(f"cleared all events, alerts and IOCs in {args.db}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mini-siem", description="A small SIEM for learning SOC work.",
                                epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--db", default="mini_siem.db", help="SQLite database file (default: mini_siem.db)")
    p.add_argument("--rules", type=Path, help="folder of YAML rules (default: built-in rules)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("ingest", help="load log files")
    s.add_argument("files", nargs="+", type=Path)
    s.add_argument("--source", choices=sorted(PARSERS), help="log source for plain JSON / JSON Lines files")
    s.set_defaults(func=cmd_ingest)

    s = sub.add_parser("detect", help="run detection rules over all events")
    s.set_defaults(func=cmd_detect)

    s = sub.add_parser("enrich", help="enrich alert IOCs with ioc-enricher and escalate malicious ones")
    s.add_argument("--offline-dataset", type=Path, metavar="JSON", help="use a threat-intel dataset instead of the APIs")
    s.add_argument("--refresh", action="store_true", help="look up IOCs again even if already enriched")
    s.set_defaults(func=cmd_enrich)

    s = sub.add_parser("alerts", help="list alerts")
    s.add_argument("--status")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_alerts)

    for name, func, helptext in (("serve", cmd_serve, "start the web dashboard"),
                                 ("demo", cmd_demo, "load the Paper Lantern scenario, then start the dashboard")):
        s = sub.add_parser(name, help=helptext)
        s.add_argument("--host", default="127.0.0.1")
        s.add_argument("--port", type=int, default=5000)
        if name == "demo":
            s.add_argument("--logs", default=str(DEMO_LOGS), help="scenario log dataset")
            s.add_argument("--offline-dataset", help="threat-intel dataset (default: the one the scenario points to)")
            s.add_argument("--no-serve", action="store_true", help="prepare the database without starting the web server")
        s.set_defaults(func=func)

    s = sub.add_parser("reset", help="delete all events, alerts and IOCs")
    s.set_defaults(func=cmd_reset)
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
    except RuleError as exc:
        print(f"rule error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
