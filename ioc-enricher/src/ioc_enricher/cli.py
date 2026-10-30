"""Command-line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .enrich import Verdict, default_providers, enrich
from .ioc import IOC, extract, parse
from .offline import offline_providers
from .output import RENDERERS, render_text, use_color

EXIT_OK, EXIT_USAGE, EXIT_FLAGGED = 0, 1, 2

EPILOG = """\
examples:
  ioc-enricher 8.8.8.8 hxxps://evil[.]example/payload.exe
  ioc-enricher -f iocs.txt -o csv --out results.csv
  ioc-enricher --extract -f threat_report.txt -o md
  cat alerts.log | ioc-enricher --extract --fail-on suspicious
  ioc-enricher -x -f tests/data/paper_lantern_report.txt --offline-dataset tests/data/paper_lantern_dataset.json

API keys are read from the environment or a .env file:
  VT_API_KEY, ABUSEIPDB_API_KEY, URLHAUS_API_KEY
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ioc-enricher",
        description="Enrich IPs, domains, URLs and file hashes with threat intelligence.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("iocs", nargs="*", help="indicators to check (defanged input is fine)")
    p.add_argument("-f", "--file", type=Path, help="read indicators from a file ('-' for stdin)")
    p.add_argument("-x", "--extract", action="store_true",
                   help="treat input as free text and pull out every IOC it contains")
    p.add_argument("-o", "--output", choices=["text", *RENDERERS], default="text",
                   help="output format (default: text)")
    p.add_argument("--out", type=Path, help="write output to a file instead of stdout")
    p.add_argument("-v", "--verbose", action="store_true", help="show every field and link")
    p.add_argument("--fail-on", choices=["malicious", "suspicious"],
                   help=f"exit with code {EXIT_FLAGGED} if any IOC reaches this verdict")
    p.add_argument("--workers", type=int, default=8, help="parallel lookups (default: 8)")
    p.add_argument("--timeout", type=float, default=15.0, help="per-request timeout in seconds")
    p.add_argument("--offline-dataset", type=Path, metavar="JSON",
                   help="answer from a threat-intel dataset file instead of the real APIs (labs, demos)")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def collect_iocs(args: argparse.Namespace) -> tuple[list[IOC], list[str]]:
    """Gather IOCs from arguments, a file or stdin. Returns (iocs, rejected inputs)."""
    chunks: list[str] = list(args.iocs)
    if args.file:
        text = sys.stdin.read() if str(args.file) == "-" else args.file.read_text(encoding="utf-8", errors="replace")
        chunks.extend(text.splitlines())
    elif not args.iocs and not sys.stdin.isatty():
        chunks.extend(sys.stdin.read().splitlines())

    iocs: list[IOC] = []
    rejected: list[str] = []
    if args.extract:
        iocs = extract("\n".join(chunks))
    else:
        for chunk in chunks:
            line = chunk.split("#", 1)[0].strip()  # allow comments in IOC lists
            if not line:
                continue
            ioc = parse(line)
            if ioc is None:
                rejected.append(line)
            elif ioc not in iocs:
                iocs.append(ioc)
    return iocs, rejected


def main(argv: list[str] | None = None) -> int:
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:  # python-dotenv is optional
        pass

    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        iocs, rejected = collect_iocs(args)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    for item in rejected:
        print(f"warning: not a recognised IOC, skipped: {item}", file=sys.stderr)
    if not iocs:
        parser.print_usage(sys.stderr)
        print("error: no valid IOCs given", file=sys.stderr)
        return EXIT_USAGE

    if args.offline_dataset:
        try:
            providers = offline_providers(args.offline_dataset)
        except (OSError, ValueError, KeyError) as exc:
            print(f"error: cannot load offline dataset: {exc}", file=sys.stderr)
            return EXIT_USAGE
        print(f"note: offline mode, answers come from {args.offline_dataset}", file=sys.stderr)
        missing = []
    else:
        providers = default_providers(timeout=args.timeout)
        missing = [p.name for p in providers if p.requires_key and not p.api_key]
    if missing:
        print(f"note: no API key for {', '.join(missing)}; those lookups are skipped", file=sys.stderr)

    reports = enrich(iocs, providers, workers=args.workers)

    if args.output == "text":
        color = not args.no_color and args.out is None and use_color()
        rendered = render_text(reports, color=color, verbose=args.verbose) + "\n"
    else:
        rendered = RENDERERS[args.output](reports)

    if args.out:
        args.out.write_text(rendered, encoding="utf-8")
        print(f"wrote {len(reports)} result(s) to {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(rendered)

    if args.fail_on:
        flagged = {Verdict.MALICIOUS} if args.fail_on == "malicious" else {Verdict.MALICIOUS, Verdict.SUSPICIOUS}
        if any(r.verdict in flagged for r in reports):
            return EXIT_FLAGGED
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
