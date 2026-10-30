"""Command line: compliance-check [PATH] --pdf report.pdf [--json report.json] [--sbom sbom.json] [--online]."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .engine import run
from .frameworks import FRAMEWORKS
from .model import Status
from .repo import Repo
from .sbom import to_cyclonedx

EXIT_OK, EXIT_ERROR, EXIT_FAILED = 0, 1, 2
SYMBOL = {Status.PASS: "PASS", Status.WARN: "WARN", Status.FAIL: "FAIL", Status.MANUAL: "TODO", Status.NA: " n/a"}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="compliance-check",
        description="Technical compliance readiness scan (NIS2, DORA, CRA, ISO/IEC 27001 & 27005, AI Act, GDPR).",
        epilog="example: compliance-check .. --pdf compliance-report.pdf --sbom sbom.cdx.json",
    )
    p.add_argument("path", nargs="?", default=".", help="repository to scan (default: current folder)")
    p.add_argument("--pdf", type=Path, default=Path("compliance-report.pdf"), help="PDF report to write")
    p.add_argument("--no-pdf", action="store_true", help="don't write a PDF")
    p.add_argument("--json", type=Path, help="also write the results as JSON")
    p.add_argument("--sbom", type=Path, help="also write a CycloneDX SBOM")
    p.add_argument("--online", action="store_true", help="query OSV.dev for known vulnerabilities in dependencies")
    p.add_argument("--fail-on", choices=["fail", "warn"], help=f"exit with code {EXIT_FAILED} if any check fails (or warns)")
    p.add_argument("-q", "--quiet", action="store_true", help="only print the summary")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        repo = Repo(args.path)
    except NotADirectoryError:
        print(f"error: not a folder: {args.path}", file=sys.stderr)
        return EXIT_ERROR

    report = run(repo, online=args.online)

    if not args.quiet:
        category = None
        for f in report.findings:
            if f.category != category:
                category = f.category
                print(f"\n{category}")
            print(f"  [{SYMBOL[f.status]}] {f.check_id:<8} {f.title}")
    print("\nFramework                Relation               Readiness")
    for key, s in report.scores.items():
        fw = FRAMEWORKS[key]
        ready = "-" if s.readiness is None else f"{s.readiness}%"
        print(f"  {fw.name:<23}{fw.applicability_level:<23}{ready}")
    c = report.counts
    print(f"\n{c['PASS']} pass, {c['WARN']} warn, {c['FAIL']} fail, {c['MANUAL']} manual, {c['N/A']} n/a | "
          f"{len(report.risks)} risks in the register")

    if not args.no_pdf:
        from .pdf import write_pdf
        write_pdf(report, str(args.pdf))
        print(f"PDF report: {args.pdf}")
    if args.json:
        args.json.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        print(f"JSON results: {args.json}")
    if args.sbom:
        args.sbom.write_text(json.dumps(to_cyclonedx(repo), indent=2), encoding="utf-8")
        print(f"SBOM: {args.sbom}")

    if args.fail_on:
        bad = {Status.FAIL} if args.fail_on == "fail" else {Status.FAIL, Status.WARN}
        if any(f.status in bad for f in report.findings):
            return EXIT_FAILED
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
