"""Render reports as terminal text, JSON, CSV or a Markdown block for tickets."""

from __future__ import annotations

import csv
import io
import json
import os
import sys
from datetime import datetime, timezone

from .enrich import Report, Verdict
from .providers import Status

_COLORS = {
    Verdict.MALICIOUS: "\033[1;31m",
    Verdict.SUSPICIOUS: "\033[1;33m",
    Verdict.CLEAN: "\033[1;32m",
    Verdict.UNKNOWN: "\033[1;37m",
    Verdict.PRIVATE: "\033[1;36m",
}
_DIM = "\033[2m"
_RESET = "\033[0m"


def use_color(stream=sys.stdout) -> bool:
    return stream.isatty() and "NO_COLOR" not in os.environ


def render_text(reports: list[Report], color: bool = False, verbose: bool = False) -> str:
    def paint(text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if color else text

    lines: list[str] = []
    for report in reports:
        verdict = report.verdict
        score = "" if report.score is None else f" {report.score}"
        badge = paint(f"[{verdict.value}{score}]", _COLORS[verdict])
        lines.append(f"{badge} {report.ioc.defanged}  {paint(f'({report.ioc.type.value})', _DIM)}")
        if verdict == Verdict.PRIVATE:
            lines.append(f"  {paint('internal / non-routable address, external lookups skipped', _DIM)}")
        for r in report.results:
            if r.status == Status.SKIPPED and not verbose:
                continue
            text = r.summary or r.status.value.replace("_", " ")
            if r.status in (Status.ERROR, Status.SKIPPED, Status.NOT_FOUND):
                text = paint(text, _DIM)
            lines.append(f"  {r.provider:<12} {text}")
            if verbose:
                for key, value in r.details.items():
                    if isinstance(value, list):
                        value = ", ".join(map(str, value))
                    lines.append(f"  {'':<12}   {paint(key + ':', _DIM)} {value}")
                if r.link:
                    lines.append(f"  {'':<12}   {paint('link:', _DIM)} {r.link}")
        lines.append("")

    counts = {v: sum(1 for r in reports if r.verdict == v) for v in Verdict}
    summary = ", ".join(f"{n} {v.value.lower()}" for v, n in counts.items() if n)
    lines.append(f"{len(reports)} IOC(s) checked: {summary}")
    return "\n".join(lines)


def render_json(reports: list[Report]) -> str:
    return json.dumps(
        {
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "reports": [r.to_dict() for r in reports],
        },
        indent=2,
    )


def render_csv(reports: list[Report]) -> str:
    providers = sorted({res.provider for r in reports for res in r.results})
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ioc", "defanged", "type", "verdict", "score", *providers])
    for r in reports:
        by_provider = {res.provider: res.summary or res.status.value for res in r.results}
        writer.writerow([r.ioc.value, r.ioc.defanged, r.ioc.type.value, r.verdict.value,
                         "" if r.score is None else r.score,
                         *(by_provider.get(p, "") for p in providers)])
    return buf.getvalue()


def render_markdown(reports: list[Report]) -> str:
    """A defanged table ready to paste into a ticket or incident report."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out = [f"### IOC enrichment ({now})", "",
           "| IOC | Type | Verdict | Score | Key findings |",
           "|---|---|---|---|---|"]
    for r in reports:
        findings = "<br>".join(
            f"**{res.provider}**: {res.summary}"
            for res in r.results
            if res.status == Status.OK and res.summary
        ) or "no data"
        score = "-" if r.score is None else str(r.score)
        out.append(f"| `{r.ioc.defanged}` | {r.ioc.type.value} | {r.verdict.value} | {score} | {findings} |")
    return "\n".join(out) + "\n"


RENDERERS = {"json": render_json, "csv": render_csv, "md": render_markdown}
