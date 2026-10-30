"""Detection rules: a small, Sigma-inspired YAML format and its matching engine.

Example rule:

    id: MS-003
    title: Script host executing a downloaded script
    severity: high                       # low | medium | high | critical
    logsource: edr                       # email | proxy | dns | firewall | edr
    mitre:
      - {id: T1059.007, name: "Command and Scripting Interpreter: JavaScript", tactic: Execution}
    detection:
      selection:
        event_type: process_start
        process_name: [wscript.exe, cscript.exe]       # a list means "any of"
        command_line|contains: '\\Downloads\\'
      filter:
        signed: false
      condition: selection and not filter
    group_by: [host]                     # one alert per host (default)

Field modifiers (after "|"): contains, startswith, endswith, re, cidr, gt, gte, lt, lte, exists, all.
String comparisons are case-insensitive. A selection can also be a list of maps (any of them).

Aggregation rules (for patterns like beaconing) add:

    aggregation:
      group_by: [host, dst_ip, dst_port]
      min_count: 6          # at least this many matching events...
      timeframe: 900        # ...within this many seconds...
      max_jitter: 5         # ...at regular intervals (std deviation of gaps, seconds). Optional.
"""

from __future__ import annotations

import ipaddress
import re
import statistics
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

SEVERITIES = ["low", "medium", "high", "critical"]
MODIFIERS = {"contains", "startswith", "endswith", "re", "cidr", "gt", "gte", "lt", "lte", "exists", "all"}
BUILTIN_RULES = Path(__file__).parent / "rules"


class RuleError(ValueError):
    pass


# --- Condition expressions: "selection and not (filter_a or filter_b)" ------------------------

_TOKEN_RE = re.compile(r"\s*(\(|\)|[A-Za-z_][A-Za-z0-9_]*)")


def _tokenize(text: str) -> list[str]:
    tokens, pos = [], 0
    text = text.strip()
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if not m:
            raise RuleError(f"invalid condition near: {text[pos:]!r}")
        tokens.append(m.group(1))
        pos = m.end()
    return tokens


def compile_condition(text: str, names: set[str]):
    """Parse a boolean condition into a function {name: bool} -> bool.

    Grammar: expr := term ("or" term)* ; term := factor ("and" factor)* ;
             factor := "not" factor | "(" expr ")" | NAME
    """
    tokens = _tokenize(text)
    pos = 0

    def peek():
        return tokens[pos] if pos < len(tokens) else None

    def take(expected=None):
        nonlocal pos
        tok = peek()
        if tok is None or (expected and tok != expected):
            raise RuleError(f"invalid condition {text!r}: expected {expected or 'more input'}")
        pos += 1
        return tok

    def expr():
        node = term()
        while peek() == "or":
            take()
            left, right = node, term()
            node = lambda r, a=left, b=right: a(r) or b(r)  # noqa: E731
        return node

    def term():
        node = factor()
        while peek() == "and":
            take()
            left, right = node, factor()
            node = lambda r, a=left, b=right: a(r) and b(r)  # noqa: E731
        return node

    def factor():
        tok = take()
        if tok == "not":
            inner = factor()
            return lambda r: not inner(r)
        if tok == "(":
            node = expr()
            take(")")
            return node
        if tok in ("and", "or", ")"):
            raise RuleError(f"invalid condition {text!r}: unexpected {tok!r}")
        if tok not in names:
            raise RuleError(f"condition {text!r} uses unknown selection {tok!r}")
        return lambda r, name=tok: r[name]

    fn = expr()
    if peek() is not None:
        raise RuleError(f"invalid condition {text!r}: unexpected {peek()!r}")
    return fn


# --- Field matching ---------------------------------------------------------------------------

def _match_one(actual: Any, expected: Any, mods: set[str]) -> bool:
    if actual is None:
        return False
    if isinstance(actual, list):  # e.g. email urls: any element may match
        return any(_match_one(a, expected, mods) for a in actual)
    if expected is None:
        return False
    if isinstance(expected, bool):
        return isinstance(actual, bool) and actual is expected
    for op in ("gt", "gte", "lt", "lte"):
        if op in mods:
            try:
                a, e = float(actual), float(expected)
            except (TypeError, ValueError):
                return False
            return {"gt": a > e, "gte": a >= e, "lt": a < e, "lte": a <= e}[op]
    if "cidr" in mods:
        try:
            return ipaddress.ip_address(str(actual)) in ipaddress.ip_network(str(expected), strict=False)
        except ValueError:
            return False
    a, e = str(actual).lower(), str(expected).lower()
    if "re" in mods:
        return re.search(str(expected), str(actual), re.IGNORECASE) is not None
    if "contains" in mods:
        return e in a
    if "startswith" in mods:
        return a.startswith(e)
    if "endswith" in mods:
        return a.endswith(e)
    return a == e


def match_field(event: dict, spec: str, expected: Any) -> bool:
    name, *mods = spec.split("|")
    mod_set = set(mods)
    if "exists" in mod_set:
        return (event.get(name) is not None) == bool(expected)
    values = expected if isinstance(expected, list) else [expected]
    if expected is None:  # "field: null" means the field must be absent
        return event.get(name) is None
    results = (_match_one(event.get(name), v, mod_set) for v in values)
    return all(results) if "all" in mod_set else any(results)


def match_selection(event: dict, selection: dict | list) -> bool:
    if isinstance(selection, list):
        return any(match_selection(event, s) for s in selection)
    return all(match_field(event, spec, value) for spec, value in selection.items())


# --- Rules -------------------------------------------------------------------------------------

@dataclass
class Rule:
    id: str
    title: str
    severity: str
    logsource: str | None
    detection: dict[str, Any]
    description: str = ""
    mitre: list[dict[str, str]] = field(default_factory=list)
    group_by: list[str] = field(default_factory=lambda: ["host"])
    aggregation: dict[str, Any] | None = None
    falsepositives: list[str] = field(default_factory=list)
    path: str | None = None

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise RuleError(f"{self.id}: severity must be one of {SEVERITIES}")
        detection = dict(self.detection)
        condition = detection.pop("condition", None)
        if not condition or not detection:
            raise RuleError(f"{self.id}: detection needs at least one selection and a condition")
        for selection in detection.values():
            for sel in selection if isinstance(selection, list) else [selection]:
                for spec in sel:
                    unknown = set(spec.split("|")[1:]) - MODIFIERS
                    if unknown:
                        raise RuleError(f"{self.id}: unknown modifier(s) {sorted(unknown)} in {spec!r}")
        self._selections = detection
        self._condition = compile_condition(condition, set(detection))
        if self.aggregation:
            self.aggregation.setdefault("group_by", self.group_by)
            if int(self.aggregation.get("min_count", 0)) < 2:
                raise RuleError(f"{self.id}: aggregation.min_count must be at least 2")

    def matches(self, event: dict) -> bool:
        if self.logsource and event.get("source") != self.logsource:
            return False
        results = {name: match_selection(event, sel) for name, sel in self._selections.items()}
        return self._condition(results)

    @property
    def group_fields(self) -> list[str]:
        return list(self.aggregation["group_by"]) if self.aggregation else list(self.group_by)

    @classmethod
    def from_dict(cls, data: dict, path: str | None = None) -> Rule:
        try:
            return cls(
                id=str(data["id"]),
                title=data["title"],
                severity=str(data.get("severity", "medium")).lower(),
                logsource=data.get("logsource"),
                detection=data["detection"],
                description=(data.get("description") or "").strip(),
                mitre=data.get("mitre") or [],
                group_by=data.get("group_by") or ["host"],
                aggregation=data.get("aggregation"),
                falsepositives=data.get("falsepositives") or [],
                path=path,
            )
        except KeyError as exc:
            raise RuleError(f"{path or 'rule'}: missing required field {exc}") from None


def load_rules(directory: str | Path = BUILTIN_RULES) -> list[Rule]:
    rules = []
    for path in sorted(Path(directory).glob("*.y*ml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        rules.append(Rule.from_dict(data, path=path.name))
    ids = [r.id for r in rules]
    duplicates = {i for i in ids if ids.count(i) > 1}
    if duplicates:
        raise RuleError(f"duplicate rule id(s): {sorted(duplicates)}")
    return rules


# --- Aggregation (e.g. beaconing) ----------------------------------------------------------------

def find_regular_window(events: list[dict], min_count: int, timeframe: float,
                        max_jitter: float | None) -> list[dict] | None:
    """Return the largest run of events (sorted by time) that fits the aggregation, or None."""
    events = sorted(events, key=lambda e: e["ts"])
    best: list[dict] | None = None
    for start in range(len(events)):
        for end in range(len(events), start + min_count - 1, -1):
            window = events[start:end]
            if window[-1]["ts"] - window[0]["ts"] > timeframe:
                continue
            if max_jitter is not None:
                gaps = [b["ts"] - a["ts"] for a, b in zip(window, window[1:])]
                if statistics.pstdev(gaps) > max_jitter:
                    continue
            if best is None or len(window) > len(best):
                best = window
            break
    return best
