"""Playbooks: YAML files describing when to act on an alert and which steps to run.

    id: PB-01
    name: Contain confirmed malware or C2
    priority: 20            # lower is checked first; the first matching playbook handles the alert
    trigger:                # every listed condition must match (a list means "any of")
      severity: [high, critical]
      ti_verdict: [MALICIOUS]
      rule_id: [MS-006]     # optional
    steps:
      - action: block_ioc
        params: {verdicts: [MALICIOUS]}
      - action: isolate_host
        approval: required  # waits for an analyst: mini-soar approve <id>
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

BUILTIN_PLAYBOOKS = Path(__file__).parent / "playbooks"
TRIGGER_KEYS = {"severity", "ti_verdict", "rule_id", "status"}


class PlaybookError(ValueError):
    pass


@dataclass
class Step:
    action: str
    params: dict[str, Any] = field(default_factory=dict)
    approval: bool = False


@dataclass
class Playbook:
    id: str
    name: str
    priority: int
    trigger: dict[str, list[str]]
    steps: list[Step]
    description: str = ""
    path: str | None = None

    def matches(self, alert: dict[str, Any]) -> bool:
        values = {"severity": alert["severity"], "ti_verdict": alert.get("ti_verdict") or "NOT_ENRICHED",
                  "rule_id": alert["rule_id"], "status": alert.get("status")}
        return all(values[key] in allowed for key, allowed in self.trigger.items())

    @classmethod
    def from_dict(cls, data: dict, path: str | None = None, known_actions: set[str] | None = None) -> Playbook:
        where = path or data.get("id", "playbook")
        for required in ("id", "name", "trigger", "steps"):
            if required not in data:
                raise PlaybookError(f"{where}: missing '{required}'")
        trigger = {}
        for key, value in (data["trigger"] or {}).items():
            if key not in TRIGGER_KEYS:
                raise PlaybookError(f"{where}: unknown trigger '{key}' (allowed: {sorted(TRIGGER_KEYS)})")
            trigger[key] = [str(v) for v in (value if isinstance(value, list) else [value])]
        steps = []
        for n, raw in enumerate(data["steps"] or [], 1):
            action = raw.get("action") if isinstance(raw, dict) else None
            if not action:
                raise PlaybookError(f"{where}: step {n} has no action")
            if known_actions is not None and action not in known_actions:
                raise PlaybookError(f"{where}: step {n} uses unknown action '{action}' (known: {sorted(known_actions)})")
            approval = raw.get("approval", "none")
            if approval not in ("none", "required"):
                raise PlaybookError(f"{where}: step {n} approval must be 'none' or 'required'")
            steps.append(Step(action, raw.get("params") or {}, approval == "required"))
        if not steps:
            raise PlaybookError(f"{where}: no steps")
        return cls(id=str(data["id"]), name=data["name"], priority=int(data.get("priority", 100)), trigger=trigger,
                   steps=steps, description=(data.get("description") or "").strip(), path=path)


def load_playbooks(directory: str | Path = BUILTIN_PLAYBOOKS, known_actions: set[str] | None = None) -> list[Playbook]:
    books = [Playbook.from_dict(yaml.safe_load(p.read_text(encoding="utf-8")), p.name, known_actions)
             for p in sorted(Path(directory).glob("*.y*ml"))]
    ids = [b.id for b in books]
    if len(ids) != len(set(ids)):
        raise PlaybookError(f"duplicate playbook ids: {sorted({i for i in ids if ids.count(i) > 1})}")
    return sorted(books, key=lambda b: (b.priority, b.id))


def select_playbook(playbooks: list[Playbook], alert: dict[str, Any]) -> Playbook | None:
    return next((b for b in playbooks if b.matches(alert)), None)
