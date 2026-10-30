"""Core types: check statuses, findings, and the registry that maps each check to legal references."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .repo import Repo


class Status(str, Enum):
    PASS = "PASS"        # the technical control is in place
    WARN = "WARN"        # partly in place, or in place with a caveat worth reviewing
    FAIL = "FAIL"        # the control is missing
    MANUAL = "MANUAL"    # cannot be verified from the code: needs a human check
    NA = "N/A"           # does not apply to this project

    @property
    def weight(self) -> float | None:
        """Contribution to a readiness score (None = not counted)."""
        return {"PASS": 1.0, "WARN": 0.5, "FAIL": 0.0}.get(self.value)


FRAMEWORKS = ["NIS2", "DORA", "CRA", "ISO27001", "ISO27005", "AIACT", "GDPR"]


@dataclass
class Finding:
    check_id: str
    title: str
    category: str
    status: Status
    summary: str
    evidence: list[str] = field(default_factory=list)
    recommendation: str = ""
    references: dict[str, list[str]] = field(default_factory=dict)
    severity: str = "medium"          # impact if the control is missing: low | medium | high
    likelihood: str = "possible"      # how likely the gap is exploited: unlikely | possible | likely

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id, "title": self.title, "category": self.category,
            "status": self.status.value, "summary": self.summary, "evidence": self.evidence,
            "recommendation": self.recommendation, "references": self.references,
            "severity": self.severity, "likelihood": self.likelihood,
        }


@dataclass
class Result:
    """What a check function returns; the registry adds the check's metadata to make a Finding."""

    status: Status
    summary: str
    evidence: list[str] = field(default_factory=list)


@dataclass
class CheckSpec:
    id: str
    title: str
    category: str
    references: dict[str, list[str]]
    recommendation: str
    severity: str
    likelihood: str
    func: Callable[[Repo], Result]

    def run(self, repo: Repo) -> Finding:
        try:
            result = self.func(repo)
        except Exception as exc:  # a broken check must not break the whole report
            result = Result(Status.MANUAL, f"The automated check could not run ({exc.__class__.__name__}: {exc}).")
        unknown = set(self.references) - set(FRAMEWORKS)
        if unknown:
            raise ValueError(f"{self.id}: unknown framework(s) {unknown}")
        return Finding(
            check_id=self.id, title=self.title, category=self.category, status=result.status,
            summary=result.summary, evidence=result.evidence[:15],
            recommendation=self.recommendation if result.status in (Status.FAIL, Status.WARN, Status.MANUAL) else "",
            references=self.references, severity=self.severity, likelihood=self.likelihood,
        )


REGISTRY: list[CheckSpec] = []


def check(id: str, title: str, category: str, references: dict[str, list[str]], recommendation: str,
          severity: str = "medium", likelihood: str = "possible"):
    """Decorator registering a check function."""
    def wrap(func: Callable[[Repo], Result]) -> Callable[[Repo], Result]:
        if any(spec.id == id for spec in REGISTRY):
            raise ValueError(f"duplicate check id {id}")
        REGISTRY.append(CheckSpec(id, title, category, references, recommendation, severity, likelihood, func))
        return func
    return wrap
