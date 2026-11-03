"""Run all checks, score each framework and derive an ISO/IEC 27005-style risk register."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from . import checks, model  # noqa: F401  (importing checks registers them)
from .checks.privacy import personal_data_projects
from .frameworks import FRAMEWORKS, MANUAL_CHECKS, assess_applicability
from .model import REGISTRY, Finding, Status
from .repo import Repo
from .sbom import components

CATEGORY_ORDER = ["Secrets & cryptography", "Supply chain", "Secure development", "Web application",
                  "Logging & monitoring", "Personal data (GDPR)", "Resilience", "Documentation",
                  "Vulnerability handling", "Risk management", "Incident handling", "AI Act"]
LIKELIHOOD = {"unlikely": 1, "possible": 2, "likely": 3}
IMPACT = {"low": 1, "medium": 2, "high": 3}


def risk_level(likelihood: str, impact: str) -> tuple[int, str]:
    """3x3 matrix (ISO 27005 clause 7.3 qualitative analysis). Returns (score 1-9, level)."""
    score = LIKELIHOOD[likelihood] * IMPACT[impact]
    return score, "High" if score >= 6 else "Medium" if score >= 3 else "Low"


@dataclass
class FrameworkScore:
    key: str
    passed: int = 0
    warned: int = 0
    failed: int = 0
    manual: int = 0
    na: int = 0
    findings: list[Finding] = field(default_factory=list)

    @property
    def assessed(self) -> int:
        return self.passed + self.warned + self.failed

    @property
    def readiness(self) -> float | None:
        """Share of applicable automated controls in place (WARN counts half)."""
        if not self.assessed:
            return None
        return round(100 * (self.passed + 0.5 * self.warned) / self.assessed)


@dataclass
class Report:
    repo: Repo
    findings: list[Finding]
    scores: dict[str, FrameworkScore]
    risks: list[dict[str, Any]]
    components: dict[str, list[dict[str, Any]]]
    personal_data: dict[str, set[str]]
    generated_at: str
    online: bool

    @property
    def counts(self) -> dict[str, int]:
        return {s.value: sum(1 for f in self.findings if f.status == s) for s in Status}

    def to_dict(self) -> dict[str, Any]:
        return {
            "repository": self.repo.root.name,
            "commit": self.repo.head or None,
            "branch": self.repo.branch or None,
            "generated_at": self.generated_at,
            "online_checks": self.online,
            "summary": self.counts,
            "frameworks": {
                k: {"name": FRAMEWORKS[k].name, "applicability": FRAMEWORKS[k].applicability_level,
                    "why": FRAMEWORKS[k].applicability, "readiness_percent": s.readiness,
                    "pass": s.passed, "warn": s.warned, "fail": s.failed, "manual": s.manual, "not_applicable": s.na}
                for k, s in self.scores.items()
            },
            "findings": [f.to_dict() for f in self.findings],
            "risk_register": self.risks,
            "manual_checks": MANUAL_CHECKS,
        }


def validate_references() -> list[str]:
    """Every reference used by a check must be described in the framework catalogue."""
    problems = []
    for spec in REGISTRY:
        for fw, refs in spec.references.items():
            for ref in refs:
                if ref not in FRAMEWORKS[fw].references:
                    problems.append(f"{spec.id}: {fw} '{ref}' is not in the catalogue")
    return problems


def run(repo: Repo, online: bool = False) -> Report:
    repo.online = online  # type: ignore[attr-defined]
    specs = sorted(REGISTRY, key=lambda s: (CATEGORY_ORDER.index(s.category), REGISTRY.index(s)))
    findings = [spec.run(repo) for spec in specs]
    by_id = {f.check_id: f for f in findings}
    personal = personal_data_projects(repo)
    assess_applicability(by_id, personal)

    scores = {key: FrameworkScore(key) for key in model.FRAMEWORKS}
    for f in findings:
        for key in f.references:
            s = scores[key]
            s.findings.append(f)
            attr = {Status.PASS: "passed", Status.WARN: "warned", Status.FAIL: "failed",
                    Status.MANUAL: "manual", Status.NA: "na"}[f.status]
            setattr(s, attr, getattr(s, attr) + 1)

    risks = []
    for f in sorted((f for f in findings if f.status in (Status.FAIL, Status.WARN)),
                    key=lambda f: -risk_level(f.likelihood, f.severity)[0]):
        # A partly implemented control (WARN) lowers the likelihood by one step.
        likelihood = f.likelihood
        if f.status == Status.WARN and likelihood != "unlikely":
            likelihood = {"likely": "possible", "possible": "unlikely"}[likelihood]
        score, level = risk_level(likelihood, f.severity)
        risks.append({
            "id": f"R-{len(risks) + 1:02d}", "check_id": f.check_id, "risk": f.title, "finding": f.summary,
            "likelihood": likelihood, "impact": f.severity, "score": score, "level": level,
            "treatment": "Modify (reduce)" if level != "Low" else "Modify or retain (accept)",
            "action": f.recommendation, "owner": "Project maintainer",
        })
    risks.sort(key=lambda r: -r["score"])
    for n, r in enumerate(risks, 1):
        r["id"] = f"R-{n:02d}"

    return Report(repo=repo, findings=findings, scores=scores, risks=risks, components=components(repo),
                  personal_data=personal, online=online,
                  generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
