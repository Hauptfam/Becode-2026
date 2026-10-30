"""Run lookups across providers in parallel and combine them into a verdict."""

from __future__ import annotations

import os
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .ioc import IOC
from .providers import RDAP, AbuseIPDB, Provider, ProviderResult, Status, URLhaus, VirusTotal


class Verdict(str, Enum):
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    CLEAN = "CLEAN"
    UNKNOWN = "UNKNOWN"
    PRIVATE = "PRIVATE"   # internal/non-routable IP: nothing to look up externally


MALICIOUS_THRESHOLD = 70
SUSPICIOUS_THRESHOLD = 30


@dataclass
class Report:
    ioc: IOC
    results: list[ProviderResult] = field(default_factory=list)

    @property
    def score(self) -> int | None:
        scores = [r.score for r in self.results if r.status == Status.OK and r.score is not None]
        if not scores:
            return None
        # Worst signal wins, with a bonus when several sources agree it is bad.
        worst = max(scores)
        agreeing = sum(1 for s in scores if s >= SUSPICIOUS_THRESHOLD)
        return min(100, worst + 10 * max(0, agreeing - 1))

    @property
    def verdict(self) -> Verdict:
        if self.ioc.is_private:
            return Verdict.PRIVATE
        score = self.score
        if score is None:
            return Verdict.UNKNOWN
        if score >= MALICIOUS_THRESHOLD:
            return Verdict.MALICIOUS
        if score >= SUSPICIOUS_THRESHOLD:
            return Verdict.SUSPICIOUS
        return Verdict.CLEAN

    def to_dict(self) -> dict[str, Any]:
        return {
            "ioc": self.ioc.value,
            "defanged": self.ioc.defanged,
            "type": self.ioc.type.value,
            "verdict": self.verdict.value,
            "score": self.score,
            "results": [r.to_dict() for r in self.results],
        }


def default_providers(timeout: float = 15.0) -> list[Provider]:
    """Build every provider from environment variables (keys are optional)."""
    return [
        VirusTotal(os.getenv("VT_API_KEY"), timeout=timeout),
        AbuseIPDB(os.getenv("ABUSEIPDB_API_KEY"), timeout=timeout),
        URLhaus(os.getenv("URLHAUS_API_KEY"), timeout=timeout),
        RDAP(timeout=timeout),
    ]


def enrich(iocs: Iterable[IOC], providers: list[Provider], workers: int = 8) -> list[Report]:
    """Look up every IOC in every provider that supports it, preserving input order."""
    reports = [Report(ioc) for ioc in iocs]
    jobs = [
        (report, provider)
        for report in reports
        if not report.ioc.is_private
        for provider in providers
        if provider.supports(report.ioc)
    ]
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        results = list(pool.map(lambda job: job[1].lookup(job[0].ioc), jobs))
    for (report, _), result in zip(jobs, results, strict=True):
        report.results.append(result)
    return reports
