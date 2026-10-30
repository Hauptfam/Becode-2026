"""AbuseIPDB: crowd-sourced abuse reports for IP addresses."""

from __future__ import annotations

from ..ioc import IOC, IOCType
from .base import Provider, ProviderResult, Status

API = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDB(Provider):
    name = "AbuseIPDB"
    supported_types = frozenset({IOCType.IPV4, IOCType.IPV6})

    def __init__(self, *args, max_age_days: int = 90, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.max_age_days = max_age_days

    def _lookup(self, ioc: IOC) -> ProviderResult:
        resp = self._request(
            "GET", API,
            headers={"Key": self.api_key, "Accept": "application/json"},
            params={"ipAddress": ioc.value, "maxAgeInDays": self.max_age_days},
        )
        link = f"https://www.abuseipdb.com/check/{ioc.value}"
        if resp is None:
            return ProviderResult(self.name, Status.NOT_FOUND, link=link)

        data = resp.json()["data"]
        confidence = int(data.get("abuseConfidenceScore", 0))
        reports = int(data.get("totalReports", 0))
        details = {
            "confidence": confidence,
            "reports": reports,
            "distinct_reporters": data.get("numDistinctUsers"),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "usage": data.get("usageType"),
            "tor": data.get("isTor"),
            "last_reported": (data.get("lastReportedAt") or "")[:10] or None,
        }
        details = {k: v for k, v in details.items() if v not in (None, "")}

        summary = f"confidence {confidence}%, {reports} reports in {self.max_age_days}d"
        if data.get("isTor"):
            summary += ", Tor exit node"
        return ProviderResult(self.name, Status.OK, score=confidence, summary=summary,
                              link=link, details=details)
