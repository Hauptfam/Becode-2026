"""VirusTotal v3 API: multi-engine reputation for IPs, domains, URLs and hashes."""

from __future__ import annotations

import base64
from datetime import datetime, timezone

from ..ioc import IOC, IOCType
from .base import Provider, ProviderResult, Status

API = "https://www.virustotal.com/api/v3"
GUI = "https://www.virustotal.com/gui"


class VirusTotal(Provider):
    name = "VirusTotal"
    supported_types = frozenset(IOCType)

    def _endpoint(self, ioc: IOC) -> tuple[str, str]:
        if ioc.type.is_ip:
            return f"{API}/ip_addresses/{ioc.value}", f"{GUI}/ip-address/{ioc.value}"
        if ioc.type == IOCType.DOMAIN:
            return f"{API}/domains/{ioc.value}", f"{GUI}/domain/{ioc.value}"
        if ioc.type == IOCType.URL:
            url_id = base64.urlsafe_b64encode(ioc.value.encode()).decode().rstrip("=")
            return f"{API}/urls/{url_id}", f"{GUI}/url/{url_id}"
        return f"{API}/files/{ioc.value}", f"{GUI}/file/{ioc.value}"

    def _lookup(self, ioc: IOC) -> ProviderResult:
        api_url, link = self._endpoint(ioc)
        resp = self._request("GET", api_url, headers={"x-apikey": self.api_key})
        if resp is None:
            return ProviderResult(self.name, Status.NOT_FOUND, summary="not in VirusTotal", link=link)

        attrs = resp.json()["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values()) or 0

        details: dict = {
            "malicious": malicious,
            "suspicious": suspicious,
            "engines": total,
            "reputation": attrs.get("reputation"),
        }
        if ioc.type.is_ip:
            details.update(country=attrs.get("country"), as_owner=attrs.get("as_owner"), asn=attrs.get("asn"))
        if ioc.type == IOCType.DOMAIN:
            details["registrar"] = attrs.get("registrar")
            if attrs.get("creation_date"):
                details["created"] = _iso(attrs["creation_date"])
        if ioc.type.is_hash:
            details.update(
                name=attrs.get("meaningful_name"),
                file_type=attrs.get("type_description"),
                size=attrs.get("size"),
                threat_label=(attrs.get("popular_threat_classification") or {}).get("suggested_threat_label"),
            )
        if attrs.get("last_analysis_date"):
            details["last_analysis"] = _iso(attrs["last_analysis_date"])
        details = {k: v for k, v in details.items() if v not in (None, "")}

        summary = f"{malicious}/{total} engines flag as malicious"
        if suspicious:
            summary += f", {suspicious} suspicious"
        if details.get("threat_label"):
            summary += f" ({details['threat_label']})"

        return ProviderResult(self.name, Status.OK, score=_score(malicious, suspicious),
                              summary=summary, link=link, details=details)


def _score(malicious: int, suspicious: int) -> int:
    """Map engine detections to 0-100. A couple of hits is often a false positive."""
    if malicious >= 10:
        return 100
    if malicious >= 5:
        return 85
    if malicious >= 2:
        return 60
    if malicious == 1 or suspicious >= 2:
        return 30
    return 0


def _iso(ts: int) -> str:
    return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d")
