"""RDAP (the modern WHOIS): registration data for domains and IP ranges. No API key."""

from __future__ import annotations

from datetime import datetime, timezone

from ..ioc import IOC, IOCType
from .base import Provider, ProviderResult, Status

API = "https://rdap.org"
NEW_DOMAIN_DAYS = 30


class RDAP(Provider):
    name = "RDAP/WHOIS"
    supported_types = frozenset({IOCType.DOMAIN, IOCType.IPV4, IOCType.IPV6})
    requires_key = False

    def __init__(self, *args, now: datetime | None = None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._now = now  # injectable for tests

    def _lookup(self, ioc: IOC) -> ProviderResult:
        kind = "domain" if ioc.type == IOCType.DOMAIN else "ip"
        resp = self._request("GET", f"{API}/{kind}/{ioc.value}",
                             headers={"Accept": "application/rdap+json"})
        if resp is None:
            return ProviderResult(self.name, Status.NOT_FOUND, summary="no registration record")
        data = resp.json()
        return self._domain(data) if kind == "domain" else self._ip(data)

    def _domain(self, data: dict) -> ProviderResult:
        events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
        created = _parse_date(events.get("registration"))
        details = {
            "registrar": _entity_name(data, "registrar"),
            "created": created.date().isoformat() if created else None,
            "expires": (events.get("expiration") or "")[:10] or None,
            "nameservers": [ns.get("ldhName", "").lower() for ns in data.get("nameservers", [])][:4],
        }
        score = None
        summary = f"registrar {details['registrar'] or 'unknown'}"
        if created:
            now = self._now or datetime.now(timezone.utc)
            age = (now - created).days
            details["age_days"] = age
            summary += f", registered {age} days ago"
            if age < NEW_DOMAIN_DAYS:
                score = 40
                summary += " (newly registered!)"
        return ProviderResult(self.name, Status.OK, score=score, summary=summary,
                              details={k: v for k, v in details.items() if v})

    def _ip(self, data: dict) -> ProviderResult:
        details = {
            "network": data.get("name"),
            "range": f"{data.get('startAddress')} - {data.get('endAddress')}"
            if data.get("startAddress") else None,
            "country": data.get("country"),
            "org": _entity_name(data, "registrant") or _entity_name(data, "administrative"),
        }
        details = {k: v for k, v in details.items() if v}
        parts = [details.get("org") or details.get("network") or "unknown owner"]
        if details.get("country"):
            parts.append(details["country"])
        return ProviderResult(self.name, Status.OK, summary=", ".join(parts), details=details)


def _entity_name(data: dict, role: str) -> str | None:
    for entity in data.get("entities", []):
        if role in entity.get("roles", []):
            vcard = entity.get("vcardArray", [None, []])[1]
            for prop in vcard:
                if prop[0] == "fn" and prop[3]:
                    return str(prop[3])
            return entity.get("handle")
    return None


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
