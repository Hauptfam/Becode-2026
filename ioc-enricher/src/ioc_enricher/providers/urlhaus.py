"""abuse.ch URLhaus: URLs, hosts and payloads used for malware distribution."""

from __future__ import annotations

from ..ioc import IOC, IOCType
from .base import Provider, ProviderError, ProviderResult, Status

API = "https://urlhaus-api.abuse.ch/v1"


class URLhaus(Provider):
    name = "URLhaus"
    supported_types = frozenset({IOCType.URL, IOCType.DOMAIN, IOCType.IPV4, IOCType.IPV6,
                                 IOCType.MD5, IOCType.SHA256})

    def _post(self, path: str, data: dict) -> dict | None:
        resp = self._request("POST", f"{API}/{path}/", data=data, headers={"Auth-Key": self.api_key})
        if resp is None:
            return None
        body = resp.json()
        status = body.get("query_status")
        if status in ("no_results", "not_found"):
            return None
        if status != "ok":
            raise ProviderError(f"query failed: {status}")
        return body

    def _lookup(self, ioc: IOC) -> ProviderResult:
        if ioc.type == IOCType.URL:
            return self._url(ioc)
        if ioc.type.is_hash:
            return self._payload(ioc)
        return self._host(ioc)

    def _url(self, ioc: IOC) -> ProviderResult:
        body = self._post("url", {"url": ioc.value})
        if body is None:
            return ProviderResult(self.name, Status.NOT_FOUND, summary="URL not listed")
        online = body.get("url_status") == "online"
        details = {
            "url_status": body.get("url_status"),
            "threat": body.get("threat"),
            "tags": body.get("tags") or [],
            "first_seen": (body.get("date_added") or "")[:10] or None,
        }
        summary = f"listed as {body.get('threat') or 'malicious'} ({body.get('url_status')})"
        if details["tags"]:
            summary += f", tags: {', '.join(details['tags'][:4])}"
        return ProviderResult(self.name, Status.OK, score=95 if online else 80, summary=summary,
                              link=body.get("urlhaus_reference"), details=_clean(details))

    def _host(self, ioc: IOC) -> ProviderResult:
        body = self._post("host", {"host": ioc.value})
        if body is None:
            return ProviderResult(self.name, Status.NOT_FOUND, summary="host not listed")
        urls = body.get("urls") or []
        online = sum(1 for u in urls if u.get("url_status") == "online")
        count = int(body.get("url_count") or len(urls))
        tags = sorted({t for u in urls for t in (u.get("tags") or [])})
        details = {"malware_urls": count, "online": online, "tags": tags,
                   "first_seen": (body.get("firstseen") or "")[:10] or None}
        summary = f"hosts {count} malware URL(s), {online} online"
        if tags:
            summary += f", tags: {', '.join(tags[:4])}"
        score = 90 if online else 70
        return ProviderResult(self.name, Status.OK, score=score, summary=summary,
                              link=body.get("urlhaus_reference"), details=_clean(details))

    def _payload(self, ioc: IOC) -> ProviderResult:
        key = "md5_hash" if ioc.type == IOCType.MD5 else "sha256_hash"
        body = self._post("payload", {key: ioc.value})
        if body is None:
            return ProviderResult(self.name, Status.NOT_FOUND, summary="payload not listed")
        details = {
            "signature": body.get("signature"),
            "file_type": body.get("file_type"),
            "delivered_by_urls": body.get("url_count"),
            "first_seen": (body.get("firstseen") or "")[:10] or None,
        }
        summary = f"known malware payload: {body.get('signature') or 'unknown family'}"
        sha = body.get("sha256_hash")
        link = f"https://urlhaus.abuse.ch/browse.php?search={sha}" if sha else None
        return ProviderResult(self.name, Status.OK, score=95, summary=summary, link=link,
                              details=_clean(details))


def _clean(d: dict) -> dict:
    return {k: v for k, v in d.items() if v not in (None, "", [])}
