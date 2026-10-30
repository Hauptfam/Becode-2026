"""Shared types and HTTP handling for threat-intel providers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import requests

from ..ioc import IOC, IOCType

USER_AGENT = "ioc-enricher/1.0 (+https://github.com)"


class Status(str, Enum):
    OK = "ok"                 # provider returned data
    NOT_FOUND = "not_found"   # provider has never seen this IOC
    SKIPPED = "skipped"       # no API key configured
    ERROR = "error"           # network error, bad key, rate limit...


@dataclass
class ProviderResult:
    provider: str
    status: Status
    # 0 (benign) .. 100 (certainly malicious). None = informational only.
    score: int | None = None
    summary: str = ""
    link: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "status": self.status.value,
            "score": self.score,
            "summary": self.summary,
            "link": self.link,
            "details": self.details,
        }


class ProviderError(Exception):
    """Raised for failures that should be reported as an ERROR result."""


class Provider(ABC):
    name: str = "provider"
    supported_types: frozenset[IOCType] = frozenset()
    requires_key: bool = True

    def __init__(self, api_key: str | None = None, session: requests.Session | None = None,
                 timeout: float = 15.0) -> None:
        self.api_key = api_key
        self.timeout = timeout
        self.session = session or requests.Session()
        self.session.headers.setdefault("User-Agent", USER_AGENT)

    def supports(self, ioc: IOC) -> bool:
        return ioc.type in self.supported_types

    def lookup(self, ioc: IOC) -> ProviderResult:
        """Query the provider, never raising: failures become ERROR results."""
        if self.requires_key and not self.api_key:
            return ProviderResult(self.name, Status.SKIPPED, summary="no API key configured")
        try:
            return self._lookup(ioc)
        except ProviderError as exc:
            return ProviderResult(self.name, Status.ERROR, summary=str(exc))
        except requests.RequestException as exc:
            return ProviderResult(self.name, Status.ERROR, summary=f"request failed: {exc.__class__.__name__}")
        except (KeyError, TypeError, ValueError) as exc:
            return ProviderResult(self.name, Status.ERROR, summary=f"unexpected response: {exc}")

    @abstractmethod
    def _lookup(self, ioc: IOC) -> ProviderResult: ...

    # -- helpers --------------------------------------------------------------

    def _request(self, method: str, url: str, **kwargs: Any) -> requests.Response | None:
        """Send a request; return None on 404, raise ProviderError on other failures."""
        resp = self.session.request(method, url, timeout=self.timeout, **kwargs)
        if resp.status_code == 404:
            return None
        if resp.status_code in (401, 403):
            raise ProviderError("authentication failed (check your API key)")
        if resp.status_code == 429:
            raise ProviderError("rate limited (try again later)")
        if resp.status_code >= 400:
            raise ProviderError(f"HTTP {resp.status_code}")
        return resp
