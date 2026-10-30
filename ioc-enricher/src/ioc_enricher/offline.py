"""Offline threat intelligence: answer provider requests from a dataset file instead of the internet.

A dataset is a JSON file shaped like tests/data/paper_lantern_dataset.json:

    {
      "now": "2026-10-28T12:00:00+00:00",          # optional: fixed date for WHOIS age checks
      "indicators": [
        {"value": "evil.example", "type": "domain",
         "responses": {"virustotal": {"body": {...}}, "rdap": {"status": 404, "body": {}}}}
      ]
    }

The real provider classes run unchanged; only their HTTP session is swapped. This is used for
tests, demos and training labs (for example by the mini-SIEM in this repository).
"""

from __future__ import annotations

import base64
import json
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .providers import RDAP, AbuseIPDB, Provider, URLhaus, VirusTotal

OFFLINE_KEY = "offline-dataset"


class DatasetResponse:
    def __init__(self, status_code: int, payload: dict | None = None) -> None:
        self.status_code = status_code
        self._payload = payload or {}

    def json(self) -> dict:
        return self._payload


class DatasetSession:
    """Drop-in replacement for requests.Session that answers from a dataset.

    Works out which provider and IOC each request is for, then returns the dataset entry,
    or a realistic "not found" answer. Every call is recorded in ``calls`` as (provider, ioc).
    """

    def __init__(self, dataset: dict[str, Any]) -> None:
        self.indicators = {item["value"]: item for item in dataset.get("indicators", [])}
        self.headers: dict[str, str] = {}
        self.calls: list[tuple[str, str]] = []

    def request(self, method: str, url: str, **kwargs: Any) -> DatasetResponse:
        provider, ioc = identify_request(url, kwargs)
        self.calls.append((provider, ioc))
        entry = self.indicators.get(ioc, {}).get("responses", {}).get(provider)
        if entry is None:
            if provider == "urlhaus":  # URLhaus answers 200 + "no_results"; the others answer 404
                return DatasetResponse(200, {"query_status": "no_results"})
            return DatasetResponse(404)
        return DatasetResponse(entry.get("status", 200), entry.get("body", {}))


def identify_request(url: str, kwargs: dict[str, Any]) -> tuple[str, str]:
    """Return (provider key, IOC value) for an outgoing provider request."""
    parsed = urlparse(url)
    last = parsed.path.rstrip("/").rsplit("/", 1)[-1]
    if parsed.hostname == "www.virustotal.com":
        if "/urls/" in parsed.path:  # VirusTotal identifies URLs by unpadded base64
            last = base64.urlsafe_b64decode(last + "=" * (-len(last) % 4)).decode()
        return "virustotal", last
    if parsed.hostname == "api.abuseipdb.com":
        return "abuseipdb", kwargs["params"]["ipAddress"]
    if parsed.hostname == "urlhaus-api.abuse.ch":
        return "urlhaus", next(iter(kwargs["data"].values()))
    if parsed.hostname == "rdap.org":
        return "rdap", last
    raise ValueError(f"unexpected outbound request to {url}")


def load_dataset(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def offline_providers(dataset: dict[str, Any] | str | Path,
                      session: DatasetSession | None = None) -> list[Provider]:
    """Build all providers wired to a dataset (a dict or a path to a JSON file)."""
    if not isinstance(dataset, dict):
        dataset = load_dataset(dataset)
    session = session or DatasetSession(dataset)
    now = datetime.fromisoformat(dataset["now"]) if dataset.get("now") else None
    return [
        VirusTotal(OFFLINE_KEY, session=session),
        AbuseIPDB(OFFLINE_KEY, session=session),
        URLhaus(OFFLINE_KEY, session=session),
        RDAP(session=session, now=now),
    ]
