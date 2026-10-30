"""Test helpers: a fake requests.Session so no test ever touches the network."""

from __future__ import annotations

import json

import pytest


class FakeResponse:
    def __init__(self, status_code: int = 200, payload: dict | None = None):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = json.dumps(self._payload)

    def json(self):
        return self._payload


class FakeSession:
    """Returns canned responses keyed by URL substring and records every call."""

    def __init__(self, routes: dict[str, FakeResponse] | None = None):
        self.routes = routes or {}
        self.headers: dict[str, str] = {}
        self.calls: list[dict] = []

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        for fragment, response in self.routes.items():
            if fragment in url:
                return response
        return FakeResponse(404)


@pytest.fixture
def fake_session():
    return FakeSession
