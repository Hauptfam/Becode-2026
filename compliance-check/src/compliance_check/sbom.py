"""Software bill of materials (CycloneDX 1.5) and known-vulnerability lookup (OSV.dev)."""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from importlib import metadata
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .repo import Repo

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"


def _name(spec: str) -> str:
    return re.split(r"[\s<>=!~;\[]", spec.strip(), maxsplit=1)[0]


def _installed(name: str) -> tuple[str | None, str | None]:
    try:
        dist = metadata.distribution(name)
    except metadata.PackageNotFoundError:
        return None, None
    meta = dist.metadata
    license_ = meta.get("License-Expression") or meta.get("License") or None
    if not license_ or len(license_) > 60:
        classifiers = [c.split("::")[-1].strip() for c in (meta.get_all("Classifier") or []) if c.startswith("License ::")]
        license_ = classifiers[0] if classifiers else (license_[:60] + "..." if license_ else None)
    return dist.version, license_


def components(repo: Repo) -> dict[str, list[dict[str, Any]]]:
    """Runtime dependencies per project, with the locally installed version and license when available."""
    result: dict[str, list[dict[str, Any]]] = {}
    for folder, data in sorted(repo.projects.items()):
        project = data.get("project", {})
        items = []
        for spec in project.get("dependencies", []):
            if ";" in spec and "python_version" in spec:
                continue  # backports for old Python versions only
            name = _name(spec)
            version, license_ = _installed(name)
            items.append({"name": name, "requirement": spec, "version": version, "license": license_})
        result[project.get("name") or folder or "root"] = items
    return result


def to_cyclonedx(repo: Repo) -> dict[str, Any]:
    comps, seen = [], set()
    for items in components(repo).values():
        for c in items:
            key = (c["name"].lower(), c["version"])
            if key in seen:
                continue
            seen.add(key)
            entry: dict[str, Any] = {"type": "library", "name": c["name"], "version": c["version"] or "unknown"}
            if c["version"]:
                entry["purl"] = f"pkg:pypi/{c['name'].lower()}@{c['version']}"
            if c["license"]:
                entry["licenses"] = [{"license": {"name": c["license"]}}]
            comps.append(entry)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tools": [{"name": "compliance-check"}],
            "component": {"type": "application", "name": repo.root.name},
        },
        "components": sorted(comps, key=lambda c: c["name"].lower()),
    }


def osv_query(comps: list[dict[str, Any]], session=None, timeout: float = 20.0) -> list[str] | None:
    """Return 'package version: vuln ids' lines, [] if clean, or None if OSV.dev is unreachable."""
    if not comps:
        return []
    try:
        import requests
    except ImportError:
        return None
    session = session or requests.Session()
    queries = [{"package": {"name": c["name"], "ecosystem": "PyPI"}, "version": c["version"]} for c in comps]
    try:
        resp = session.post(OSV_BATCH_URL, json={"queries": queries}, timeout=timeout)
        resp.raise_for_status()
        results = resp.json().get("results", [])
    except (requests.RequestException, ValueError):
        return None
    found = []
    for comp, res in zip(comps, results, strict=False):
        ids = [v["id"] for v in (res or {}).get("vulns", [])]
        if ids:
            found.append(f"{comp['name']} {comp['version']}: {', '.join(ids)}")
    return found
