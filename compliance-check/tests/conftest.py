"""Helpers to build small fake repositories for testing individual checks."""

from __future__ import annotations

from pathlib import Path

import pytest

from compliance_check.model import REGISTRY
from compliance_check.repo import Repo

ROOT = Path(__file__).resolve().parents[2]   # the Becode-2026 repository


def make_repo(tmp_path: Path, files: dict[str, str]) -> Repo:
    for rel, content in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return Repo(tmp_path)


def run_check(repo: Repo, check_id: str):
    import compliance_check.checks  # noqa: F401  (registers the checks)

    spec = next(s for s in REGISTRY if s.id == check_id)
    return spec.run(repo)


@pytest.fixture
def repo_factory(tmp_path):
    """Each call builds a separate repository in its own folder."""
    counter = iter(range(1000))

    def factory(files: dict[str, str]) -> Repo:
        folder = tmp_path / f"repo{next(counter)}"
        folder.mkdir()
        return make_repo(folder, files)
    return factory
