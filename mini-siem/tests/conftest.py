from __future__ import annotations

import json
from pathlib import Path

import pytest

from mini_siem.engine import detect, enrich_alerts, ingest, read_input
from mini_siem.rules import load_rules
from mini_siem.store import Store

ROOT = Path(__file__).resolve().parents[1]
LOGS_PATH = ROOT / "data" / "paper_lantern_logs.json"
LOGS = json.loads(LOGS_PATH.read_text(encoding="utf-8"))
INTEL_PATH = (LOGS_PATH.parent / LOGS["threat_intel_dataset"]).resolve()


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "test.db")
    yield s
    s.close()


@pytest.fixture
def loaded_store(store):
    """Paper Lantern logs ingested, detected and enriched offline."""
    records, assets = read_input(LOGS_PATH)
    ingest(store, records, assets)
    detect(store, load_rules())
    enrich_alerts(store, offline_dataset=INTEL_PATH)
    return store
