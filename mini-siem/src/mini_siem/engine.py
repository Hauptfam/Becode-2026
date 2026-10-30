"""The SIEM pipeline: ingest logs -> detect with rules -> enrich alert IOCs with ioc-enricher."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .parsers import PARSERS, AssetInventory, ParseError, is_private_ip, parse_record
from .rules import SEVERITIES, Rule, find_regular_window
from .store import Store

# ---------------------------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------------------------


@dataclass
class IngestResult:
    ingested: int = 0
    errors: list[str] = field(default_factory=list)
    by_source: dict[str, int] = field(default_factory=dict)


def read_input(path: str | Path, source: str | None = None) -> tuple[list[tuple[str, dict]], list[dict]]:
    """Read a log file. Returns ([(source, record), ...], assets).

    Accepted formats:
      * a scenario dataset: {"assets": [...], "events": [{"id", "source", "record"}, ...]}
      * a JSON array of records, or JSON Lines (one record per line): needs ``source``
    """
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = None  # not a single JSON document: treat as JSON Lines

    if isinstance(data, dict) and "events" in data:
        records = [(item["source"], {**item["record"], "id": item.get("id")}) for item in data["events"]]
        return records, data.get("assets", [])
    if source is None:
        raise ParseError(f"{path.name}: plain log files need --source ({', '.join(PARSERS)})")
    if isinstance(data, list):
        return [(source, r) for r in data], []
    if isinstance(data, dict):
        return [(source, data)], []
    try:
        return [(source, json.loads(line)) for line in text.splitlines() if line.strip()], []
    except json.JSONDecodeError as exc:
        raise ParseError(f"{path.name}: not valid JSON or JSON Lines ({exc})") from None


def ingest(store: Store, records: list[tuple[str, dict]], assets: list[dict] | None = None) -> IngestResult:
    inventory = AssetInventory(assets or [])
    result = IngestResult()
    events, raws = [], []
    for n, (source, record) in enumerate(records, 1):
        try:
            events.append(parse_record(source, record, inventory))
            raws.append({k: v for k, v in record.items() if k != "id"})
        except (ParseError, KeyError, TypeError, ValueError) as exc:
            result.errors.append(f"record {n} ({source}): {exc}")
            continue
        result.by_source[source] = result.by_source.get(source, 0) + 1
    result.ingested = store.add_events(events, raws)
    return result


# ---------------------------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------------------------


def _group_key(event: dict, fields: list[str]) -> tuple:
    return tuple(event.get(f) for f in fields)


def run_rule(rule: Rule, events: list[dict]) -> list[dict[str, Any]]:
    """Return the alerts (as dicts) one rule produces over a list of events."""
    matched = [e for e in events if rule.matches(e)]
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for event in matched:
        groups[_group_key(event, rule.group_fields)].append(event)

    alerts = []
    for key, group in groups.items():
        if rule.aggregation:
            agg = rule.aggregation
            group = find_regular_window(group, int(agg["min_count"]), float(agg.get("timeframe", 3600)),
                                        agg.get("max_jitter"))
            if not group:
                continue
        group = sorted(group, key=lambda e: e["ts"])
        alerts.append({
            "key": "|".join([rule.id, *(str(k) for k in key)]),
            "rule_id": rule.id,
            "title": rule.title,
            "description": rule.description,
            "severity": rule.severity,
            "host": next((e.get("host") for e in group if e.get("host")), None),
            "first_seen": group[0]["timestamp"],
            "last_seen": group[-1]["timestamp"],
            "event_ids": [e["id"] for e in group],
            "mitre": rule.mitre,
        })
    return alerts


def detect(store: Store, rules: list[Rule]) -> list[dict[str, Any]]:
    """Run every rule over all stored events and save the alerts. Re-running keeps analyst status."""
    events = store.all_events()
    alerts = [alert for rule in rules for alert in run_rule(rule, events)]
    for alert in alerts:
        alert["id"] = store.upsert_alert(alert)
    store.delete_alerts_except(a["key"] for a in alerts)
    return alerts


# ---------------------------------------------------------------------------------------------
# Enrichment with ioc-enricher
# ---------------------------------------------------------------------------------------------

IOC_FIELDS = ("sender_domain", "domain", "url", "urls", "dst_ip", "src_ip", "sha256", "sha1", "md5")
VERDICT_ORDER = ["MALICIOUS", "SUSPICIOUS", "UNKNOWN", "CLEAN", "PRIVATE"]


def enrichment_available() -> bool:
    try:
        import ioc_enricher  # noqa: F401
    except ImportError:
        return False
    return True


def iocs_from_events(events: list[dict]) -> list[str]:
    """Collect the indicators in a set of events. Internal IPs are assets, not IOCs, so they are skipped."""
    from ioc_enricher.ioc import parse

    found: list[str] = []
    for event in events:
        for name in IOC_FIELDS:
            values = event.get(name)
            for value in values if isinstance(values, list) else [values]:
                if not value or is_private_ip(str(value)):
                    continue
                ioc = parse(str(value))
                if ioc and ioc.value not in found:
                    found.append(ioc.value)
    return found


def bump(severity: str) -> str:
    return SEVERITIES[min(SEVERITIES.index(severity) + 1, len(SEVERITIES) - 1)]


def enrich_alerts(store: Store, offline_dataset: str | Path | None = None, refresh: bool = False,
                  timeout: float = 15.0) -> dict[str, Any]:
    """Enrich the IOCs of every alert, then raise the severity of alerts with a MALICIOUS indicator."""
    from ioc_enricher.enrich import default_providers, enrich
    from ioc_enricher.ioc import parse
    from ioc_enricher.offline import offline_providers

    providers = offline_providers(offline_dataset) if offline_dataset else default_providers(timeout=timeout)

    alerts = store.alerts()
    alert_iocs = {a["id"]: iocs_from_events(store.get_events(a["event_ids"])) for a in alerts}
    wanted = list(dict.fromkeys(v for values in alert_iocs.values() for v in values))
    known = {i["value"] for i in store.get_iocs(wanted)}
    todo = wanted if refresh else [v for v in wanted if v not in known]

    for report in enrich([parse(v) for v in todo], providers):
        store.save_ioc(report.to_dict())

    verdicts = {i["value"]: i["verdict"] for i in store.get_iocs(wanted)}
    escalated = 0
    for alert in alerts:
        values = alert_iocs[alert["id"]]
        found = [verdicts[v] for v in values if v in verdicts]
        ti_verdict = min(found, key=VERDICT_ORDER.index) if found else "NONE"
        severity = bump(alert["base_severity"]) if ti_verdict == "MALICIOUS" else alert["base_severity"]
        escalated += severity != alert["base_severity"]
        store.set_alert_enrichment(alert["id"], values, ti_verdict, severity)

    return {"alerts": len(alerts), "iocs": len(wanted), "looked_up": len(todo), "escalated": escalated,
            "mode": "offline" if offline_dataset else "online"}
