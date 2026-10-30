"""Web dashboard (Flask): alert queue, alert investigation, event search, host timeline, rules."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import yaml
from flask import Flask, abort, jsonify, redirect, render_template, request, url_for

from .engine import enrichment_available
from .rules import SEVERITIES, Rule, load_rules
from .store import ALERT_STATUSES, Store

STATUS_LABELS = {
    "new": "New",
    "in_progress": "In progress",
    "closed_true_positive": "Closed: true positive",
    "closed_false_positive": "Closed: false positive",
}
PAGE_SIZE = 100


def _defang(value: str) -> str:
    try:
        from ioc_enricher.ioc import parse
    except ImportError:
        return value.replace("http", "hxxp", 1).replace(".", "[.]")
    ioc = parse(value)
    return ioc.defanged if ioc else value


def _mitre_url(technique_id: str) -> str:
    return f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"


def _fmt_time(value: str | None, with_date: bool = False) -> str:
    if not value:
        return ""
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt.strftime("%Y-%m-%d %H:%M:%S" if with_date else "%H:%M:%S")


def create_app(db_path: str | Path = "mini_siem.db", rules: list[Rule] | None = None) -> Flask:
    app = Flask(__name__)
    store = Store(db_path)
    rule_list = rules if rules is not None else load_rules()
    rules_by_id = {r.id: r for r in rule_list}
    app.config.update(STORE=store, RULES=rules_by_id)

    app.jinja_env.filters.update(defang=_defang, mitre_url=_mitre_url, t=_fmt_time,
                                 pretty=lambda d: json.dumps(d, indent=2, ensure_ascii=False),
                                 normalized=lambda e: {k: v for k, v in e.items() if k != "raw"},
                                 to_yaml=lambda d: yaml.safe_dump(d, sort_keys=False, allow_unicode=True))
    app.jinja_env.globals.update(STATUS_LABELS=STATUS_LABELS, SEVERITIES=SEVERITIES,
                                 enrichment_on=enrichment_available())

    @app.context_processor
    def nav_counts():
        open_alerts = sum(1 for a in store.alerts() if not a["status"].startswith("closed"))
        return {"open_alerts": open_alerts}

    @app.get("/")
    def index():
        return redirect(url_for("alerts"))

    # --- alert queue -------------------------------------------------------------------
    @app.get("/alerts")
    def alerts():
        status = request.args.get("status") or None
        severity = request.args.get("severity") or None
        items = store.alerts(status=status, severity=severity)
        return render_template("alerts.html", alerts=items, stats=store.stats(), all_alerts=store.alerts(),
                               status=status, severity=severity, statuses=ALERT_STATUSES)

    # --- one alert ---------------------------------------------------------------------
    @app.get("/alerts/<int:alert_id>")
    def alert(alert_id: int):
        item = store.get_alert(alert_id) or abort(404)
        events = store.get_events(item["event_ids"])
        iocs = store.get_iocs(item["iocs"])
        enriched = {i["value"] for i in iocs}
        missing = [v for v in item["iocs"] if v not in enriched]
        related = [a for a in store.alerts(host=item["host"]) if a["id"] != alert_id] if item["host"] else []
        return render_template("alert.html", alert=item, events=events, iocs=iocs, missing=missing,
                               rule=rules_by_id.get(item["rule_id"]), related=related, statuses=ALERT_STATUSES)

    @app.post("/alerts/<int:alert_id>/status")
    def alert_status(alert_id: int):
        store.get_alert(alert_id) or abort(404)
        status = request.form.get("status", "")
        if status not in ALERT_STATUSES:
            abort(400)
        store.update_alert_status(alert_id, status, request.form.get("notes", "").strip())
        return redirect(url_for("alert", alert_id=alert_id))

    # --- events ------------------------------------------------------------------------
    @app.get("/events")
    def events():
        source = request.args.get("source") or None
        host = request.args.get("host") or None
        q = (request.args.get("q") or "").strip() or None
        page = max(1, request.args.get("page", 1, type=int))
        items, total = store.search_events(source=source, host=host, q=q, limit=PAGE_SIZE,
                                           offset=(page - 1) * PAGE_SIZE)
        flagged = {e for a in store.alerts() for e in a["event_ids"]}
        return render_template("events.html", events=items, total=total, page=page, page_size=PAGE_SIZE,
                               sources=store.distinct("source"), hosts=store.distinct("host"),
                               source=source, host=host, q=q or "", flagged=flagged)

    # --- host timeline -----------------------------------------------------------------
    @app.get("/hosts/<host>")
    def host(host: str):
        items, total = store.search_events(host=host, limit=1000)
        if not total:
            abort(404)
        host_alerts = store.alerts(host=host)
        rule_of = {}
        for a in host_alerts:
            for e in a["event_ids"]:
                rule_of.setdefault(e, []).append(a)
        return render_template("host.html", host=host, events=items, alerts=host_alerts, rule_of=rule_of)

    # --- rules -------------------------------------------------------------------------
    @app.get("/rules")
    def rules_page():
        hits = {}
        for a in store.alerts():
            hits[a["rule_id"]] = hits.get(a["rule_id"], 0) + 1
        return render_template("rules.html", rules=rule_list, hits=hits)

    # --- JSON API (for scripts / SOAR) ----------------------------------------------------
    @app.get("/api/alerts")
    def api_alerts():
        return jsonify(store.alerts(status=request.args.get("status"), severity=request.args.get("severity")))

    @app.get("/api/alerts/<int:alert_id>")
    def api_alert(alert_id: int):
        item = store.get_alert(alert_id) or abort(404)
        return jsonify({**item, "events": store.get_events(item["event_ids"]), "ioc_details": store.get_iocs(item["iocs"])})

    @app.errorhandler(404)
    def not_found(_):
        return render_template("base.html", error="Not found"), 404

    return app
