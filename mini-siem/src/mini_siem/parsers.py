"""Parse raw log records from each source into one normalized event schema.

Every source keeps its own native field names (like a real mail gateway, proxy, DNS server,
firewall and EDR would). The parsers map them to common fields so one rule language can
query all of them:

    timestamp, ts, source, event_type, host, user, src_ip, src_port, dst_ip, dst_port, protocol,
    action, domain, url, http_method, http_status, user_agent, content_type, sender, sender_domain,
    recipient, subject, url_count, process_name, process_path, command_line, parent_name,
    file_path, file_name, sha256, sha1, md5, signed, message
"""

from __future__ import annotations

import ipaddress
import itertools
from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

Event = dict[str, Any]

_counter = itertools.count(1)


class ParseError(ValueError):
    pass


# --- Timestamps -------------------------------------------------------------------------

def parse_timestamp(value: Any) -> datetime:
    """Accept ISO 8601, Apache/Squid "28/Oct/2026:08:44:02 +0000", "2026-10-28 08:44:02" or epoch."""
    if isinstance(value, int | float):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if not isinstance(value, str) or not value.strip():
        raise ParseError(f"missing or invalid timestamp: {value!r}")
    text = value.strip()
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(text, fmt)
            break
        except ValueError:
            continue
    else:
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ParseError(f"unrecognised timestamp: {value!r}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)  # logs without a timezone are treated as UTC
    return dt.astimezone(timezone.utc)


# --- Helpers ----------------------------------------------------------------------------

def is_ip(value: str | None) -> bool:
    try:
        ipaddress.ip_address(value or "")
        return True
    except ValueError:
        return False


def is_private_ip(value: str | None) -> bool:
    try:
        return not ipaddress.ip_address(value or "").is_global
    except ValueError:
        return False


def basename(path: str | None) -> str | None:
    if not path:
        return None
    return path.replace("/", "\\").rstrip("\\").rsplit("\\", 1)[-1]


def _url_parts(url: str | None) -> tuple[str | None, str | None]:
    """Return (domain, ip) for the host part of a URL; one of them is None."""
    if not url:
        return None, None
    host = (urlparse(url).hostname or "").lower() or None
    if host and is_ip(host):
        return None, host
    return host, None


def _base(record: dict, source: str, ts_field: str) -> Event:
    dt = parse_timestamp(record.get(ts_field))
    return {
        "id": record.get("id") or f"{source}-{next(_counter):06d}",
        "source": source,
        "timestamp": dt.isoformat().replace("+00:00", "Z"),
        "ts": dt.timestamp(),
    }


def _clean(event: Event) -> Event:
    return {k: v for k, v in event.items() if v not in (None, "", [])}


# --- One parser per log source -------------------------------------------------------------

def parse_email(record: dict) -> Event:
    """Mail gateway log: one line per delivered/blocked message."""
    e = _base(record, "email", "timestamp")
    sender = (record.get("sender") or "").lower()
    urls = record.get("urls") or []
    e.update(
        event_type="email",
        sender=sender,
        sender_domain=sender.rsplit("@", 1)[-1] if "@" in sender else None,
        recipient=(record.get("recipient") or "").lower(),
        subject=record.get("subject"),
        url=urls[0] if urls else None,
        urls=urls,
        url_count=len(urls),
        attachments=record.get("attachments") or [],
        spf=record.get("spf"),
        action=record.get("action"),
    )
    e["domain"], _ = _url_parts(e["url"])
    e["message"] = f"{sender} -> {e['recipient']}: {record.get('subject', '')}"
    return _clean(e)


def parse_proxy(record: dict) -> Event:
    """Web proxy access log (Squid/Apache style timestamps)."""
    e = _base(record, "proxy", "time")
    url = record.get("url")
    domain, ip = _url_parts(url)
    e.update(
        event_type="http",
        src_ip=record.get("client_ip"),
        user=record.get("user"),
        http_method=record.get("method"),
        url=url,
        domain=domain,
        dst_ip=ip,
        http_status=record.get("status"),
        bytes=record.get("bytes"),
        content_type=record.get("content_type"),
        user_agent=record.get("user_agent"),
    )
    e["message"] = f"{record.get('method', 'GET')} {url} ({record.get('status')})"
    return _clean(e)


def parse_dns(record: dict) -> Event:
    """DNS server query log (epoch timestamps)."""
    e = _base(record, "dns", "ts")
    answers = record.get("answers") or []
    e.update(
        event_type="dns_query",
        src_ip=record.get("client"),
        domain=(record.get("query") or "").lower().rstrip("."),
        dns_type=record.get("qtype"),
        dns_rcode=record.get("rcode"),
        answers=answers,
    )
    e["message"] = f"{e['domain']} {record.get('qtype', 'A')} -> {', '.join(answers) or record.get('rcode', '')}"
    return _clean(e)


def parse_firewall(record: dict) -> Event:
    """Perimeter firewall connection log."""
    e = _base(record, "firewall", "timestamp")
    e.update(
        event_type="connection",
        src_ip=record.get("src"),
        src_port=record.get("sport"),
        dst_ip=record.get("dst"),
        dst_port=record.get("dport"),
        protocol=record.get("proto"),
        action=record.get("action"),
        bytes_out=record.get("bytes_out"),
    )
    e["message"] = (f"{e['src_ip']}:{e.get('src_port')} -> {e['dst_ip']}:{e.get('dst_port')} "
                    f"{record.get('proto', '')} {record.get('action', '')}")
    return _clean(e)


def parse_edr(record: dict) -> Event:
    """Endpoint detection & response telemetry: processes, files, DLL loads, host actions."""
    e = _base(record, "edr", "@timestamp")
    proc = record.get("process") or {}
    file = record.get("file") or {}
    event_type = record.get("event_type")
    e.update(
        event_type=event_type,
        host=record.get("hostname"),
        user=record.get("user"),
        process_name=(proc.get("name") or "").lower() or None,
        process_path=proc.get("path"),
        command_line=proc.get("command_line"),
        parent_name=(proc.get("parent_name") or "").lower() or None,
        file_path=file.get("path"),
        file_name=basename(file.get("path")),
    )
    # Hashes and signature belong to the file for file events, otherwise to the process.
    subject = file if event_type in ("file_create", "image_load") else proc
    e.update(sha256=subject.get("sha256"), sha1=subject.get("sha1"), md5=subject.get("md5"),
             signed=subject.get("signed"))

    name = e.get("process_name") or "?"
    if event_type == "process_start":
        e["message"] = f"{e.get('parent_name') or '?'} -> {name}: {e.get('command_line') or e.get('process_path')}"
    elif event_type == "file_create":
        e["message"] = f"{name} created {e.get('file_path')}"
    elif event_type == "image_load":
        signed = "signed" if e.get("signed") else "UNSIGNED"
        e["message"] = f"{name} loaded {e.get('file_path')} ({signed})"
    else:
        e["message"] = record.get("description") or f"{event_type} on {e.get('host')}"
    return _clean(e)  # keeps signed=False, drops missing values


PARSERS: dict[str, Callable[[dict], Event]] = {
    "email": parse_email,
    "proxy": parse_proxy,
    "dns": parse_dns,
    "firewall": parse_firewall,
    "edr": parse_edr,
}


# --- Asset inventory: map IPs and mailboxes to hosts -----------------------------------------

class AssetInventory:
    """Resolves the internal host (and user) behind an IP address or a mailbox."""

    def __init__(self, assets: Iterable[dict] = ()) -> None:
        self.by_ip: dict[str, dict] = {}
        self.by_email: dict[str, dict] = {}
        for asset in assets:
            if asset.get("ip"):
                self.by_ip[asset["ip"]] = asset
            if asset.get("email"):
                self.by_email[asset["email"].lower()] = asset

    def resolve(self, event: Event) -> Event:
        if event.get("host"):
            return event
        asset = None
        if event["source"] == "email":
            asset = self.by_email.get(event.get("recipient", ""))
        elif event.get("src_ip"):
            asset = self.by_ip.get(event["src_ip"])
        if asset:
            event["host"] = asset.get("hostname")
            event.setdefault("user", asset.get("user"))
        return event


def parse_record(source: str, record: dict, assets: AssetInventory | None = None) -> Event:
    try:
        parser = PARSERS[source]
    except KeyError:
        raise ParseError(f"unknown log source {source!r} (expected one of: {', '.join(PARSERS)})") from None
    event = parser(record)
    return (assets or AssetInventory()).resolve(event)
