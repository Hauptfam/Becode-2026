"""IOC parsing: type detection, refanging/defanging and extraction from free text."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum


class IOCType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"

    @property
    def is_ip(self) -> bool:
        return self in (IOCType.IPV4, IOCType.IPV6)

    @property
    def is_hash(self) -> bool:
        return self in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256)


@dataclass(frozen=True)
class IOC:
    value: str
    type: IOCType

    @property
    def defanged(self) -> str:
        return defang(self.value, self.type)

    @property
    def is_private(self) -> bool:
        """True for private, loopback, link-local or otherwise non-routable IPs."""
        if not self.type.is_ip:
            return False
        ip = ipaddress.ip_address(self.value)
        return not ip.is_global

    @property
    def host(self) -> str | None:
        """Domain or IP part of a URL, or the value itself for domains/IPs."""
        if self.type == IOCType.URL:
            m = re.match(r"^[a-z][a-z0-9+.-]*://(?:[^@/]*@)?(\[[^\]]+\]|[^:/?#]+)", self.value, re.I)
            return m.group(1).strip("[]").lower() if m else None
        if self.type == IOCType.DOMAIN or self.type.is_ip:
            return self.value
        return None


_HASH_TYPES = {32: IOCType.MD5, 40: IOCType.SHA1, 64: IOCType.SHA256}
_HEX_RE = re.compile(r"^[a-fA-F0-9]+$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$",
    re.I,
)
_URL_RE = re.compile(r"^(?:https?|ftp)://[^\s/$.?#][^\s]*$", re.I)

# Common defanging styles seen in threat reports and tickets.
_REFANG_RULES = [
    (re.compile(r"^hxxp", re.I), "http"),
    (re.compile(r"^fxp", re.I), "ftp"),
    (re.compile(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[dot\]|\(dot\)", re.I), "."),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[://\]"), "://"),
    (re.compile(r"\[/\]"), "/"),
]


def refang(value: str) -> str:
    """Turn a defanged indicator (hxxp://evil[.]com) back into its real form."""
    value = value.strip().strip("\"'<>,;")
    for pattern, repl in _REFANG_RULES:
        value = pattern.sub(repl, value)
    return value


def defang(value: str, ioc_type: IOCType | None = None) -> str:
    """Make an indicator safe to paste in tickets and chats (not clickable)."""
    if ioc_type is not None and ioc_type.is_hash:
        return value
    out = re.sub(r"^http", "hxxp", value, flags=re.I)
    out = re.sub(r"^ftp", "fxp", out, flags=re.I)
    if ioc_type == IOCType.IPV6:
        return out.replace(":", "[:]")
    if ioc_type == IOCType.URL or "://" in out:
        scheme, _, rest = out.partition("://")
        host, sep, path = rest.partition("/")
        return f"{scheme}://{host.replace('.', '[.]')}{sep}{path}"
    return out.replace(".", "[.]")


def detect_type(value: str) -> IOCType | None:
    """Return the IOC type of an already-refanged value, or None if unrecognised."""
    value = value.strip()
    if not value:
        return None
    try:
        ip = ipaddress.ip_address(value)
        return IOCType.IPV4 if ip.version == 4 else IOCType.IPV6
    except ValueError:
        pass
    if _HEX_RE.match(value) and len(value) in _HASH_TYPES:
        return _HASH_TYPES[len(value)]
    if _URL_RE.match(value):
        return IOCType.URL
    if _DOMAIN_RE.match(value):
        return IOCType.DOMAIN
    return None


def parse(raw: str) -> IOC | None:
    """Refang, normalise and classify a single indicator."""
    value = refang(raw)
    ioc_type = detect_type(value)
    if ioc_type is None:
        return None
    if ioc_type.is_hash or ioc_type == IOCType.DOMAIN:
        value = value.lower()
    elif ioc_type.is_ip:
        value = str(ipaddress.ip_address(value))
    return IOC(value=value, type=ioc_type)


# --- Extraction from free text (reports, emails, tickets) -----------------------

_DOT = r"(?:\.|\[\.\]|\(\.\)|\[dot\])"
_EXTRACT_PATTERNS = [
    re.compile(r"\b(?:hxxps?|https?|fxp|ftp)(?:\[:\]|:)//[^\s\"'<>]+|"
               r"\b(?:hxxps?|https?|fxp|ftp)\[://\][^\s\"'<>]+", re.I),
    re.compile(rf"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:{_DOT}(?:25[0-5]|2[0-4]\d|1?\d?\d)){{3}}\b"),
    re.compile(r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b"),
    re.compile(rf"\b(?:[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?{_DOT})+[a-z]{{2,24}}\b", re.I),
]

# File extensions that the domain regex would otherwise mistake for TLDs.
_NOT_TLDS = {
    "exe", "dll", "txt", "pdf", "doc", "docx", "xls", "xlsx", "zip", "rar", "js",
    "ps1", "bat", "vbs", "png", "jpg", "jpeg", "gif", "html", "htm", "php", "py",
    "log", "csv", "json", "xml", "lnk", "iso", "msi", "tmp", "dat", "bin", "sh",
    "docm", "xlsm", "pptx", "ppt", "hta", "jar", "scr", "wsf", "cab", "gz", "tar", "eml", "msg",
}


def extract(text: str) -> list[IOC]:
    """Find every IOC in a block of text, deduplicated, in order of appearance."""
    found: list[tuple[int, IOC]] = []
    seen: set[IOC] = set()
    taken: list[tuple[int, int]] = []

    for pattern in _EXTRACT_PATTERNS:
        for m in pattern.finditer(text):
            start, end = m.span()
            # Skip matches inside an already-captured URL (its domain, path, etc.).
            if any(s <= start and end <= e for s, e in taken):
                continue
            ioc = parse(refang(m.group(0)).rstrip(".,;:)]"))
            if ioc is None:
                continue
            if ioc.type == IOCType.DOMAIN and ioc.value.rsplit(".", 1)[-1] in _NOT_TLDS:
                continue
            taken.append((start, end))
            if ioc not in seen:
                seen.add(ioc)
                found.append((start, ioc))

    return [ioc for _, ioc in sorted(found, key=lambda pair: pair[0])]
