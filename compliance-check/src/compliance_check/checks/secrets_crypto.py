"""Secrets handling, encryption in transit and safe outbound connections."""

from __future__ import annotations

import ast
import re

from ..model import Result, Status, check
from ..repo import Repo, is_test_path, location

# Patterns are assembled from pieces so this file never matches itself.
_PRIVATE_KEY = "-----BEGIN " + r"(RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
SECRET_PATTERNS = {
    "private key": re.compile(_PRIVATE_KEY),
    "AWS access key": re.compile(r"\bA" + r"KIA[0-9A-Z]{16}\b"),
    "GitHub token": re.compile(r"\bgh" + r"[pousr]_[A-Za-z0-9]{36,}\b"),
    "Slack token": re.compile(r"\bxox" + r"[baprs]-[A-Za-z0-9-]{10,}\b"),
    "Google API key": re.compile(r"\bAI" + r"za[0-9A-Za-z_-]{35}\b"),
    "hard-coded credential": re.compile(
        r"""(?i)\b[\w-]*(api[_-]?key|secret|token|passw(or)?d|auth[_-]?key)[\w-]*\s*[:=]\s*["']([^"'\s]{12,})["']"""),
}
PLAIN_HTTP = re.compile(r"http://(?!localhost|127\.0\.0\.1|\[::1\])[\w.-]+\.(com|org|net|io|ch|eu)(/\S*)?")
PLACEHOLDER = re.compile(r"(?i)(example|dummy|test|fake|changeme|placeholder|your[_-]|xxx|offline|redacted|<|\$\{)")


@check(
    "SEC-01", "No secrets hard-coded in the repository", "Secrets & cryptography",
    references={
        "NIS2": ["Art. 21(2)(i)", "Art. 21(2)(e)"],
        "DORA": ["Art. 9"],
        "CRA": ["Annex I, Part I(2)(d)", "Annex I, Part I(2)(e)"],
        "ISO27001": ["A.5.17", "A.8.28"],
        "GDPR": ["Art. 32"],
    },
    recommendation="Remove the secret, rotate it immediately (it is in the git history), and load it from an "
                   "environment variable or a secrets manager instead. Add a secret scanner (e.g. gitleaks) to CI.",
    severity="high", likelihood="likely",
)
def no_hardcoded_secrets(repo: Repo) -> Result:
    hits = []
    for rel in repo.text_files():
        if rel.endswith(".example"):
            continue
        for n, line in enumerate(repo.text(rel).splitlines(), 1):
            for kind, pattern in SECRET_PATTERNS.items():
                m = pattern.search(line)
                if not m:
                    continue
                value = m.group(m.lastindex) if kind == "hard-coded credential" and m.lastindex else m.group(0)
                if kind == "hard-coded credential" and (PLACEHOLDER.search(value) or is_test_path(rel)):
                    continue
                hits.append(f"{rel}:{n}: possible {kind}")
    scanned = len(repo.text_files())
    if hits:
        return Result(Status.FAIL, f"{len(hits)} possible secret(s) found in {scanned} scanned files.", hits)
    return Result(Status.PASS, f"No API keys, tokens, passwords or private keys found in {scanned} scanned files.")


@check(
    "SEC-02", "Local secrets files are excluded from git", "Secrets & cryptography",
    references={
        "NIS2": ["Art. 21(2)(i)"],
        "CRA": ["Annex I, Part I(2)(d)"],
        "ISO27001": ["A.5.17", "A.8.9"],
        "GDPR": ["Art. 32"],
    },
    recommendation="Add `.env` to .gitignore and commit only a `.env.example` with empty values.",
    severity="high", likelihood="possible",
)
def env_files_ignored(repo: Repo) -> Result:
    ignore_rules = []
    for rel in repo.find(r"(^|/)\.gitignore$"):
        ignore_rules += [line.strip() for line in repo.text(rel).splitlines()]
    published_env = [f for f in repo.files if re.search(r"(^|/)\.env(\.[^/]*)?$", f) and not f.endswith(".example")]
    examples = repo.find(r"(^|/)\.env\.example$")
    evidence = [f"published: {f}" for f in published_env]
    leaking_examples = []
    for rel in examples:
        for n, line in enumerate(repo.text(rel).splitlines(), 1):
            key, _, value = line.partition("=")
            if value.strip() and not line.lstrip().startswith("#") and not PLACEHOLDER.search(value):
                leaking_examples.append(f"{rel}:{n}: {key.strip()} has a value")
    if published_env or leaking_examples:
        return Result(Status.FAIL, "Secrets files are published or example files contain values.",
                      evidence + leaking_examples)
    if ".env" not in ignore_rules:
        return Result(Status.WARN, "No .env file is published, but no .gitignore rule protects it either.")
    return Result(Status.PASS, f".env is in .gitignore, and {len(examples)} .env.example file(s) contain empty values only.",
                  [f"example: {e}" for e in examples])


def _calls(repo: Repo, files: list[str]):
    for rel in files:
        tree = repo.asts.get(rel)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                yield rel, node


def _call_name(node: ast.Call) -> str:
    func = node.func
    parts = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
    return ".".join(reversed(parts))


@check(
    "SEC-03", "Encrypted connections are never downgraded", "Secrets & cryptography",
    references={
        "NIS2": ["Art. 21(2)(h)", "Art. 21(2)(j)"],
        "DORA": ["Art. 9"],
        "CRA": ["Annex I, Part I(2)(e)", "Annex I, Part I(2)(f)"],
        "ISO27001": ["A.8.24", "A.5.14"],
        "GDPR": ["Art. 32"],
    },
    recommendation="Never pass verify=False; use HTTPS endpoints only and keep certificate validation on.",
    severity="high", likelihood="possible",
)
def tls_verification(repo: Repo) -> Result:
    bad = []
    for rel, node in _calls(repo, repo.source_files()):
        for kw in node.keywords:
            if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                bad.append(f"{location(rel, node)}: verify=False")
    plain_http = []
    for rel in repo.source_files():
        for node in ast.walk(repo.asts.get(rel, ast.Module(body=[], type_ignores=[]))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and \
                    PLAIN_HTTP.fullmatch(node.value):
                plain_http.append(f"{location(rel, node)}: {node.value}")
    if bad:
        return Result(Status.FAIL, "Certificate verification is disabled.", bad + plain_http)
    if plain_http:
        return Result(Status.WARN, "Some service endpoints use plain HTTP.", plain_http)
    return Result(Status.PASS, "Certificate verification is never disabled, and all service endpoints use HTTPS.")


@check(
    "SEC-04", "Outbound network calls have timeouts", "Secrets & cryptography",
    references={
        "NIS2": ["Art. 21(2)(e)"],
        "DORA": ["Art. 9"],
        "CRA": ["Annex I, Part I(2)(h)"],
        "ISO27001": ["A.8.28"],
    },
    recommendation="Pass an explicit timeout to every HTTP request so a slow third party cannot hang the tool.",
    severity="low", likelihood="possible",
)
def http_timeouts(repo: Repo) -> Result:
    methods = {"get", "post", "put", "delete", "patch", "head", "request", "urlopen"}
    calls, missing = 0, []
    for rel, node in _calls(repo, repo.source_files()):
        name = _call_name(node)
        last = name.rsplit(".", 1)[-1]
        if last not in methods or not re.search(r"(requests|session|urllib|urlopen|http)", name, re.I):
            continue
        calls += 1
        if not any(kw.arg == "timeout" for kw in node.keywords):
            missing.append(f"{location(rel, node)}: {name}() without timeout")
    if missing:
        return Result(Status.FAIL, f"{len(missing)} of {calls} HTTP call(s) have no timeout.", missing)
    if calls == 0:
        return Result(Status.NA, "The code makes no outbound HTTP calls.")
    return Result(Status.PASS, f"All {calls} outbound HTTP call site(s) set a timeout.")
