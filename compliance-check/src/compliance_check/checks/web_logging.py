"""Web interface security (the mini-SIEM dashboard) and security logging."""

from __future__ import annotations

import ast
import re

from ..model import Result, Status, check
from ..repo import Repo, location


def _templates(repo: Repo) -> list[str]:
    return [f for f in repo.files if re.search(r"(^|/)templates/.+\.(html|jinja2?|j2)$", f)]


WEB_FRAMEWORKS = {"flask", "fastapi", "django", "starlette", "bottle"}


def _web_files(repo: Repo) -> list[str]:
    """Application modules that import a web framework."""
    found = []
    for rel in repo.source_files():
        tree = repo.asts.get(rel)
        if tree is None:
            continue
        for node in ast.walk(tree):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else \
                [node.module or ""] if isinstance(node, ast.ImportFrom) and node.level == 0 else []
            if any(n.split(".")[0] in WEB_FRAMEWORKS for n in names):
                found.append(rel)
                break
    return found


@check(
    "WEB-01", "Web pages escape untrusted data", "Web application",
    references={"NIS2": ["Art. 21(2)(e)"], "CRA": ["Annex I, Part I(2)(f)", "Annex I, Part I(2)(j)"],
                "ISO27001": ["A.8.28", "A.8.26"]},
    recommendation="Keep Jinja autoescaping on and avoid `|safe`, `Markup()` and `{% autoescape false %}` on log data.",
    severity="high", likelihood="likely",
)
def output_escaping(repo: Repo) -> Result:
    if not _web_files(repo):
        return Result(Status.NA, "No web application in the project.")
    risky = [f"{rel}:{n}: {line[:90]}" for rel, n, line in
             repo.grep(r"\|\s*safe\b|autoescape\s+false|Markup\(|render_template_string\(",
                       _templates(repo) + _web_files(repo))]
    if risky:
        return Result(Status.FAIL, "Some output bypasses HTML escaping (cross-site scripting risk).", risky)
    return Result(Status.PASS, f"{len(_templates(repo))} templates rely on Jinja autoescaping; no `|safe`, Markup() "
                               "or disabled autoescape.")


@check(
    "WEB-02", "Forms are protected against cross-site request forgery", "Web application",
    references={"NIS2": ["Art. 21(2)(e)", "Art. 21(2)(i)"], "CRA": ["Annex I, Part I(2)(d)", "Annex I, Part I(2)(f)"],
                "ISO27001": ["A.8.26", "A.8.28"]},
    recommendation="Add CSRF tokens to every POST form (e.g. Flask-WTF's CSRFProtect). Without them, any website "
                   "the analyst visits can send a hidden request to the dashboard on 127.0.0.1 and close alerts.",
    severity="medium", likelihood="possible",
)
def csrf_protection(repo: Repo) -> Result:
    if not _web_files(repo):
        return Result(Status.NA, "No web application in the project.")
    forms = [(rel, n) for rel, n, _ in repo.grep(r"<form[^>]*method\s*=\s*[\"']?post", _templates(repo))]
    if not forms:
        return Result(Status.NA, "The web interface has no state-changing forms.")
    protected = repo.grep(r"CSRFProtect|csrf_token|SeaSurf", _web_files(repo) + _templates(repo))
    if protected:
        return Result(Status.PASS, f"{len(forms)} POST form(s), CSRF protection in place.",
                      [f"{r}:{n}" for r, n, _ in protected[:5]])
    return Result(Status.FAIL, f"{len(forms)} POST form(s) without CSRF tokens.", [f"{r}:{n}" for r, n in forms])


@check(
    "WEB-03", "The web interface requires authentication", "Web application",
    references={"NIS2": ["Art. 21(2)(i)", "Art. 21(2)(j)"], "DORA": ["Art. 9"], "CRA": ["Annex I, Part I(2)(d)"],
                "ISO27001": ["A.8.5", "A.5.15", "A.8.3"], "GDPR": ["Art. 32"]},
    recommendation="Add a login (and MFA when exposed beyond one machine) before the dashboard is used by several "
                   "analysts or on a network. Until then, keep it bound to 127.0.0.1.",
    severity="high", likelihood="possible",
)
def authentication(repo: Repo) -> Result:
    files = _web_files(repo)
    if not files:
        return Result(Status.NA, "No web application in the project.")
    auth = repo.grep(r"login_required|LoginManager|flask_login|HTTPBasicAuth|auth_required|@requires_auth", files)
    if auth:
        return Result(Status.PASS, "The web routes are protected by authentication.", [f"{r}:{n}" for r, n, _ in auth[:5]])
    public = repo.grep(r"""default\s*=\s*["']0\.0\.0\.0["']|host\s*=\s*["']0\.0\.0\.0["']""", repo.source_files())
    local = repo.grep(r"""default\s*=\s*["']127\.0\.0\.1["']""", repo.source_files())
    if public:
        return Result(Status.FAIL, "No authentication, and the server listens on all network interfaces by default.",
                      [f"{r}:{n}: {line}" for r, n, line in public])
    return Result(Status.WARN, "No authentication on the dashboard. Risk is reduced because it listens on 127.0.0.1 "
                               "(this computer only) by default, and the README states this limitation.",
                  [f"{r}:{n}: {line}" for r, n, line in local])


@check(
    "WEB-04", "HTTP security headers are set", "Web application",
    references={"CRA": ["Annex I, Part I(2)(b)", "Annex I, Part I(2)(j)"], "ISO27001": ["A.8.26", "A.8.9"]},
    recommendation="Set Content-Security-Policy, X-Frame-Options (or frame-ancestors), X-Content-Type-Options and "
                   "Referrer-Policy in an @app.after_request hook, or use Flask-Talisman.",
    severity="low", likelihood="possible",
)
def security_headers(repo: Repo) -> Result:
    files = _web_files(repo)
    if not files:
        return Result(Status.NA, "No web application in the project.")
    found = repo.grep(r"Content-Security-Policy|X-Frame-Options|X-Content-Type-Options|Talisman", files)
    if found:
        return Result(Status.PASS, "Security headers are configured.", [f"{r}:{n}" for r, n, _ in found])
    return Result(Status.FAIL, "No Content-Security-Policy, X-Frame-Options or X-Content-Type-Options header is set.")


@check(
    "WEB-05", "Debug mode is off", "Web application",
    references={"CRA": ["Annex I, Part I(2)(b)"], "ISO27001": ["A.8.9", "A.8.31"]},
    recommendation="Never ship with debug=True: the Flask debugger allows remote code execution.",
    severity="high", likelihood="possible",
)
def debug_off(repo: Repo) -> Result:
    files = _web_files(repo)
    if not files:
        return Result(Status.NA, "No web application in the project.")
    bad, ok = [], []
    for rel in files:
        for node in ast.walk(repo.asts.get(rel, ast.Module(body=[], type_ignores=[]))):
            if isinstance(node, ast.keyword) and node.arg == "debug" and isinstance(node.value, ast.Constant):
                (bad if node.value.value is True else ok).append(f"{location(rel, node.value)}: debug={node.value.value}")
    bad += [f"{r}:{n}: {line}" for r, n, line in repo.grep(r"FLASK_DEBUG\s*=\s*1|DEBUG\s*=\s*True", files)]
    if bad:
        return Result(Status.FAIL, "Debug mode is enabled.", bad)
    return Result(Status.PASS, "Debug mode is explicitly disabled." if ok else "Debug mode is never enabled.", ok)


@check(
    "LOG-01", "Security-relevant actions are logged", "Logging & monitoring",
    references={"NIS2": ["Art. 21(2)(b)"], "DORA": ["Art. 10", "Art. 12"], "CRA": ["Annex I, Part I(2)(l)"],
                "ISO27001": ["A.8.15", "A.8.16"], "GDPR": ["Art. 32"]},
    recommendation="Log security events with Python's logging module, and keep an audit trail of analyst actions "
                   "(who changed which alert, when, from which status to which).",
    severity="medium", likelihood="possible",
)
def security_logging(repo: Repo) -> Result:
    users = [rel for rel in repo.source_files() if re.search(r"^\s*(import logging|from logging|import structlog)",
                                                              repo.text(rel), re.M)]
    audit = repo.grep(r"\baudit_(log|trail)s?\b|CREATE TABLE[^\n]*audit", repo.source_files())
    stores = [f for f in repo.source_files() if re.search(r"^\s*import sqlite3", repo.text(f), re.M)]
    timestamps = repo.grep(r"updated_at", stores)
    evidence = [f"uses logging: {u}" for u in users]
    if users and audit:
        return Result(Status.PASS, "The code logs events and keeps an audit trail.", evidence)
    if timestamps:
        evidence.append(f"{timestamps[0][0]}:{timestamps[0][1]}: only a last-modified timestamp is kept")
    if users:
        return Result(Status.WARN, f"{len(users)} module(s) use logging, but analyst actions have no audit trail.", evidence)
    return Result(Status.WARN, "The tools don't use a logging framework and keep no audit trail of who changed what. "
                               "Alerts only store a last-modified time.", evidence)
