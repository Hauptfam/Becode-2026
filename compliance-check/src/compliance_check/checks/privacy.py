"""Personal data protection (GDPR) and data resilience, assessed per project."""

from __future__ import annotations

import ast
import re

from ..model import Result, Status, check
from ..repo import Repo

PERSONAL_FIELDS = {"email", "sender", "recipient", "user", "username", "client_ip", "src_ip", "hostname", "client"}
RESERVED_DOMAIN = re.compile(r"(\.(example|test|invalid|localhost)|(^|\.)example\.(com|net|org))$", re.I)
EMAIL = re.compile(r"\b[\w.+-]+@((?:[\w-]+\.)+[A-Za-z]{2,})\b")


def project_of(repo: Repo, rel: str) -> str | None:
    best = None
    for folder in repo.projects:
        if folder == "" or rel.startswith(folder + "/"):
            if best is None or len(folder) > len(best):
                best = folder
    return best


def _imports(tree: ast.AST) -> set[str]:
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".")[0])
    return names


def personal_data_projects(repo: Repo) -> dict[str, set[str]]:
    """Projects whose application code reads personal-data fields from records: {project: fields}."""
    found: dict[str, set[str]] = {}
    for rel in repo.source_files():
        tree = repo.asts.get(rel)
        project = project_of(repo, rel)
        if tree is None or project is None:
            continue
        for node in ast.walk(tree):
            key = None
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get" \
                    and node.args and isinstance(node.args[0], ast.Constant):
                key = node.args[0].value
            elif isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
                key = node.slice.value
            if isinstance(key, str) and key in PERSONAL_FIELDS:
                found.setdefault(project, set()).add(key)
    return found


def project_imports(repo: Repo, project: str) -> set[str]:
    names: set[str] = set()
    for rel in repo.source_files():
        if project_of(repo, rel) == project and rel in repo.asts:
            names |= _imports(repo.asts[rel])
    return names


def readme(repo: Repo, project: str) -> str:
    rel = f"{project}/README.md" if project else "README.md"
    return repo.text(rel) if repo.exists(rel) else ""


def label(project: str) -> str:
    return project or "(root)"


@check(
    "PRIV-01", "Personal data processing is documented", "Personal data (GDPR)",
    references={"GDPR": ["Art. 5(1)(a)", "Art. 13", "Art. 30"], "CRA": ["Annex II"], "ISO27001": ["A.5.34"],
                "NIS2": ["Art. 21(2)(a)"]},
    recommendation="Add a 'Privacy & personal data' section to each such README: which personal data the tool "
                   "processes (usernames, email addresses, IPs, hostnames), why, where it is stored, for how long, "
                   "and which third parties receive any of it. A SOC using it typically relies on legitimate interest "
                   "(GDPR Art. 6(1)(f), Recital 49: network and information security).",
    severity="medium", likelihood="likely",
)
def personal_data_documented(repo: Repo) -> Result:
    projects = personal_data_projects(repo)
    if not projects:
        return Result(Status.NA, "No application code reads personal-data fields.")
    heading = re.compile(r"^#+.*(privacy|personal data|gdpr|data protection|rgpd)", re.I | re.M)
    missing = [p for p in projects if not heading.search(readme(repo, p))]
    evidence = [f"{label(p)} reads: {', '.join(sorted(f))}" for p, f in projects.items()]
    if missing:
        return Result(Status.FAIL, f"{len(projects)} project(s) process personal data; {len(missing)} don't document it: "
                                   f"{', '.join(label(m) for m in missing)}.", evidence)
    return Result(Status.PASS, "Every project that processes personal data documents it.", evidence)


@check(
    "PRIV-02", "Internal data is filtered before third-party lookups", "Personal data (GDPR)",
    references={"GDPR": ["Art. 5(1)(c)", "Art. 25", "Art. 44"], "CRA": ["Annex I, Part I(2)(g)"],
                "ISO27001": ["A.5.14", "A.8.12"], "NIS2": ["Art. 21(2)(d)"]},
    recommendation="Filter internal IP addresses, hostnames and user identifiers out of anything sent to external "
                   "threat-intelligence services.",
    severity="high", likelihood="possible",
)
def minimisation_before_sharing(repo: Repo) -> Result:
    projects = personal_data_projects(repo)
    sharing = [p for p in projects if project_imports(repo, p) & {"requests", "httpx", "urllib3", "ioc_enricher"}]
    if not sharing:
        return Result(Status.NA, "No project sends personal data to external services.")
    evidence, missing = [], []
    for p in sharing:
        hits = [(r, n) for r, n, _ in repo.grep(r"is_private|is_global|is_private_ip|private_ip",
                                                 [f for f in repo.source_files() if project_of(repo, f) == p])]
        if hits:
            evidence += [f"{label(p)}: {r}:{n}" for r, n in hits[:4]]
        else:
            missing.append(label(p))
    if missing:
        return Result(Status.FAIL, f"No filtering of internal addresses before external lookups in: {', '.join(missing)}.")
    return Result(Status.PASS, "Private and internal IP addresses are filtered out before any external lookup, and the "
                               "tests verify that none is ever sent.", evidence)


@check(
    "PRIV-03", "Stored personal data has a retention limit", "Personal data (GDPR)",
    references={"GDPR": ["Art. 5(1)(e)", "Art. 17"], "CRA": ["Annex I, Part I(2)(m)"], "ISO27001": ["A.8.10"],
                "NIS2": ["Art. 21(2)(a)"]},
    recommendation="Add a retention setting and a purge command (e.g. `mini-siem purge --older-than 90d`) that "
                   "deletes old events, alerts and IOC results, and document the default retention period.",
    severity="medium", likelihood="likely",
)
def retention(repo: Repo) -> Result:
    storing = [p for p in personal_data_projects(repo) if project_imports(repo, p) & {"sqlite3", "sqlalchemy", "pymongo"}]
    if not storing:
        return Result(Status.NA, "No project stores personal data in a database.")
    missing, evidence = [], []
    for p in storing:
        files = [f for f in repo.source_files() if project_of(repo, f) == p]
        hits = repo.grep(r"retention|purge|older[_ -]than|DELETE FROM \w+ WHERE \w*(ts|time|date)\w* <", files)
        reset = repo.grep(r"DELETE FROM", files)
        if hits:
            evidence += [f"{r}:{n}" for r, n, _ in hits[:3]]
        else:
            missing.append(label(p))
            if reset:
                evidence.append(f"{label(p)}: data can only be deleted all at once ({reset[0][0]}:{reset[0][1]})")
    if missing:
        return Result(Status.FAIL, f"Personal data is kept indefinitely in: {', '.join(missing)}.", evidence)
    return Result(Status.PASS, "Stored data has a retention mechanism.", evidence)


@check(
    "PRIV-04", "Test and demo data contain no real personal data", "Personal data (GDPR)",
    references={"GDPR": ["Art. 5(1)(c)", "Art. 25"], "ISO27001": ["A.8.33", "A.8.11"]},
    recommendation="Use reserved domains (.example, .test, example.com) and invented names in test data, or "
                   "anonymise real samples before committing them.",
    severity="medium", likelihood="unlikely",
)
def fictional_test_data(repo: Repo) -> Result:
    data_files = [f for f in repo.files if re.search(r"(^|/)(data|tests?|examples|fixtures)/", f)
                  and f.endswith((".json", ".txt", ".csv", ".log", ".eml", ".yml", ".yaml"))]
    if not data_files:
        return Result(Status.NA, "No test or demo data files.")
    emails, real = set(), []
    for rel in data_files:
        for n, line in enumerate(repo.text(rel).splitlines(), 1):
            for m in EMAIL.finditer(line):
                emails.add(m.group(0).lower())
                if not RESERVED_DOMAIN.search(m.group(1)):
                    real.append(f"{rel}:{n}: {m.group(0)}")
    disclaimers = [r for r, _, _ in repo.grep(r"fictional|invented|made up", data_files)]
    evidence = [f"{len(data_files)} data files, {len(emails)} distinct email addresses, all on reserved domains"
                if not real else f"{len(real)} address(es) on real domains"]
    evidence += [f"marked as fictional: {d}" for d in sorted(set(disclaimers))[:5]]
    if real:
        return Result(Status.FAIL, "Test data contains email addresses on real domains.", real + evidence)
    return Result(Status.PASS, "Test and demo data use reserved domains only and are marked as fictional.", evidence)


@check(
    "PRIV-05", "Stored personal data is encrypted at rest", "Personal data (GDPR)",
    references={"GDPR": ["Art. 32"], "NIS2": ["Art. 21(2)(h)"], "DORA": ["Art. 9"], "CRA": ["Annex I, Part I(2)(e)"],
                "ISO27001": ["A.8.24", "A.5.33"]},
    recommendation="Store the database on an encrypted disk (BitLocker / FileVault / LUKS) and document it, or use "
                   "SQLCipher for application-level encryption.",
    severity="medium", likelihood="unlikely",
)
def encryption_at_rest(repo: Repo) -> Result:
    storing = [p for p in personal_data_projects(repo) if project_imports(repo, p) & {"sqlite3", "sqlalchemy"}]
    if not storing:
        return Result(Status.NA, "No project stores personal data in a database.")
    hits = repo.grep(r"sqlcipher|PRAGMA key|cryptography\.fernet|encrypt", [f for f in repo.source_files()
                                                                            if project_of(repo, f) in storing])
    if hits:
        return Result(Status.PASS, "Stored data is encrypted.", [f"{r}:{n}" for r, n, _ in hits[:3]])
    return Result(Status.WARN, f"{', '.join(label(p) for p in storing)} store(s) events with usernames, email addresses "
                               "and IPs in a plain SQLite file. Acceptable on an encrypted laptop disk, but not documented.")


@check(
    "PRIV-06", "Third-party data recipients are disclosed", "Personal data (GDPR)",
    references={"GDPR": ["Art. 13(1)(e)", "Art. 28", "Art. 44"], "NIS2": ["Art. 21(2)(d)"], "DORA": ["Art. 28"],
                "ISO27001": ["A.5.19", "A.5.14"]},
    recommendation="List each external service (VirusTotal, AbuseIPDB, URLhaus, RDAP), what is sent to it, where it is "
                   "based, and that VirusTotal shares submissions with its users. Organisations need a legal basis and, "
                   "for transfers outside the EU, a transfer mechanism (GDPR Chapter V).",
    severity="medium", likelihood="possible",
)
def recipients_disclosed(repo: Repo) -> Result:
    senders = [p for p in repo.projects if project_imports(repo, p) & {"requests", "httpx"}
               and repo.grep(r"https://[\w.-]*(virustotal\.com|abuseipdb\.com|abuse\.ch|shodan\.io|otx\.alienvault)",
                             [f for f in repo.source_files() if project_of(repo, f) == p])]
    if not senders:
        return Result(Status.NA, "No project sends indicators to external threat-intelligence services.")
    weak, evidence = [], []
    for p in senders:
        text = readme(repo, p)
        names = [n for n in ("VirusTotal", "AbuseIPDB", "URLhaus", "RDAP") if n.lower() in text.lower()]
        warned = re.search(r"sensitive|personal data|confidential", text, re.I)
        evidence.append(f"{label(p)}: README names {', '.join(names) or 'no services'}; "
                        f"{'warns against sending sensitive data' if warned else 'no data warning'}")
        if not (names and warned):
            weak.append(p)
    if weak:
        return Result(Status.FAIL, "External data recipients are not disclosed.", evidence)
    return Result(Status.WARN, "The README names every external service and warns against submitting sensitive data, "
                               "but doesn't say what each receives, where it is based, or how long it keeps it.", evidence)


@check(
    "RES-01", "Stored data can be backed up and restored", "Resilience",
    references={"NIS2": ["Art. 21(2)(c)"], "DORA": ["Art. 11", "Art. 12"], "CRA": ["Annex I, Part I(2)(h)"],
                "ISO27001": ["A.8.13"], "GDPR": ["Art. 32"]},
    recommendation="Add an export/backup command (SQLite's online backup API) and document how to restore it.",
    severity="low", likelihood="possible",
)
def backup(repo: Repo) -> Result:
    storing = [p for p in repo.projects if project_imports(repo, p) & {"sqlite3", "sqlalchemy"}]
    if not storing:
        return Result(Status.NA, "No project keeps persistent data.")
    files = [f for f in repo.source_files() if project_of(repo, f) in storing]
    hits = repo.grep(r"\.backup\(|def (cmd_)?(backup|export)", files)
    if hits:
        return Result(Status.PASS, "A backup or export function exists.", [f"{r}:{n}" for r, n, _ in hits[:3]])
    return Result(Status.WARN, f"{', '.join(label(p) for p in storing)} keep(s) alerts and analyst notes in one SQLite "
                               "file with no backup or export command. The logs can be re-ingested, but triage work "
                               "would be lost.")
