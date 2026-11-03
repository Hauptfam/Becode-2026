"""Each check on small fake repositories: one that passes and one that fails."""

from __future__ import annotations

import pytest
from conftest import run_check

from compliance_check.model import Status

PYPROJECT = '[project]\nname = "app"\nversion = "1.0.0"\ndependencies = ["requests>=2.31"]\n'


def status(repo, check_id):
    return run_check(repo, check_id).status


# --- secrets & crypto ------------------------------------------------------------------------------

def test_secrets_detected_but_placeholders_ignored(repo_factory):
    fake_aws = "AK" + "IA" + "ABCDEFGHIJKLMNOP"   # built at runtime so this test file holds no secret
    repo = repo_factory({
        "app/config.py": f'AWS = "{fake_aws}"\napi_key = "s3cr3tvalue-0123456789"\nTOKEN = "your-token-here-xxx"\n',
    })
    finding = run_check(repo, "SEC-01")
    assert finding.status == Status.FAIL
    assert len(finding.evidence) == 2   # the placeholder is ignored
    assert all("config.py" in e for e in finding.evidence)


def test_no_secrets(repo_factory):
    assert status(repo_factory({"app/x.py": "API_KEY = os.getenv('API_KEY')\n"}), "SEC-01") == Status.PASS


def test_env_file_published(repo_factory):
    assert status(repo_factory({".env": "VT_API_KEY=abc\n", ".gitignore": ""}), "SEC-02") == Status.FAIL
    assert status(repo_factory({".gitignore": ".env\n", "a/.env.example": "VT_API_KEY=\n"}), "SEC-02") == Status.PASS


def test_tls_verification_disabled(repo_factory):
    assert status(repo_factory({"a.py": "requests.get(url, verify=False, timeout=5)\n"}), "SEC-03") == Status.FAIL


def test_http_timeouts(repo_factory):
    assert status(repo_factory({"a.py": "requests.get(url)\n"}), "SEC-04") == Status.FAIL
    assert status(repo_factory({"a.py": "requests.get(url, timeout=5)\n"}), "SEC-04") == Status.PASS
    assert status(repo_factory({"a.py": "print(1)\n"}), "SEC-04") == Status.NA


# --- supply chain -----------------------------------------------------------------------------------

def test_dependencies_declared(repo_factory):
    assert status(repo_factory({"app/pyproject.toml": PYPROJECT}), "SC-01") == Status.WARN   # no lock file
    unversioned = PYPROJECT.replace("requests>=2.31", "requests")
    assert status(repo_factory({"app/pyproject.toml": unversioned}), "SC-01") == Status.FAIL


def test_dependabot(repo_factory):
    assert status(repo_factory({"x.py": ""}), "SC-04") == Status.FAIL
    assert status(repo_factory({".github/dependabot.yml": "version: 2\n"}), "SC-04") == Status.PASS


WORKFLOW = """
name: ci
on: [push]
{permissions}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: {uses}
      - run: pytest -v
      - run: ruff check .
"""


@pytest.mark.parametrize(("uses", "expected"), [
    ("actions/checkout@v4", Status.WARN),
    ("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683", Status.PASS),
])
def test_actions_pinned(repo_factory, uses, expected):
    repo = repo_factory({".github/workflows/ci.yml": WORKFLOW.format(permissions="", uses=uses)})
    assert status(repo, "SC-05") == expected


def test_workflow_permissions(repo_factory):
    without = repo_factory({".github/workflows/ci.yml": WORKFLOW.format(permissions="", uses="a/b@v1")})
    assert status(without, "SC-06") == Status.FAIL


def test_workflow_permissions_set(repo_factory):
    flow = WORKFLOW.format(permissions="permissions:\n  contents: read", uses="a/b@v1")
    assert status(repo_factory({".github/workflows/ci.yml": flow}), "SC-06") == Status.PASS


def test_vulnerabilities_offline_is_manual(repo_factory):
    assert status(repo_factory({"app/pyproject.toml": PYPROJECT}), "SC-03") == Status.MANUAL


# --- secure development --------------------------------------------------------------------------------

def test_tests_and_linting_in_ci(repo_factory):
    repo = repo_factory({"tests/test_a.py": "def test_x():\n    assert True\n",
                         ".github/workflows/ci.yml": WORKFLOW.format(permissions="", uses="a/b@v1")})
    assert status(repo, "DEV-01") == Status.PASS
    assert status(repo, "DEV-02") == Status.PASS
    assert status(repo_factory({"tests/test_a.py": "def test_x():\n    pass\n"}), "DEV-01") in (Status.WARN, Status.PASS)


def test_security_scanning_must_cover_every_project(repo_factory):
    secure = PYPROJECT + '[tool.ruff.lint]\nselect = ["E", "S"]\n'
    assert status(repo_factory({"a/pyproject.toml": secure}), "DEV-03") == Status.PASS
    assert status(repo_factory({"a/pyproject.toml": secure, "b/pyproject.toml": PYPROJECT}), "DEV-03") == Status.WARN
    assert status(repo_factory({"a/pyproject.toml": PYPROJECT}), "DEV-03") == Status.FAIL


def test_dangerous_patterns(repo_factory):
    assert status(repo_factory({"a.py": "eval(user_input)\n"}), "DEV-04") == Status.FAIL
    assert status(repo_factory({"a.py": "import yaml\nyaml.load(text)\n"}), "DEV-04") == Status.FAIL
    assert status(repo_factory({"a.py": "subprocess.run(cmd, shell=True)\n"}), "DEV-04") == Status.FAIL
    constant = run_check(repo_factory({"a.py": "import os\nos.system('')\n"}), "DEV-04")
    assert constant.status == Status.PASS and "constant" in constant.evidence[0]


SQL_UNSAFE = '''
def find(conn, name):
    return conn.execute(f"SELECT * FROM users WHERE name = '{name}'")
'''
SQL_ALLOWLIST = '''
def distinct(conn, column):
    if column not in ("source", "host"):
        raise ValueError(column)
    return conn.execute(f"SELECT DISTINCT {column} FROM events")
'''
SQL_PARAMS = '''
def find(conn, clause, value):
    return conn.execute(f"SELECT * FROM t {clause}", [value])
'''


@pytest.mark.parametrize(("code", "expected"), [
    (SQL_UNSAFE, Status.FAIL),
    (SQL_ALLOWLIST, Status.WARN),
    (SQL_PARAMS, Status.WARN),
    ('def f(c):\n    c.execute("SELECT * FROM t WHERE id = ?", [1])\n', Status.PASS),
])
def test_sql(repo_factory, code, expected):
    assert status(repo_factory({"app/db.py": code}), "DEV-05") == expected


def test_silent_errors(repo_factory):
    assert status(repo_factory({"a.py": "try:\n    x()\nexcept:\n    pass\n"}), "DEV-06") == Status.WARN


# --- web --------------------------------------------------------------------------------------------------

FLASK_APP = "from flask import Flask\napp = Flask(__name__)\n"
FORM = '<form method="post" action="/x"><button>go</button></form>'


def test_web_checks_skip_projects_without_web_framework(repo_factory):
    repo = repo_factory({"a.py": "# mentions Flask and |safe in a comment only\n"})
    for check_id in ("WEB-01", "WEB-02", "WEB-03", "WEB-04", "WEB-05"):
        assert status(repo, check_id) == Status.NA, check_id


def test_escaping(repo_factory):
    assert status(repo_factory({"app/web.py": FLASK_APP, "app/templates/a.html": "{{ x|safe }}"}), "WEB-01") == Status.FAIL
    assert status(repo_factory({"app/web.py": FLASK_APP, "app/templates/a.html": "{{ x }}"}), "WEB-01") == Status.PASS


def test_csrf(repo_factory):
    assert status(repo_factory({"app/web.py": FLASK_APP, "app/templates/a.html": FORM}), "WEB-02") == Status.FAIL
    protected = FORM.replace("<button>", '<input name="csrf_token" value="{{ csrf_token() }}"><button>')
    assert status(repo_factory({"app/web.py": FLASK_APP, "app/templates/a.html": protected}), "WEB-02") == Status.PASS


def test_authentication(repo_factory):
    public = FLASK_APP + 'p.add_argument("--host", default="0.0.0.0")\n'
    local = FLASK_APP + 'p.add_argument("--host", default="127.0.0.1")\n'
    assert status(repo_factory({"app/web.py": public}), "WEB-03") == Status.FAIL
    assert status(repo_factory({"app/web.py": local}), "WEB-03") == Status.WARN
    with_login = FLASK_APP + "from flask_login import login_required\n"
    assert status(repo_factory({"app/web.py": with_login}), "WEB-03") == Status.PASS


def test_debug(repo_factory):
    assert status(repo_factory({"app/web.py": FLASK_APP + "app.run(debug=True)\n"}), "WEB-05") == Status.FAIL
    assert status(repo_factory({"app/web.py": FLASK_APP + "app.run(debug=False)\n"}), "WEB-05") == Status.PASS


# --- personal data -------------------------------------------------------------------------------------------

PARSER = 'def parse(r):\n    return {"user": r.get("user"), "ip": r["client_ip"]}\nimport sqlite3\n'


def test_personal_data_documentation(repo_factory):
    files = {"siem/pyproject.toml": PYPROJECT, "siem/src/p.py": PARSER, "siem/README.md": "# SIEM\n"}
    assert status(repo_factory(files), "PRIV-01") == Status.FAIL
    files["siem/README.md"] = "# SIEM\n## Privacy & personal data\nWe store usernames.\n"
    assert status(repo_factory(files), "PRIV-01") == Status.PASS


def test_no_personal_data_means_not_applicable(repo_factory):
    assert status(repo_factory({"app/pyproject.toml": PYPROJECT, "app/a.py": "x = 1\n"}), "PRIV-01") == Status.NA


def test_retention(repo_factory):
    files = {"siem/pyproject.toml": PYPROJECT, "siem/src/p.py": PARSER}
    assert status(repo_factory(files), "PRIV-03") == Status.FAIL
    files["siem/src/purge.py"] = 'def purge(c, days):\n    c.execute("DELETE FROM events WHERE ts < ?", [days])\n'
    assert status(repo_factory(files), "PRIV-03") == Status.PASS


def test_test_data_must_use_reserved_domains(repo_factory):
    good = repo_factory({"tests/data/a.json": '{"from": "a@corp.example", "url": "https://cdn.x.net/jquery@3.7.1/a.js"}'})
    assert status(good, "PRIV-04") == Status.PASS
    bad = repo_factory({"tests/data/a.json": '{"from": "jane.doe@gmail.com"}'})
    assert status(bad, "PRIV-04") == Status.FAIL


# --- documentation, risk, AI -------------------------------------------------------------------------------------

def test_security_policy(repo_factory):
    assert status(repo_factory({"README.md": "# x"}), "DOC-02") == Status.FAIL
    assert status(repo_factory({"SECURITY.md": "Report a vulnerability to sec@x.example"}), "DOC-02") == Status.PASS


def test_risk_assessment(repo_factory):
    assert status(repo_factory({"README.md": "# x"}), "RISK-01") == Status.FAIL
    assert status(repo_factory({"docs/THREAT_MODEL.md": "# Threats"}), "RISK-01") == Status.PASS


def test_ai_detection(repo_factory):
    assert status(repo_factory({"a.py": "import json\n"}), "AI-01") == Status.NA
    assert status(repo_factory({"a.py": "from sklearn.ensemble import IsolationForest\n"}), "AI-01") == Status.MANUAL
    assert status(repo_factory({"models/model.onnx": "x"}), "AI-01") == Status.MANUAL


def test_broken_check_becomes_manual(repo_factory, monkeypatch):
    from compliance_check.model import REGISTRY

    spec = next(s for s in REGISTRY if s.id == "SEC-01")
    monkeypatch.setattr(spec, "func", lambda repo: 1 / 0)
    finding = spec.run(repo_factory({"a.py": ""}))
    assert finding.status == Status.MANUAL and "could not run" in finding.summary


def test_support_period_needs_a_real_statement(repo_factory):
    mention = repo_factory({"README.md": "| Docs | READMEs, SECURITY.md, support period, change log |\n"})
    assert status(mention, "DOC-03") == Status.FAIL
    assert status(repo_factory({"SECURITY.md": "## Supported versions\nOnly 1.x\n"}), "DOC-03") == Status.PASS
    assert status(repo_factory({"README.md": "Security updates until December 2027.\n"}), "DOC-03") == Status.PASS
