"""Secure development lifecycle: testing, static analysis, dangerous code patterns, change management."""

from __future__ import annotations

import ast
import re

from ..model import Result, Status, check
from ..repo import Repo, location

DEV_REFS = {
    "NIS2": ["Art. 21(2)(e)", "Art. 21(2)(f)"],
    "DORA": ["Art. 25"],
    "CRA": ["Annex I, Part II(3)"],
    "ISO27001": ["A.8.25", "A.8.29"],
}


def _ci_commands(repo: Repo) -> list[tuple[str, str]]:
    return [(rel, str(step.get("run", ""))) for rel, step in repo.workflow_steps() if step.get("run")]


@check(
    "DEV-01", "Automated tests run in CI", "Secure development", references=DEV_REFS,
    recommendation="Write automated tests and run them in CI on every push and pull request.",
    severity="medium", likelihood="possible",
)
def tests_in_ci(repo: Repo) -> Result:
    tests = 0
    for rel in repo.test_files():
        tree = repo.asts.get(rel)
        if tree is not None:
            tests += sum(1 for n in ast.walk(tree)
                         if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef) and n.name.startswith("test_"))
    runs = [f"{rel}: {cmd.strip()}" for rel, cmd in _ci_commands(repo) if re.search(r"\b(pytest|unittest|tox|nox)\b", cmd)]
    if tests and runs:
        return Result(Status.PASS, f"{tests} test functions in {len(repo.test_files())} files, run by "
                                   f"{len(runs)} CI step(s).", runs)
    if tests:
        return Result(Status.WARN, f"{tests} test functions exist but no CI workflow runs them.")
    return Result(Status.FAIL, "No automated tests found.")


@check(
    "DEV-02", "Static analysis (linting) runs in CI", "Secure development",
    references={"NIS2": ["Art. 21(2)(e)"], "CRA": ["Annex I, Part II(3)"], "ISO27001": ["A.8.28"]},
    recommendation="Run a linter such as ruff on every push.",
    severity="low", likelihood="possible",
)
def linting_in_ci(repo: Repo) -> Result:
    runs = [f"{rel}: {cmd.strip()}" for rel, cmd in _ci_commands(repo)
            if re.search(r"\b(ruff|flake8|pylint|mypy|pyright)\b", cmd)]
    if runs:
        return Result(Status.PASS, f"{len(runs)} CI step(s) run static analysis.", runs)
    return Result(Status.FAIL, "No linter or type checker runs in CI.")


@check(
    "DEV-03", "Security-focused code scanning is enabled", "Secure development",
    references={"NIS2": ["Art. 21(2)(e)"], "CRA": ["Annex I, Part I(2)(a)", "Annex I, Part II(3)"],
                "ISO27001": ["A.8.28", "A.8.29"]},
    recommendation="Enable ruff's security rules (add \"S\" to `select` in each pyproject.toml), or run bandit "
                   "or GitHub CodeQL in CI.",
    severity="medium", likelihood="possible",
)
def security_scanning(repo: Repo) -> Result:
    repo_wide = [f"{rel}: {cmd.strip()}" for rel, cmd in _ci_commands(repo) if re.search(r"\b(bandit|semgrep)\b", cmd)]
    repo_wide += [f"{rel}: {step['uses']}" for rel, step in repo.workflow_steps()
                  if "codeql" in str(step.get("uses", "")).lower()]
    if repo_wide:
        return Result(Status.PASS, "A security scanner runs in CI.", repo_wide)
    covered, missing = [], []
    for folder, data in repo.projects.items():
        select = data.get("tool", {}).get("ruff", {}).get("lint", {}).get("select", [])
        (covered if ("S" in select or "ALL" in select) else missing).append(folder or ".")
    if covered and not missing:
        return Result(Status.PASS, "ruff security rules (S) are enabled in every project.", covered)
    if covered:
        return Result(Status.WARN, f"Security rules are enabled in {', '.join(covered)} but not in {', '.join(missing)}.")
    return Result(Status.FAIL, "No security scanner (ruff S rules, bandit, semgrep, CodeQL) is configured.")


DANGEROUS = {
    "eval": "eval() runs arbitrary code", "exec": "exec() runs arbitrary code",
    "pickle.load": "unpickling untrusted data runs code", "pickle.loads": "unpickling untrusted data runs code",
    "marshal.loads": "unmarshalling untrusted data", "os.system": "runs a shell command",
    "os.popen": "runs a shell command", "tempfile.mktemp": "race-prone temporary file",
}


def _name(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


@check(
    "DEV-04", "No dangerous code patterns", "Secure development",
    references={"NIS2": ["Art. 21(2)(e)"], "CRA": ["Annex I, Part I(2)(j)", "Annex I, Part I(2)(k)"],
                "ISO27001": ["A.8.28"]},
    recommendation="Replace eval/exec, pickle, shell=True and unsafe YAML loading with safe alternatives "
                   "(ast.literal_eval, json, subprocess with a list of arguments, yaml.safe_load).",
    severity="high", likelihood="possible",
)
def dangerous_patterns(repo: Repo) -> Result:
    bad, reviewed = [], []
    for rel in repo.python_files:
        tree = repo.asts.get(rel)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _name(node.func)
            constant_args = all(isinstance(a, ast.Constant) for a in node.args) and not node.keywords
            if name in DANGEROUS:
                (reviewed if constant_args else bad).append(
                    f"{location(rel, node)}: {name}() "
                    f"{'with a constant argument' if constant_args else '- ' + DANGEROUS[name]}")
            if name == "yaml.load" and not any(
                    kw.arg == "Loader" and "Safe" in _name(kw.value) for kw in node.keywords):
                bad.append(f"{location(rel, node)}: yaml.load() without SafeLoader")
            if any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                   for kw in node.keywords):
                bad.append(f"{location(rel, node)}: subprocess call with shell=True")
    if bad:
        return Result(Status.FAIL, f"{len(bad)} dangerous call(s) with variable input.", bad + reviewed)
    note = f" {len(reviewed)} call(s) use only constant arguments (no injection possible)." if reviewed else ""
    return Result(Status.PASS, f"No eval/exec, pickle, unsafe YAML or shell injection patterns in "
                               f"{len(repo.python_files)} Python files.{note}", reviewed)


def _allow_listed_names(func: ast.AST) -> set[str]:
    """Names checked against a fixed list before use: `if name not in ("a", "b"): raise ...`."""
    names = set()
    for node in ast.walk(func):
        if isinstance(node, ast.If) and isinstance(node.test, ast.Compare) and isinstance(node.test.left, ast.Name) \
                and len(node.test.ops) == 1 and isinstance(node.test.ops[0], ast.NotIn) \
                and isinstance(node.test.comparators[0], ast.Tuple | ast.List | ast.Set) \
                and all(isinstance(e, ast.Constant) for e in node.test.comparators[0].elts) \
                and any(isinstance(b, ast.Raise | ast.Return) for b in node.body):
            names.add(node.test.left.id)
    return names


@check(
    "DEV-05", "Database queries are parameterised", "Secure development",
    references={"NIS2": ["Art. 21(2)(e)"], "CRA": ["Annex I, Part I(2)(f)", "Annex I, Part I(2)(j)"],
                "ISO27001": ["A.8.28"], "GDPR": ["Art. 32"]},
    recommendation="Review each query built with an f-string: values must go through `?` placeholders, and any "
                   "interpolated column or clause must come from a fixed allow-list, never from user input.",
    severity="high", likelihood="unlikely",
)
def sql_parameterised(repo: Repo) -> Result:
    dynamic, unsafe, safe = [], [], 0
    for rel in repo.source_files():
        tree = repo.asts.get(rel)
        if tree is None:
            continue
        functions = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)]
        for func in functions or [tree]:
            allowed = _allow_listed_names(func)
            for node in ast.walk(func):
                if not (isinstance(node, ast.Call) and node.args
                        and _name(node.func).rsplit(".", 1)[-1] in ("execute", "executemany", "executescript")):
                    continue
                query = node.args[0]
                if not (isinstance(query, ast.JoinedStr | ast.BinOp)
                        or (isinstance(query, ast.Call) and _name(query.func).endswith("format"))):
                    safe += 1
                    continue
                inserted = {n.id for v in ast.walk(query) if isinstance(v, ast.FormattedValue)
                            for n in ast.walk(v.value) if isinstance(n, ast.Name)}
                where = location(rel, node)
                if len(node.args) > 1:
                    dynamic.append(f"{where}: structure built dynamically, values passed as parameters")
                elif inserted and inserted <= allowed:
                    dynamic.append(f"{where}: inserts {', '.join(sorted(inserted))}, checked against a fixed allow-list")
                else:
                    unsafe.append(f"{where}: query built dynamically with no parameters")
    # A call found in a nested function is visited twice (once per enclosing scope): de-duplicate.
    dynamic, unsafe = sorted(set(dynamic)), sorted(set(unsafe))
    dynamic = [d for d in dynamic if d.split(":")[0] + ":" + d.split(":")[1] not in {u.rsplit(":", 1)[0] for u in unsafe}]
    if not (dynamic or unsafe or safe):
        return Result(Status.NA, "The code runs no SQL queries.")
    if unsafe:
        return Result(Status.FAIL, f"{len(unsafe)} dynamic quer(y/ies) without parameters or allow-list: possible SQL "
                                   "injection.", unsafe + dynamic)
    if dynamic:
        return Result(Status.WARN, f"No SQL injection found: {len(dynamic)} queries build their structure dynamically, but "
                                   "every value is passed as a parameter or checked against a fixed allow-list. A manual "
                                   "review of these lines is still advisable.", dynamic)
    return Result(Status.PASS, f"All {safe} queries are static strings with placeholders.")


@check(
    "DEV-06", "Errors are not silently swallowed", "Secure development",
    references={"CRA": ["Annex I, Part I(2)(l)"], "ISO27001": ["A.8.28", "A.8.15"]},
    recommendation="Replace bare `except:` and `except Exception: pass` with specific exceptions, and log what was ignored.",
    severity="low", likelihood="possible",
)
def no_silent_errors(repo: Repo) -> Result:
    bad = []
    for rel in repo.source_files():
        tree = repo.asts.get(rel)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                silent = len(node.body) == 1 and isinstance(node.body[0], ast.Pass)
                if node.type is None:
                    bad.append(f"{location(rel, node)}: bare except")
                elif silent and _name(node.type) in ("Exception", "BaseException"):
                    bad.append(f"{location(rel, node)}: except {_name(node.type)}: pass")
    if bad:
        return Result(Status.WARN, f"{len(bad)} place(s) hide all errors.", bad)
    return Result(Status.PASS, "No bare `except:` or silently ignored broad exceptions in application code.")


@check(
    "DEV-07", "Changes are reviewed through pull requests", "Secure development",
    references={"NIS2": ["Art. 21(2)(e)"], "DORA": ["Art. 9"], "CRA": ["Annex I, Part II(3)"],
                "ISO27001": ["A.8.32", "A.8.25"]},
    recommendation="Protect the main branch on GitHub (Settings > Branches): require a pull request and passing "
                   "CI before merging.",
    severity="medium", likelihood="possible",
)
def change_management(repo: Repo) -> Result:
    if not repo.is_git:
        return Result(Status.MANUAL, "Not a git checkout: change history cannot be verified.")
    merges = repo.git_log("--merges", "--first-parent", "--format=%s")
    prs = [m for m in merges if re.match(r"Merge pull request #\d+", m)]
    direct = repo.git_log("--no-merges", "--first-parent", "--format=%h %s")
    if prs:
        return Result(Status.PASS if len(direct) <= 2 else Status.WARN,
                      f"{len(prs)} change(s) merged through pull requests; {len(direct)} commit(s) pushed directly "
                      "to the main line. Branch protection itself can only be checked on GitHub.",
                      prs[:8] + [f"direct: {d}" for d in direct[:5]])
    return Result(Status.WARN, "No pull-request merges in the history: changes are pushed without review.",
                  [f"direct: {d}" for d in direct[:5]])
