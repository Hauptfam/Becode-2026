"""A read-only view of the repository being assessed: files, Python syntax trees, CI workflows, git history."""

from __future__ import annotations

import ast
import re
import subprocess
from functools import cached_property
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

import yaml

SKIP_DIRS = {".git", ".venv", "venv", "env", "__pycache__", ".pytest_cache", ".ruff_cache", "node_modules",
             "build", "dist", ".mypy_cache", ".tox"}
TEXT_SUFFIXES = {".py", ".md", ".txt", ".json", ".yml", ".yaml", ".toml", ".html", ".cfg", ".ini", ".example", ".env", ""}
MAX_TEXT_BYTES = 2_000_000


class Repo:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        if not self.root.is_dir():
            raise NotADirectoryError(self.root)

    # --- files ------------------------------------------------------------------------------

    @cached_property
    def is_git(self) -> bool:
        return self._git("rev-parse", "--is-inside-work-tree").strip() == "true"

    @cached_property
    def files(self) -> list[str]:
        """Files that are (or would be) published: tracked + untracked-but-not-ignored when in git."""
        if self.is_git:
            out = self._git("ls-files", "--cached", "--others", "--exclude-standard", "-z")
            names = [n for n in out.split("\0") if n]
            return sorted(n for n in names if (self.root / n).is_file())
        found = []
        for path in self.root.rglob("*"):
            rel = path.relative_to(self.root)
            if any(part in SKIP_DIRS or part.endswith(".egg-info") for part in rel.parts):
                continue
            if path.is_file():
                found.append(rel.as_posix())
        return sorted(found)

    def exists(self, rel: str) -> bool:
        return (self.root / rel).exists()

    def text(self, rel: str) -> str:
        path = self.root / rel
        if path.stat().st_size > MAX_TEXT_BYTES:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")

    def text_files(self) -> list[str]:
        return [f for f in self.files if Path(f).suffix.lower() in TEXT_SUFFIXES or Path(f).name.startswith(".")]

    def find(self, pattern: str) -> list[str]:
        regex = re.compile(pattern, re.IGNORECASE)
        return [f for f in self.files if regex.search(f)]

    def grep(self, pattern: str, files: list[str] | None = None, flags: int = re.IGNORECASE) -> list[tuple[str, int, str]]:
        """Return (file, line number, line) for every match."""
        regex = re.compile(pattern, flags)
        hits = []
        for rel in files if files is not None else self.text_files():
            try:
                lines = self.text(rel).splitlines()
            except OSError:
                continue
            for n, line in enumerate(lines, 1):
                if regex.search(line):
                    hits.append((rel, n, line.strip()))
        return hits

    # --- projects (folders with a pyproject.toml) ----------------------------------------------

    @cached_property
    def projects(self) -> dict[str, dict]:
        """Map project folder ('' for the root) -> parsed pyproject.toml."""
        found = {}
        for rel in self.files:
            if Path(rel).name != "pyproject.toml":
                continue
            parent = Path(rel).parent
            key = "" if parent == Path(".") else parent.as_posix()
            try:
                found[key] = tomllib.loads(self.text(rel))
            except tomllib.TOMLDecodeError:
                continue
        return found

    # --- Python code -----------------------------------------------------------------------------

    @cached_property
    def python_files(self) -> list[str]:
        return [f for f in self.files if f.endswith(".py")]

    @cached_property
    def asts(self) -> dict[str, ast.AST]:
        trees = {}
        for rel in self.python_files:
            try:
                trees[rel] = ast.parse(self.text(rel), filename=rel)
            except SyntaxError:
                continue
        return trees

    def source_files(self) -> list[str]:
        """Application code, i.e. Python files that are not tests."""
        return [f for f in self.python_files if not is_test_path(f)]

    def test_files(self) -> list[str]:
        return [f for f in self.python_files if is_test_path(f)]

    # --- CI ----------------------------------------------------------------------------------------

    @cached_property
    def workflows(self) -> dict[str, dict]:
        flows = {}
        for rel in self.find(r"^\.github/workflows/[^/]+\.ya?ml$"):
            try:
                data = yaml.safe_load(self.text(rel))
            except yaml.YAMLError:
                continue
            if isinstance(data, dict):
                flows[rel] = data
        return flows

    def workflow_steps(self) -> list[tuple[str, dict]]:
        steps = []
        for rel, flow in self.workflows.items():
            for job in (flow.get("jobs") or {}).values():
                for step in (job or {}).get("steps") or []:
                    if isinstance(step, dict):
                        steps.append((rel, step))
        return steps

    # --- git ---------------------------------------------------------------------------------------

    def _git(self, *args: str) -> str:
        try:
            proc = subprocess.run(["git", "-C", str(self.root), *args], capture_output=True, text=True,
                                  timeout=30, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return ""
        return proc.stdout if proc.returncode == 0 else ""

    @cached_property
    def head(self) -> str:
        return self._git("rev-parse", "--short", "HEAD").strip()

    @cached_property
    def branch(self) -> str:
        return self._git("rev-parse", "--abbrev-ref", "HEAD").strip()

    def git_log(self, *args: str) -> list[str]:
        return [line for line in self._git("log", *args).splitlines() if line.strip()]


def is_test_path(rel: str) -> bool:
    parts = Path(rel).parts
    name = Path(rel).name
    return "tests" in parts or "test" in parts or name.startswith("test_") or name == "conftest.py"


def location(rel: str, node: ast.AST | int) -> str:
    line = node if isinstance(node, int) else getattr(node, "lineno", 0)
    return f"{rel}:{line}"
