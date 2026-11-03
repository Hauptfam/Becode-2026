"""Third-party components, vulnerability management and CI/CD supply-chain hygiene."""

from __future__ import annotations

import re

from ..model import Result, Status, check
from ..repo import Repo
from ..sbom import components, osv_query

SHA_PIN = re.compile(r"@[0-9a-f]{40}$")


@check(
    "SC-01", "Third-party dependencies are declared with versions", "Supply chain",
    references={
        "NIS2": ["Art. 21(2)(d)"],
        "DORA": ["Art. 8", "Art. 28"],
        "CRA": ["Annex I, Part II(1)"],
        "ISO27001": ["A.5.21", "A.8.9"],
    },
    recommendation="Declare every dependency in pyproject.toml with a minimum version, and use a lock file "
                   "(e.g. pip-tools or uv) for reproducible builds.",
    severity="medium", likelihood="possible",
)
def dependencies_declared(repo: Repo) -> Result:
    if not repo.projects:
        return Result(Status.FAIL, "No pyproject.toml found: dependencies are not declared.")
    evidence, unversioned = [], []
    for folder, data in repo.projects.items():
        deps = data.get("project", {}).get("dependencies", [])
        for dep in deps:
            if not re.search(r"[<>=~!]", dep):
                unversioned.append(f"{folder or '.'}/pyproject.toml: {dep}")
        evidence.append(f"{folder or '.'}: {len(deps)} runtime dependencies ({', '.join(deps) or 'none'})")
    locks = repo.find(r"(requirements.*\.txt|\.lock|poetry\.lock|uv\.lock)$")
    if unversioned:
        return Result(Status.FAIL, "Some dependencies have no version constraint.", unversioned + evidence)
    if not locks:
        return Result(Status.WARN, f"{len(repo.projects)} project(s) declare all dependencies with minimum versions, "
                                   "but there is no lock file pinning exact versions.", evidence)
    return Result(Status.PASS, "All dependencies are declared with versions and locked.", evidence + locks)


@check(
    "SC-02", "A software bill of materials (SBOM) is available", "Supply chain",
    references={
        "NIS2": ["Art. 21(2)(d)"],
        "DORA": ["Art. 8"],
        "CRA": ["Annex I, Part II(1)", "Annex VII"],
        "ISO27001": ["A.5.9", "A.5.21"],
    },
    recommendation="Generate a CycloneDX or SPDX SBOM in CI for every release (this tool writes one with --sbom) "
                   "and publish it with the release.",
    severity="medium", likelihood="possible",
)
def sbom_available(repo: Repo) -> Result:
    committed = repo.find(r"(sbom|bom)[^/]*\.(json|xml|spdx)$|\.cdx\.json$|\.spdx(\.json)?$")
    count = sum(len(c) for c in components(repo).values())
    if committed:
        return Result(Status.PASS, "An SBOM is published in the repository.", committed)
    return Result(Status.WARN, f"No SBOM is published. This report lists the {count} declared component(s) "
                               "in the appendix, and `--sbom` writes a CycloneDX file.")


@check(
    "SC-03", "Dependencies have no known vulnerabilities", "Supply chain",
    references={
        "NIS2": ["Art. 21(2)(e)"],
        "DORA": ["Art. 9", "Art. 10"],
        "CRA": ["Annex I, Part I(2)(a)", "Annex I, Part II(2)"],
        "ISO27001": ["A.8.8"],
        "ISO27005": ["7.2"],
    },
    recommendation="Run this check with --online (queries the OSV.dev database), or add pip-audit to CI, and "
                   "upgrade any vulnerable dependency.",
    severity="high", likelihood="possible",
)
def known_vulnerabilities(repo: Repo) -> Result:
    if not getattr(repo, "online", False):
        return Result(Status.MANUAL, "Not checked: the scan ran offline. Use --online to query the OSV.dev "
                                     "vulnerability database for every installed dependency version.")
    comps = [c for items in components(repo).values() for c in items if c.get("version")]
    vulns = osv_query(comps)
    if vulns is None:
        return Result(Status.MANUAL, "The OSV.dev database could not be reached.")
    if vulns:
        return Result(Status.FAIL, f"{len(vulns)} known vulnerabilit(y/ies) in installed dependencies.", vulns)
    return Result(Status.PASS, f"No known vulnerabilities in the {len(comps)} installed dependency versions (OSV.dev).")


@check(
    "SC-04", "Dependency updates are automated", "Supply chain",
    references={
        "NIS2": ["Art. 21(2)(e)"],
        "DORA": ["Art. 9"],
        "CRA": ["Annex I, Part II(2)", "Annex I, Part I(2)(c)"],
        "ISO27001": ["A.8.8"],
    },
    recommendation="Add .github/dependabot.yml (ecosystems: pip for each project folder, and github-actions) "
                   "so vulnerable dependencies get update pull requests automatically.",
    severity="medium", likelihood="likely",
)
def dependency_updates(repo: Repo) -> Result:
    configs = repo.find(r"^\.github/dependabot\.ya?ml$|(^|/)renovate\.json5?$|^\.renovaterc")
    if configs:
        return Result(Status.PASS, "Automated dependency updates are configured.", configs)
    return Result(Status.FAIL, "No Dependabot or Renovate configuration: outdated or vulnerable dependencies "
                               "are only found if someone looks.")


@check(
    "SC-05", "CI uses third-party actions pinned to a commit", "Supply chain",
    references={
        "NIS2": ["Art. 21(2)(d)"],
        "DORA": ["Art. 28"],
        "CRA": ["Annex I, Part I(2)(f)"],
        "ISO27001": ["A.5.21", "A.8.32"],
    },
    recommendation="Pin each `uses:` to a full commit SHA (with the version in a comment), and let Dependabot "
                   "update them. A moved tag would otherwise run new code in CI without review.",
    severity="medium", likelihood="unlikely",
)
def actions_pinned(repo: Repo) -> Result:
    uses = [(rel, step["uses"]) for rel, step in repo.workflow_steps() if "uses" in step]
    if not uses:
        return Result(Status.NA, "No CI workflows use third-party actions.")
    unpinned = sorted({f"{rel}: {u}" for rel, u in uses if not SHA_PIN.search(u) and not u.startswith("./")})
    if unpinned:
        return Result(Status.WARN, f"{len(unpinned)} action reference(s) use a movable tag instead of a commit SHA.",
                      unpinned)
    return Result(Status.PASS, f"All {len(uses)} action references are pinned to a commit SHA.")


@check(
    "SC-06", "CI jobs run with least-privilege tokens", "Supply chain",
    references={
        "NIS2": ["Art. 21(2)(i)"],
        "DORA": ["Art. 9"],
        "CRA": ["Annex I, Part I(2)(j)"],
        "ISO27001": ["A.8.2", "A.5.15"],
    },
    recommendation="Add `permissions: contents: read` at the top of each workflow, and grant more only to the "
                   "jobs that need it.",
    severity="medium", likelihood="unlikely",
)
def workflow_permissions(repo: Repo) -> Result:
    if not repo.workflows:
        return Result(Status.NA, "No CI workflows found.")
    missing = []
    for rel, flow in repo.workflows.items():
        jobs = flow.get("jobs") or {}
        if "permissions" not in flow and not all("permissions" in (job or {}) for job in jobs.values()):
            missing.append(f"{rel}: no `permissions:` block (the token gets the repository default)")
    if missing:
        return Result(Status.FAIL, f"{len(missing)} of {len(repo.workflows)} workflow(s) don't restrict the CI token.",
                      missing)
    return Result(Status.PASS, f"All {len(repo.workflows)} workflows restrict the CI token permissions.")
