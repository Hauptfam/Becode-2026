"""Product documentation, vulnerability handling policy, risk management, and AI Act scoping."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from ..model import Result, Status, check
from ..repo import Repo
from .privacy import label


def _docs(repo: Repo) -> list[str]:
    return [f for f in repo.files if f.lower().endswith(".md")]


@check(
    "DOC-01", "Each project has user documentation", "Documentation",
    references={"CRA": ["Annex II"], "ISO27001": ["A.5.37"], "NIS2": ["Art. 21(2)(g)"]},
    recommendation="Give every project a README covering purpose, installation, usage and known limitations.",
    severity="low", likelihood="possible",
)
def readmes(repo: Repo) -> Result:
    if not repo.projects:
        return Result(Status.NA, "No projects found.")
    evidence, weak = [], []
    for p in repo.projects:
        rel = f"{p}/README.md" if p else "README.md"
        text = repo.text(rel) if repo.exists(rel) else ""
        parts = {k: bool(re.search(rx, text, re.I | re.M)) for k, rx in
                 {"install": r"^#+.*(install|quick start|setup)", "usage": r"^#+.*(usage|how to|example)",
                  "limitations": r"^#+.*(limitation|disclaimer|security|known issues)"}.items()}
        evidence.append(f"{rel}: " + ", ".join(f"{k} {'yes' if v else 'missing'}" for k, v in parts.items()))
        if not all(parts.values()):
            weak.append(rel)
    if weak:
        return Result(Status.WARN, f"{len(weak)} README(s) miss installation, usage or limitations sections.", evidence)
    return Result(Status.PASS, f"All {len(repo.projects)} projects document installation, usage and limitations.", evidence)


@check(
    "DOC-02", "A vulnerability disclosure policy exists", "Vulnerability handling",
    references={"CRA": ["Annex I, Part II(5)", "Annex I, Part II(6)", "Art. 13(17)"], "NIS2": ["Art. 21(2)(e)", "Art. 12"],
                "ISO27001": ["A.8.8", "A.5.24"], "DORA": ["Art. 10"]},
    recommendation="Add a SECURITY.md: how to report a vulnerability privately (email or GitHub private vulnerability "
                   "reporting), what reporters can expect and when, and which versions get fixes.",
    severity="medium", likelihood="likely",
)
def security_policy(repo: Repo) -> Result:
    policies = repo.find(r"(^|/)(\.github/)?SECURITY\.md$")
    if not policies:
        return Result(Status.FAIL, "No SECURITY.md: someone who finds a vulnerability has no private way to report it.")
    text = " ".join(repo.text(p) for p in policies)
    if re.search(r"@|security advisor|report a vulnerability|private vulnerability", text, re.I):
        return Result(Status.PASS, "A security policy with a reporting channel is published.", policies)
    return Result(Status.WARN, "SECURITY.md exists but gives no reporting contact.", policies)


@check(
    "DOC-03", "The security support period is stated", "Vulnerability handling",
    references={"CRA": ["Art. 13(8)", "Annex II"], "ISO27001": ["A.8.8"]},
    recommendation="State which versions receive security fixes and until when (e.g. 'the latest release; this is a "
                   "learning project with best-effort support'), in SECURITY.md or the README.",
    severity="low", likelihood="likely",
)
def support_period(repo: Repo) -> Result:
    statement = (r"^#+\s*supported versions|support(ed)? until|support period\s*(:|ends|is|of \d)"
                 r"|security (updates|fixes) (until|for \d|are provided)|end of (life|support)\s*[:-]")
    hits = repo.grep(statement, _docs(repo))
    if hits:
        return Result(Status.PASS, "The support period is documented.", [f"{r}:{n}" for r, n, _ in hits[:3]])
    return Result(Status.FAIL, "No document says how long the software receives security updates.")


@check(
    "DOC-04", "Releases are versioned with a change log", "Vulnerability handling",
    references={"CRA": ["Annex I, Part II(4)", "Annex II"], "ISO27001": ["A.8.32"], "DORA": ["Art. 9"]},
    recommendation="Keep a CHANGELOG.md per project (Keep a Changelog format) that flags security fixes, and tag releases.",
    severity="low", likelihood="possible",
)
def changelog(repo: Repo) -> Result:
    versions = [f"{label(p)}: {d.get('project', {}).get('version', '?')}" for p, d in repo.projects.items()]
    logs = repo.find(r"(^|/)(CHANGELOG|CHANGES|HISTORY|RELEASE[_-]?NOTES)(\.md|\.rst|\.txt)?$")
    tags = repo._git("tag").split() if repo.is_git else []
    if logs:
        return Result(Status.PASS, "Changes are recorded in a change log.", logs + versions)
    if versions:
        return Result(Status.WARN, f"Versions are declared ({', '.join(versions)}) but there is no change log"
                                   f"{' and no release tags' if not tags else ''}, so users can't see which version "
                                   "fixes what.", versions)
    return Result(Status.FAIL, "No versioning or change log.")


@check(
    "DOC-05", "Licensing is clear", "Documentation",
    references={"ISO27001": ["A.5.32"], "CRA": ["Annex I, Part II(1)"]},
    recommendation="Add a LICENSE file to every project, and check that dependency licenses are compatible.",
    severity="low", likelihood="unlikely",
)
def licensing(repo: Repo) -> Result:
    missing = [label(p) for p in repo.projects if not repo.exists(f"{p}/LICENSE" if p else "LICENSE")]
    if missing:
        return Result(Status.WARN, f"No LICENSE file in: {', '.join(missing)}.")
    return Result(Status.PASS, f"All {len(repo.projects)} projects have a LICENSE file; dependency licenses are listed "
                               "in the SBOM appendix.")


@check(
    "RISK-01", "A documented risk assessment or threat model exists", "Risk management",
    references={"ISO27005": ["6", "7.2", "7.3", "7.4", "8"], "ISO27001": ["6.1.2", "6.1.3", "8.2"],
                "NIS2": ["Art. 21(1)", "Art. 21(2)(a)"], "DORA": ["Art. 6", "Art. 8"], "CRA": ["Art. 13(2)", "Annex VII"]},
    recommendation="Write a THREAT_MODEL.md per project: assets, threats (e.g. STRIDE), likelihood and impact, chosen "
                   "treatment, and the risk owner. The risk register in this report is a starting point.",
    severity="medium", likelihood="likely",
)
def risk_assessment(repo: Repo) -> Result:
    name_rx = re.compile(r"threat[-_ ]?model|risk[-_ ]?(assessment|register|analysis)", re.I)
    docs = [f for f in _docs(repo) if name_rx.search(Path(f).name)]
    sections = [(r, n) for r, n, _ in repo.grep(r"^#+\s*(threat model|risk assessment|risk register)", _docs(repo))]
    if docs or sections:
        return Result(Status.PASS, "A risk assessment is documented.", docs + [f"{r}:{n}" for r, n in sections])
    return Result(Status.FAIL, "No threat model or risk assessment is documented. CRA Art. 13(2) requires one for "
                               "products in scope, and ISO 27001/27005 build everything on it.")


@check(
    "INC-01", "An incident and vulnerability response procedure is documented", "Incident handling",
    references={"NIS2": ["Art. 21(2)(b)", "Art. 23"], "DORA": ["Art. 17", "Art. 19"], "CRA": ["Art. 14"],
                "ISO27001": ["A.5.24", "A.5.26"], "GDPR": ["Art. 33", "Art. 34"]},
    recommendation="Document who does what when a vulnerability in the tools is exploited or a breach happens, "
                   "including the legal clocks: CRA 24 h early warning to ENISA/CSIRT, NIS2 24 h / 72 h / 1 month, "
                   "GDPR 72 h to the data protection authority.",
    severity="medium", likelihood="possible",
)
def incident_procedure(repo: Repo) -> Result:
    hits = repo.grep(r"^#+.*(incident (response|handling|reporting)|breach notification|security incident)", _docs(repo))
    if hits:
        return Result(Status.PASS, "An incident procedure is documented.", [f"{r}:{n}" for r, n, _ in hits[:3]])
    return Result(Status.FAIL, "No documented procedure for responding to an exploited vulnerability or a data breach.")


AI_LIBRARIES = {"sklearn", "torch", "tensorflow", "keras", "transformers", "openai", "anthropic", "langchain",
                "xgboost", "lightgbm", "onnxruntime", "huggingface_hub", "llama_cpp", "mistralai", "cohere",
                "spacy", "jax", "catboost", "ollama", "sentence_transformers"}
MODEL_FILES = r"\.(onnx|pt|pth|h5|keras|joblib|safetensors|gguf|tflite|pkl)$"


@check(
    "AI-01", "Use of AI systems (AI Act scope)", "AI Act",
    references={"AIACT": ["Art. 3(1)", "Art. 4", "Art. 5", "Art. 6", "Art. 50"]},
    recommendation="Classify each AI system (prohibited, high-risk under Art. 6 / Annex III, transparency duties "
                   "under Art. 50, or minimal risk), document it, and ensure AI literacy for its users (Art. 4).",
    severity="medium", likelihood="possible",
)
def ai_usage(repo: Repo) -> Result:
    libs = set()
    for rel in repo.python_files:
        tree = repo.asts.get(rel)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                libs |= {a.name.split(".")[0] for a in node.names} & AI_LIBRARIES
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                libs |= {node.module.split(".")[0]} & AI_LIBRARIES
    deps = {re.split(r"[<>=!~\[; ]", d, maxsplit=1)[0].lower().replace("-", "_")
            for data in repo.projects.values() for d in data.get("project", {}).get("dependencies", [])}
    libs |= deps & {lib.replace("-", "_") for lib in AI_LIBRARIES | {"scikit_learn"}}
    models = repo.find(MODEL_FILES)
    if libs or models:
        return Result(Status.MANUAL, "The project uses machine learning or AI models: classify them under the AI Act.",
                      [f"library: {lib}" for lib in sorted(libs)] + [f"model file: {m}" for m in models])
    return Result(Status.NA, f"No AI system: none of {len(AI_LIBRARIES)} common ML/LLM libraries is imported or declared, "
                             "and no model files are present. Verdicts come from fixed, human-written rules and "
                             "thresholds, which the AI Act's definition (Art. 3(1)) excludes.",
                  [f"{len(repo.python_files)} Python files and {len(repo.projects)} pyproject.toml files inspected"])
