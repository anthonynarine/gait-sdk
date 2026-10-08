"""0.5.4 hygiene -- regression tests for GAIT-SEC-032, 033, 034 and 080-082.

  032  CI supply chain: every third-party action is pinned to a full commit
       SHA (tag in a trailing comment) and Dependabot watches the actions and
       pip ecosystems.
  080  Workflow permissions, parsed structurally (YAML, so flow-style
       mappings count too): every job's EFFECTIVE permissions are at most
       `contents: read`, except the `publish` job, which gets exactly
       `id-token: write` (optionally plus `contents: read`). `read-all`,
       `write-all` and any write scope elsewhere are rejected, as are the
       `pull_request_target` and `workflow_run` triggers.
  081  Every actions/checkout sets `persist-credentials: false`.
  082  The release build tools are installed from a hash-pinned requirements
       file with `--require-hashes`, and the build runs without isolation.
  033  `requests` is not a dependency and nothing in the package imports it.
  034  The library never sets a level on its own loggers; the package root
       logger carries a NullHandler and nothing else.

The workflow checks are pure functions over parsed YAML. They run against the
repository's workflows, and against mutated in-memory copies to prove each
one rejects what it is meant to reject. They are skipped when the suite runs
from an installed sdist without `.github/`.
"""

from __future__ import annotations

import ast
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
RELEASE_REQUIREMENTS = ".github/requirements/release.txt"
PACKAGES = ("gait_sdk", "auth_integration")

# The one job allowed to mint an OIDC token (PyPI Trusted Publishing).
PUBLISH_JOB = ("publish.yml", "publish")
PUBLISH_ALLOWED = ({"id-token": "write"}, {"id-token": "write", "contents": "read"})
FORBIDDEN_TRIGGERS = {"pull_request_target", "workflow_run"}

needs_checkout = pytest.mark.skipif(
    not WORKFLOWS.is_dir(), reason="repository checkout (.github/) not present"
)

# owner/repo[/path]@<40 hex> # <tag>
_PINNED = re.compile(
    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}\s+#\s*v?\d+(\.\d+)*\s*$"
)
_PINNED_REF = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}$")
_USES = re.compile(r"^\s*(?:-\s+)?uses:\s*(?P<ref>.+?)\s*$")


def _yaml():
    return pytest.importorskip("yaml")  # declared in the [test] extra


def _workflow_files():
    return sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))


def _workflow_texts():
    return {p.name: p.read_text() for p in _workflow_files()}


def _parse(texts):
    yaml = _yaml()
    return {name: yaml.safe_load(text) for name, text in texts.items()}


def _uses_lines():
    for path in _workflow_files():
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            m = _USES.match(line)
            if m:
                yield path.name, lineno, m.group("ref")


# -----------------------------------------------------------------------------
# Structural checks (pure functions over {filename: parsed workflow})
# -----------------------------------------------------------------------------
def _triggers(doc):
    # YAML 1.1 reads a bare `on:` key as the boolean True.
    on = doc.get("on", doc.get(True))
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return set(on)
    if isinstance(on, dict):
        return set(on)
    return set()


def _scopes(perms, where, problems):
    """Normalise a permissions value to {scope: level}; record what is invalid."""
    if isinstance(perms, dict):
        return {str(k): str(v) for k, v in perms.items()}
    # `read-all`, `write-all`, a bare `permissions:` or anything else.
    problems.append(f"{where}: permissions must be an explicit mapping, got {perms!r}")
    return None


def _jobs(doc):
    jobs = doc.get("jobs") or {}
    return jobs.items() if isinstance(jobs, dict) else []


def check_permissions_and_triggers(docs):
    problems = []
    seen_publish = False
    for name, doc in docs.items():
        bad = _triggers(doc) & FORBIDDEN_TRIGGERS
        if bad:
            problems.append(f"{name}: forbidden trigger(s) {sorted(bad)}")

        if "permissions" not in doc:
            problems.append(f"{name}: no top-level permissions")
            top = None
        else:
            top = _scopes(doc["permissions"], f"{name} (top level)", problems)
            if top is not None and top != {"contents": "read"}:
                problems.append(f"{name} (top level): must be exactly contents: read, got {top}")

        for job_id, job in _jobs(doc):
            where = f"{name} job {job_id}"
            if isinstance(job, dict) and "permissions" in job:
                eff = _scopes(job["permissions"], where, problems)
            else:
                eff = top  # a job without its own block inherits the top level
            if eff is None:
                continue
            granted = {k: v for k, v in eff.items() if v != "none"}
            if (name, job_id) == PUBLISH_JOB:
                seen_publish = True
                if granted not in PUBLISH_ALLOWED:
                    problems.append(f"{where}: must be exactly id-token: write (+ contents: read), got {eff}")
            elif granted and granted != {"contents": "read"}:
                problems.append(f"{where}: effective permissions exceed contents: read: {eff}")
    if not seen_publish:
        problems.append(f"{PUBLISH_JOB[0]}: job {PUBLISH_JOB[1]!r} not found")
    return problems


def _steps(doc):
    for job_id, job in _jobs(doc):
        if isinstance(job, dict):
            for step in job.get("steps") or []:
                if isinstance(step, dict):
                    yield job_id, step


def check_structural_pins(docs):
    """Every `uses:` (step or reusable-workflow job), flow style included."""
    problems = []
    for name, doc in docs.items():
        refs = [(job_id, job.get("uses")) for job_id, job in _jobs(doc) if isinstance(job, dict)]
        refs += [(job_id, step.get("uses")) for job_id, step in _steps(doc)]
        for job_id, ref in refs:
            if ref is None or str(ref).startswith("./"):
                continue
            if not _PINNED_REF.match(str(ref)):
                problems.append(f"{name} job {job_id}: not SHA-pinned: {ref}")
    return problems


def check_checkout_credentials(docs):
    problems = []
    for name, doc in docs.items():
        for job_id, step in _steps(doc):
            if str(step.get("uses", "")).startswith("actions/checkout@"):
                value = (step.get("with") or {}).get("persist-credentials")
                if value is not False and str(value).lower() != "false":
                    problems.append(f"{name} job {job_id}: checkout without persist-credentials: false")
    return problems


def check_release_tool_installs(docs):
    """Build tools come only from the hash-pinned file; builds are not isolated."""
    problems = []
    build_jobs = 0
    for name, doc in docs.items():
        for job_id, step in _steps(doc):
            run = str(step.get("run", ""))
            for line in run.splitlines():
                line = line.strip()
                if re.search(r"\bpip install\b", line) and re.search(r"\b(build|twine|setuptools)\b", line):
                    problems.append(f"{name} job {job_id}: build tool installed outside the pinned file: {line}")
                if re.search(r"\bpython -m build\b", line):
                    build_jobs += 1
                    if "--no-isolation" not in line:
                        problems.append(f"{name} job {job_id}: `python -m build` without --no-isolation")
                    if f"--require-hashes -r {RELEASE_REQUIREMENTS}" not in run:
                        problems.append(f"{name} job {job_id}: builds without the hash-pinned install")
    if build_jobs < 2:
        problems.append(f"expected the publish and test build jobs, found {build_jobs} build step(s)")
    return problems


# -----------------------------------------------------------------------------
# GAIT-SEC-032 / 080 / 081 / 082 against the repository
# -----------------------------------------------------------------------------
@needs_checkout
def test_workflows_exist():
    assert _workflow_files(), "no workflow files found"
    assert list(_uses_lines()), "no `uses:` lines found; the pin check would be vacuous"


@needs_checkout
def test_every_action_is_pinned_to_a_full_commit_sha():
    bad = []
    for name, lineno, ref in _uses_lines():
        if ref.startswith("./"):
            continue  # a workflow in this same repository and commit
        if not _PINNED.match(ref):
            bad.append(f"{name}:{lineno}: {ref}")
    assert not bad, "actions must be pinned as owner/repo@<40-hex sha> # vX.Y.Z:\n" + "\n".join(bad)
    assert check_structural_pins(_parse(_workflow_texts())) == []


@pytest.mark.parametrize(
    "ref, ok",
    [
        ("actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0", True),
        ("actions/checkout@v4", False),
        ("actions/checkout@11d5960a326750d5838078e36cf38b85af677262", False),  # no tag comment
        ("actions/checkout@11d5960a # v4.4.0", False),  # short SHA
        ("pypa/gh-action-pypi-publish@release/v1", False),  # branch
        ("actions/checkout@main # v4.4.0", False),
    ],
)
def test_pin_pattern_rejects_mutable_refs(ref, ok):
    assert bool(_PINNED.match(ref)) is ok


@needs_checkout
def test_workflow_permissions_and_triggers():
    assert check_permissions_and_triggers(_parse(_workflow_texts())) == []


@needs_checkout
def test_every_checkout_drops_credentials():
    docs = _parse(_workflow_texts())
    assert any(
        str(s.get("uses", "")).startswith("actions/checkout@") for d in docs.values() for _, s in _steps(d)
    )
    assert check_checkout_credentials(docs) == []


@needs_checkout
def test_release_tools_installed_with_require_hashes():
    assert check_release_tool_installs(_parse(_workflow_texts())) == []


@needs_checkout
def test_release_requirements_are_hash_pinned():
    path = ROOT / RELEASE_REQUIREMENTS
    assert path.is_file()
    # Join continuation lines, then every requirement must be == pinned and hashed.
    entries = [
        e.strip()
        for e in path.read_text().replace("\\\n", " ").splitlines()
        if e.strip() and not e.strip().startswith("#")
    ]
    names = set()
    for entry in entries:
        assert re.match(r"^[A-Za-z0-9_.-]+==\S+\s", entry), f"not ==-pinned: {entry[:60]}"
        assert "--hash=sha256:" in entry, f"no hash: {entry[:60]}"
        names.add(entry.split("==")[0].lower())
    assert {"build", "twine", "setuptools"} <= names


# Mutations of the real workflows (in memory only), each of which must be
# rejected. (file, old text, new text, checker)
_MUTATIONS = {
    "job contents: write": (
        "python-tests.yml", "  test:\n", "  test:\n    permissions:\n      contents: write\n",
        check_permissions_and_triggers,
    ),
    "top-level write-all": (
        "python-tests.yml", "permissions:\n  contents: read\n", "permissions: write-all\n",
        check_permissions_and_triggers,
    ),
    "job write-all": (
        "publish.yml", "  build:\n", "  build:\n    permissions: write-all\n",
        check_permissions_and_triggers,
    ),
    "top-level read-all": (
        "publish.yml", "permissions:\n  contents: read\n", "permissions: read-all\n",
        check_permissions_and_triggers,
    ),
    "flow-style id-token on build": (
        "publish.yml", "  build:\n", "  build:\n    permissions: {id-token: write}\n",
        check_permissions_and_triggers,
    ),
    "flow-style write on publish": (
        "publish.yml", "      id-token: write", "      id-token: write\n      contents: write",
        check_permissions_and_triggers,
    ),
    "publish gains actions: write": (
        "publish.yml", "    permissions:\n      id-token: write", "    permissions: {id-token: write, actions: write}",
        check_permissions_and_triggers,
    ),
    "pull_request_target trigger": (
        "python-tests.yml", "  pull_request:\n", "  pull_request_target:\n",
        check_permissions_and_triggers,
    ),
    "workflow_run trigger": (
        "python-tests.yml", "  workflow_call:\n", "  workflow_call:\n  workflow_run:\n    workflows: [x]\n",
        check_permissions_and_triggers,
    ),
    "checkout keeps credentials": (
        "publish.yml", "persist-credentials: false", "persist-credentials: true",
        check_checkout_credentials,
    ),
    "flow-style unpinned action": (
        "publish.yml", "      - name: Tag must match", "      - {uses: actions/cache@v4}\n      - name: Tag must match",
        check_structural_pins,
    ),
    "unhashed build tools": (
        "publish.yml", "python -m pip install --require-hashes -r .github/requirements/release.txt",
        "python -m pip install --upgrade build twine",
        check_release_tool_installs,
    ),
    "isolated build": (
        "python-tests.yml", "python -m build --no-isolation", "python -m build",
        check_release_tool_installs,
    ),
}


@needs_checkout
@pytest.mark.parametrize("mutation", sorted(_MUTATIONS))
def test_checks_reject_mutated_workflows(mutation):
    filename, old, new, checker = _MUTATIONS[mutation]
    texts = _workflow_texts()
    assert old in texts[filename], f"mutation anchor missing in {filename}: {old!r}"
    texts[filename] = texts[filename].replace(old, new, 1)
    assert checker(_parse(texts)), f"{checker.__name__} accepted: {mutation}"


@needs_checkout
def test_dependabot_watches_actions_and_pip_weekly():
    docs = _parse({"dependabot.yml": (ROOT / ".github" / "dependabot.yml").read_text()})
    updates = docs["dependabot.yml"]["updates"]
    have = {(u["package-ecosystem"], u["directory"]) for u in updates if u["schedule"]["interval"] == "weekly"}
    assert {
        ("github-actions", "/"),
        ("pip", "/"),
        ("pip", "/.github/requirements"),
    } <= have, have


# -----------------------------------------------------------------------------
# GAIT-SEC-033
# -----------------------------------------------------------------------------
def _dependency_names():
    tomllib = pytest.importorskip("tomllib")  # Python 3.11+; 3.10 runs the AST checks below
    data = tomllib.loads((ROOT / "pyproject.toml").read_text())
    project = data["project"]
    specs = list(project.get("dependencies", []))
    for extra in project.get("optional-dependencies", {}).values():
        specs.extend(extra)
    return {re.split(r"[\s\[<>=!~;]", s.strip(), maxsplit=1)[0].lower() for s in specs}


def test_requests_is_not_a_declared_dependency():
    assert "requests" not in _dependency_names()


def _imported_top_level_modules(path):
    tree = ast.parse(path.read_text(), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            yield node.module.split(".")[0]


def test_no_source_file_imports_requests():
    offenders = [
        str(p.relative_to(ROOT))
        for pkg in PACKAGES
        for p in (ROOT / pkg).rglob("*.py")
        if "requests" in set(_imported_top_level_modules(p))
    ]
    assert not offenders, offenders


# Imports every module of the package in a fresh interpreter with `requests`
# made unimportable, then reports every gait_sdk logger's level and the root
# package logger's handlers. A fresh process keeps other tests (caplog etc.)
# from influencing logger state.
_PROBE = textwrap.dedent(
    """
    import importlib, json, logging, pkgutil, sys
    sys.modules["requests"] = None  # any `import requests` now raises ImportError

    import django
    from django.conf import settings
    settings.configure()
    django.setup()

    import gait_sdk
    failed = {}
    for mod in pkgutil.walk_packages(gait_sdk.__path__, "gait_sdk."):
        try:
            importlib.import_module(mod.name)
        except Exception as exc:
            failed[mod.name] = f"{type(exc).__name__}: {exc}"

    levels = {
        name: lg.level
        for name, lg in logging.root.manager.loggerDict.items()
        if isinstance(lg, logging.Logger) and (name == "gait_sdk" or name.startswith("gait_sdk."))
    }
    handlers = [type(h).__name__ for h in logging.getLogger("gait_sdk").handlers]
    print(json.dumps({"failed": failed, "levels": levels, "handlers": handlers,
                      "requests_loaded": sys.modules.get("requests") is not None}))
    """
)


@pytest.fixture(scope="module")
def probe():
    pytest.importorskip("django")
    pytest.importorskip("rest_framework")
    pytest.importorskip("fastapi")
    import json

    env = dict(os.environ)
    env.pop("DJANGO_SETTINGS_MODULE", None)
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(ROOT), env.get("PYTHONPATH")]))
    out = subprocess.run(
        [sys.executable, "-c", _PROBE], capture_output=True, text=True, env=env, cwd=ROOT, timeout=120
    )
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_every_module_imports_without_requests(probe):
    assert probe["failed"] == {}
    assert probe["requests_loaded"] is False


# -----------------------------------------------------------------------------
# GAIT-SEC-034
# -----------------------------------------------------------------------------
def test_every_gait_sdk_logger_level_is_notset(probe):
    assert "gait_sdk.client" in probe["levels"], "probe did not see the module loggers"
    forced = {n: lvl for n, lvl in probe["levels"].items() if lvl != 0}  # 0 == logging.NOTSET
    assert not forced, f"library loggers must not set a level: {forced}"


def test_package_logger_has_only_a_null_handler(probe):
    assert probe["handlers"] == ["NullHandler"]


def test_no_source_file_calls_setlevel():
    offenders = []
    for pkg in PACKAGES:
        for p in (ROOT / pkg).rglob("*.py"):
            tree = ast.parse(p.read_text(), filename=str(p))
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "setLevel"
                ):
                    offenders.append(f"{p.relative_to(ROOT)}:{node.lineno}")
    assert not offenders, offenders
