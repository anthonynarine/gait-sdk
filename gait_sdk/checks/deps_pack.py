"""The dependencies check pack (v1.0.0): CHK.DEPS.KNOWN_VULNS.

Wraps an existing scanner; gait-sdk keeps no vulnerability database of its own.

- pip-audit (default, `pip install 'gait-sdk[deps]'`) audits the running
  Python environment:
      <python> -m pip_audit -f json --progress-spinner off
- osv-scanner (a separate binary on PATH) scans a requirements list of the
  running environment's installed distributions, written to a temporary
  file that is deleted afterwards:
      osv-scanner --format json --lockfile requirements.txt:<tempfile>

Disclosure: pip-audit / osv-scanner send your package names and versions to
PyPI / OSV to look them up. Gait receives only the vulnerable packages,
versions and advisory ids (at most 10), plus counts. The full dependency
list is never sent, and no scanner output text (stdout or stderr) is ever
put into facts or reports.

Never PASS when unknown: if the scanner is missing, times out, fails on the
network or prints something unparseable, the outcome is `unknown` with only
{tool, reason}.
"""

from __future__ import annotations

import importlib.util
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

from gait_sdk.checks.engine import PackContext

PACK = "deps"
PACK_VERSION = "1.0.0"
CHECK_ID = "CHK.DEPS.KNOWN_VULNS"

TOOLS = ("pip-audit", "osv-scanner")
DEFAULT_TOOL = "pip-audit"
TIMEOUT_SECONDS = 120
MAX_ITEMS = 10

PACKAGE_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
VERSION_RE = re.compile(r"^[0-9A-Za-z.+!-]{1,50}$")
ADVISORY_RE = re.compile(r"^(PYSEC|GHSA|CVE|OSV)-[A-Za-z0-9-]{1,40}$")
_ADVISORY_PREFERENCE = ("PYSEC", "GHSA", "CVE", "OSV")

# stderr that means "couldn't reach the vulnerability service".
NETWORK_ERROR_RE = re.compile(
    r"connection|connect\b|could not resolve|name resolution|getaddrinfo|nodename nor servname|dns|"
    r"proxy|ssl|certificate|tls|http ?error|httperror|status code [45]\d\d|\b(?:429|5\d\d)\b|"
    r"too many requests|rate.?limit|max retries|timed out|network is unreachable|temporary failure",
    re.IGNORECASE,
)

logger = logging.getLogger("gait_sdk.checks")

Outcome = tuple[str, dict[str, Any]]
Runner = Callable[..., "subprocess.CompletedProcess[str]"]


class ScanUnknown(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass
class Finding:
    """One vulnerable (package, version)."""

    package: str
    version: str
    advisory_ids: list[str] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)


# -----------------------------------------------------------------------------
# Versions and advisory ids
# -----------------------------------------------------------------------------
def _simple_key(version: str) -> tuple:
    return tuple(int(p) if p.isdigit() else 0 for p in re.split(r"[.+!-]", version))


def lowest_version(versions: Iterable[str]) -> Optional[str]:
    """The lowest well-formed version (PEP 440 ordering when `packaging` is available)."""
    candidates = [v for v in versions if isinstance(v, str) and VERSION_RE.fullmatch(v)]
    if not candidates:
        return None
    try:
        from packaging.version import Version

        return min(candidates, key=Version)
    except Exception:
        return min(candidates, key=_simple_key)


def pick_advisory(ids: Iterable[str]) -> Optional[str]:
    """The first id matching the pattern, preferring PYSEC, then GHSA, CVE, OSV."""
    valid = [i for i in ids if isinstance(i, str) and ADVISORY_RE.fullmatch(i)]
    for prefix in _ADVISORY_PREFERENCE:
        for advisory in valid:
            if advisory.startswith(prefix + "-"):
                return advisory
    return None


# -----------------------------------------------------------------------------
# Parsing
# -----------------------------------------------------------------------------
def parse_pip_audit(text: str) -> list[Finding]:
    """pip-audit -f json: {"dependencies": [{name, version, vulns: [{id, fix_versions, aliases}]}]}.

    Older pip-audit releases print the dependency list at the top level.
    """
    try:
        data = json.loads(text)
    except (TypeError, ValueError):
        raise ScanUnknown("unparseable") from None
    deps = data.get("dependencies") if isinstance(data, dict) else data
    if not isinstance(deps, list):
        raise ScanUnknown("unparseable")
    findings: dict[tuple[str, str], Finding] = {}
    for dep in deps:
        if not isinstance(dep, dict):
            raise ScanUnknown("unparseable")
        vulns = dep.get("vulns") or []
        if not isinstance(vulns, list):
            raise ScanUnknown("unparseable")
        if not vulns:
            continue
        name, version = dep.get("name"), dep.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            raise ScanUnknown("unparseable")
        finding = findings.setdefault((name.lower(), version), Finding(name, version))
        for vuln in vulns:
            if not isinstance(vuln, dict):
                raise ScanUnknown("unparseable")
            finding.advisory_ids.extend(
                i for i in [vuln.get("id"), *(vuln.get("aliases") or [])] if isinstance(i, str)
            )
            finding.fixed_versions.extend(v for v in (vuln.get("fix_versions") or []) if isinstance(v, str))
    return list(findings.values())


def _osv_fixed_versions(vuln: dict, package_name: str) -> list[str]:
    fixed = []
    for affected in vuln.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        pkg = affected.get("package") or {}
        if isinstance(pkg, dict) and str(pkg.get("name", "")).lower() not in {"", package_name.lower()}:
            continue
        for rng in affected.get("ranges") or []:
            for event in (rng or {}).get("events") or []:
                if isinstance(event, dict) and isinstance(event.get("fixed"), str):
                    fixed.append(event["fixed"])
    return fixed


def parse_osv_scanner(text: str) -> list[Finding]:
    """osv-scanner --format json: {"results": [{"packages": [{package, vulnerabilities}]}]}."""
    try:
        data = json.loads(text)
    except (TypeError, ValueError):
        raise ScanUnknown("unparseable") from None
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list):
        raise ScanUnknown("unparseable")
    findings: dict[tuple[str, str], Finding] = {}
    for result in results:
        packages = (result or {}).get("packages") if isinstance(result, dict) else None
        if not isinstance(packages, list):
            raise ScanUnknown("unparseable")
        for entry in packages:
            if not isinstance(entry, dict):
                raise ScanUnknown("unparseable")
            pkg = entry.get("package") or {}
            vulns = entry.get("vulnerabilities") or []
            if not isinstance(pkg, dict) or not isinstance(vulns, list):
                raise ScanUnknown("unparseable")
            if not vulns:
                continue
            name, version = pkg.get("name"), pkg.get("version")
            if not isinstance(name, str) or not isinstance(version, str):
                raise ScanUnknown("unparseable")
            finding = findings.setdefault((name.lower(), version), Finding(name, version))
            for vuln in vulns:
                if not isinstance(vuln, dict):
                    raise ScanUnknown("unparseable")
                finding.advisory_ids.extend(
                    i for i in [vuln.get("id"), *(vuln.get("aliases") or [])] if isinstance(i, str)
                )
                finding.fixed_versions.extend(_osv_fixed_versions(vuln, name))
    return list(findings.values())


# -----------------------------------------------------------------------------
# Facts
# -----------------------------------------------------------------------------
def summarize(tool: str, findings: list[Finding]) -> Outcome:
    """Counts plus at most 10 vulnerable items. Never the full dependency list."""
    unfixed = sum(1 for f in findings if lowest_version(f.fixed_versions) is None)
    items = []
    # Fixable first (actionable), then by name, for a stable, useful top 10.
    for finding in sorted(findings, key=lambda f: (lowest_version(f.fixed_versions) is None, f.package.lower(), f.version)):
        if len(items) >= MAX_ITEMS:
            break
        advisory = pick_advisory(finding.advisory_ids)
        if advisory is None or not PACKAGE_RE.fullmatch(finding.package) or not VERSION_RE.fullmatch(finding.version):
            continue
        item = {"package": finding.package, "version": finding.version, "advisory_id": advisory}
        fixed = lowest_version(finding.fixed_versions)
        if fixed is not None:
            item["fixed_in"] = fixed
        items.append(item)
    facts: dict[str, Any] = {
        "tool": tool,
        "vulnerable_count": len(findings),
        "unfixed_count": unfixed,
        "items": items,
    }
    if not findings:
        return "ok", facts
    if unfixed < len(findings):
        return "fail", facts
    return "weak", facts


def unknown(tool: str, reason: str) -> Outcome:
    return "unknown", {"tool": tool, "reason": reason}


# -----------------------------------------------------------------------------
# Running the scanners
# -----------------------------------------------------------------------------
def _run(runner: Runner, cmd: list[str]) -> "subprocess.CompletedProcess[str]":
    return runner(cmd, capture_output=True, text=True, timeout=TIMEOUT_SECONDS, check=False)


def _interpret(proc: "subprocess.CompletedProcess[str]", parse: Callable[[str], list[Finding]]) -> list[Finding]:
    try:
        findings = parse(proc.stdout or "")
    except ScanUnknown:
        findings = None
    if proc.returncode != 0:
        if findings:  # scanners exit non-zero when they find something
            return findings
        if NETWORK_ERROR_RE.search(proc.stderr or ""):
            raise ScanUnknown("network")
        raise ScanUnknown("unparseable")
    if findings is None:
        raise ScanUnknown("unparseable")
    return findings


def pip_audit_available() -> bool:
    return importlib.util.find_spec("pip_audit") is not None


def pip_audit_command() -> list[str]:
    return [sys.executable, "-m", "pip_audit", "-f", "json", "--progress-spinner", "off"]


def run_pip_audit(runner: Runner = subprocess.run) -> Outcome:
    if not pip_audit_available():
        return unknown("none", "tool_missing")
    try:
        proc = _run(runner, pip_audit_command())
        return summarize("pip-audit", _interpret(proc, parse_pip_audit))
    except subprocess.TimeoutExpired:
        return unknown("pip-audit", "timeout")
    except FileNotFoundError:
        return unknown("none", "tool_missing")
    except ScanUnknown as exc:
        return unknown("pip-audit", exc.reason)


def osv_scanner_path() -> Optional[str]:
    return shutil.which("osv-scanner")


def installed_requirements() -> str:
    """name==version for every installed distribution (written to a temp file for osv-scanner only)."""
    from importlib.metadata import distributions

    lines = set()
    for dist in distributions():
        name = dist.metadata.get("Name") if dist.metadata else None
        if name and dist.version:
            lines.add(f"{name}=={dist.version}")
    return "\n".join(sorted(lines)) + "\n"


def osv_scanner_command(binary: str, lockfile: str) -> list[str]:
    return [binary, "--format", "json", "--lockfile", f"requirements.txt:{lockfile}"]


def run_osv_scanner(runner: Runner = subprocess.run) -> Outcome:
    binary = osv_scanner_path()
    if not binary:
        return unknown("none", "tool_missing")
    fd, path = tempfile.mkstemp(prefix="gait-check-", suffix=".txt")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(installed_requirements())
        proc = _run(runner, osv_scanner_command(binary, path))
        return summarize("osv-scanner", _interpret(proc, parse_osv_scanner))
    except subprocess.TimeoutExpired:
        return unknown("osv-scanner", "timeout")
    except FileNotFoundError:
        return unknown("none", "tool_missing")
    except ScanUnknown as exc:
        return unknown("osv-scanner", exc.reason)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


# Indirection so tests can swap the subprocess runner.
RUNNER: Runner = subprocess.run


def check_known_vulns(ctx: PackContext) -> Outcome:
    tool = ctx.deps_tool or DEFAULT_TOOL
    outcome = run_osv_scanner(RUNNER) if tool == "osv-scanner" else run_pip_audit(RUNNER)
    if outcome[0] == "unknown":
        # A short local note only; never the scanner's own text.
        logger.warning("Dependency scan result unknown (%s, %s).", outcome[1]["tool"], outcome[1]["reason"])
    return outcome


CHECKS: dict[str, Callable[[PackContext], Outcome]] = {CHECK_ID: check_known_vulns}


def prepare(ctx: PackContext) -> None:
    if (ctx.deps_tool or DEFAULT_TOOL) not in TOOLS:
        from gait_sdk.checks.engine import UsageError

        raise UsageError(f"--deps-tool must be one of: {', '.join(TOOLS)}.")


def run_check(check_id: str, ctx: PackContext) -> Outcome:
    return CHECKS[check_id](ctx)
