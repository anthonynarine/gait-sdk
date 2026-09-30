"""CHK2b: the deps pack (CHK.DEPS.KNOWN_VULNS). Every scanner run is a mocked
subprocess; nothing touches the network."""

import io
import json
import subprocess
import sys

import pytest

from tests._checks_support import FakeGait, SleepRecorder, install_fake_gait

from gait_sdk.checks import cli, deps_pack, engine, registry

CHECK = "CHK.DEPS.KNOWN_VULNS"
CLEAN_PACKAGE = "totally-private-internal-lib"  # installed, not vulnerable: must never be sent


# --- Fixtures: real-shaped scanner output ------------------------------------------------
def pip_audit_json(deps):
    return json.dumps({"dependencies": deps, "fixes": []})


def dep(name, version, *vulns):
    return {"name": name, "version": version, "vulns": list(vulns)}


def vuln(vid, fixes=(), aliases=()):
    return {"id": vid, "fix_versions": list(fixes), "aliases": list(aliases), "description": "long advisory text"}


CLEAN = pip_audit_json([dep(CLEAN_PACKAGE, "1.0.0"), dep("django", "5.2.17"),
                        {"name": "gait-sdk", "skip_reason": "Dependency not found on PyPI"}])
WITH_FIX = pip_audit_json([
    dep(CLEAN_PACKAGE, "1.0.0"),
    dep("pip", "23.1.2",
        vuln("PYSEC-2023-228", ["23.3"], ["CVE-2023-5752", "GHSA-mq26-g339-26xf"]),
        vuln("GHSA-4xh5-x5gv-qwph", ["25.3", "24.0"], ["CVE-2025-8869"])),
    dep("setuptools", "65.5.0", vuln("PYSEC-2022-43012", ["65.5.1"], ["BIT-setuptools-2022-40897"])),
])
UNFIXED_ONLY = pip_audit_json([
    dep(CLEAN_PACKAGE, "1.0.0"),
    dep("ecdsa", "0.19.1", vuln("GHSA-wj6h-64fc-37mp", [], ["CVE-2024-23342"])),
])
MIXED = pip_audit_json([
    dep("ecdsa", "0.19.1", vuln("GHSA-wj6h-64fc-37mp", [])),
    dep("jinja2", "3.1.2", vuln("GHSA-h5c8-rqwp-cp95", ["3.1.3"])),
])
MANY = pip_audit_json(
    [dep(f"pkg{i:02d}", "1.0", vuln(f"PYSEC-2024-{i}", [f"1.{i}"])) for i in range(14)]
    + [dep(CLEAN_PACKAGE, "1.0.0")]
)
WEIRD_IDS = pip_audit_json([
    dep("odd", "1.0", vuln("BIT-odd-2024-1", ["1.1"], ["RUSTSEC-2024-1"])),  # no usable id: counted, not itemised
    dep("aliasonly", "2.0", vuln("BIT-x-1", ["2.1"], ["CVE-2024-9999"])),  # falls back to the CVE alias
    dep("bad name!", "1.0", vuln("PYSEC-2024-1", ["1.1"])),  # name fails the pattern
])
OLD_TOP_LEVEL_LIST = json.dumps([dep("pip", "23.1.2", vuln("PYSEC-2023-228", ["23.3"]))])

OSV = json.dumps({"results": [{"source": {"path": "/tmp/x.txt", "type": "lockfile"}, "packages": [
    {"package": {"name": "pip", "version": "23.1.2", "ecosystem": "PyPI"}, "vulnerabilities": [
        {"id": "GHSA-mq26-g339-26xf", "aliases": ["CVE-2023-5752", "PYSEC-2023-228"],
         "affected": [{"package": {"name": "pip", "ecosystem": "PyPI"},
                       "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "23.3"}]}]}]}]},
    {"package": {"name": "ecdsa", "version": "0.19.1", "ecosystem": "PyPI"}, "vulnerabilities": [
        {"id": "GHSA-wj6h-64fc-37mp", "aliases": ["CVE-2024-23342"],
         "affected": [{"package": {"name": "ecdsa", "ecosystem": "PyPI"},
                       "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]}]},
    {"package": {"name": CLEAN_PACKAGE, "version": "1.0.0", "ecosystem": "PyPI"}, "vulnerabilities": []},
]}]})


class Runner:
    """A fake subprocess.run: records the command, returns or raises what it's told."""

    def __init__(self, stdout="", stderr="", returncode=0, raises=None):
        self.stdout, self.stderr, self.returncode, self.raises = stdout, stderr, returncode, raises
        self.calls = []

    def __call__(self, cmd, **kwargs):
        self.calls.append((cmd, kwargs))
        if self.raises is not None:
            raise self.raises
        return subprocess.CompletedProcess(cmd, self.returncode, self.stdout, self.stderr)


@pytest.fixture
def pip_audit(monkeypatch):
    def install(**kwargs):
        runner = Runner(**kwargs)
        monkeypatch.setattr(deps_pack, "pip_audit_available", lambda: True)
        monkeypatch.setattr(deps_pack, "RUNNER", runner)
        return runner

    return install


@pytest.fixture
def osv(monkeypatch):
    def install(**kwargs):
        runner = Runner(**kwargs)
        monkeypatch.setattr(deps_pack, "osv_scanner_path", lambda: "/usr/local/bin/osv-scanner")
        monkeypatch.setattr(deps_pack, "RUNNER", runner)
        return runner

    return install


def run(tool="pip-audit"):
    ctx = engine.PackContext(environment="production", deps_tool=tool)
    results, _ = engine.run_checks(["deps"], "production", context=ctx)
    assert len(results) == 1
    item = results[0]
    registry.validate_payload(CHECK, item.payload, result=item.result)
    assert item.valid
    return item


# --- pip-audit ------------------------------------------------------------------------------
def test_pip_audit_command_and_timeout(pip_audit):
    runner = pip_audit(stdout=CLEAN)
    run()
    cmd, kwargs = runner.calls[0]
    assert cmd == [sys.executable, "-m", "pip_audit", "-f", "json", "--progress-spinner", "off"]
    assert kwargs["timeout"] == 120 and kwargs["capture_output"] is True


def test_clean_is_ok(pip_audit):
    pip_audit(stdout=CLEAN)
    item = run()
    assert (item.outcome, item.result) == ("ok", "PASS")
    assert item.facts == {"tool": "pip-audit", "vulnerable_count": 0, "unfixed_count": 0, "items": []}


def test_vulnerable_with_fix_fails(pip_audit):
    pip_audit(stdout=WITH_FIX, returncode=1)  # pip-audit exits 1 when it finds something
    item = run()
    assert (item.outcome, item.result) == ("fail", "FAIL")
    assert item.facts["vulnerable_count"] == 2 and item.facts["unfixed_count"] == 0
    assert item.facts["items"] == [
        {"package": "pip", "version": "23.1.2", "advisory_id": "PYSEC-2023-228", "fixed_in": "23.3"},
        {"package": "setuptools", "version": "65.5.0", "advisory_id": "PYSEC-2022-43012", "fixed_in": "65.5.1"},
    ]


def test_unfixed_only_is_weak_and_omits_fixed_in(pip_audit):
    pip_audit(stdout=UNFIXED_ONLY, returncode=1)
    item = run()
    assert (item.outcome, item.result) == ("weak", "WARNING")
    assert item.facts["unfixed_count"] == 1
    assert item.facts["items"] == [{"package": "ecdsa", "version": "0.19.1", "advisory_id": "GHSA-wj6h-64fc-37mp"}]


def test_any_fixable_makes_it_fail(pip_audit):
    pip_audit(stdout=MIXED, returncode=1)
    item = run()
    assert item.outcome == "fail"
    assert (item.facts["vulnerable_count"], item.facts["unfixed_count"]) == (2, 1)
    assert item.facts["items"][0]["package"] == "jinja2"  # fixable first


def test_more_than_ten_is_capped(pip_audit):
    pip_audit(stdout=MANY, returncode=1)
    item = run()
    assert item.facts["vulnerable_count"] == 14
    assert len(item.facts["items"]) == 10
    assert registry.encoded_size(item.payload) <= registry.limits()["max_payload_bytes"]


def test_weird_ids_are_skipped_but_counted(pip_audit):
    pip_audit(stdout=WEIRD_IDS, returncode=1)
    item = run()
    assert item.facts["vulnerable_count"] == 3
    assert item.facts["items"] == [
        {"package": "aliasonly", "version": "2.0", "advisory_id": "CVE-2024-9999", "fixed_in": "2.1"}
    ]


def test_older_pip_audit_top_level_list(pip_audit):
    pip_audit(stdout=OLD_TOP_LEVEL_LIST, returncode=1)
    assert run().facts["items"][0]["advisory_id"] == "PYSEC-2023-228"


def test_lowest_fix_version_is_reported():
    assert deps_pack.lowest_version(["25.3", "24.0", "23.10", "23.3"]) == "23.3"
    assert deps_pack.lowest_version(["1.10.0", "1.9.2"]) == "1.9.2"
    assert deps_pack.lowest_version([]) is None


def test_advisory_preference():
    assert deps_pack.pick_advisory(["CVE-2023-1", "GHSA-a-b", "PYSEC-2023-2"]) == "PYSEC-2023-2"
    assert deps_pack.pick_advisory(["CVE-2023-1", "GHSA-a-b"]) == "GHSA-a-b"
    assert deps_pack.pick_advisory(["BIT-x", "RUSTSEC-1"]) is None


# --- The dependency list is never sent ---------------------------------------------------------
@pytest.mark.parametrize("stdout", [CLEAN, WITH_FIX, UNFIXED_ONLY, MANY])
def test_non_vulnerable_packages_are_never_sent(monkeypatch, pip_audit, stdout):
    pip_audit(stdout=stdout, returncode=0 if stdout == CLEAN else 1)
    fake = install_fake_gait(monkeypatch, FakeGait())
    out = io.StringIO()
    cli.main(["--pack", "deps", "--json"], out=out, err=io.StringIO(), sleep=SleepRecorder())
    sent = json.dumps(fake.sent)
    assert CLEAN_PACKAGE not in sent
    assert "django" not in sent.lower().replace("chk.django", "")
    assert CLEAN_PACKAGE not in out.getvalue()
    assert "long advisory text" not in sent + out.getvalue()


# --- Unknown, never ok -------------------------------------------------------------------------
def assert_unknown(item, tool, reason):
    assert (item.outcome, item.result) == ("unknown", "INFORMATIONAL")
    assert item.facts == {"tool": tool, "reason": reason}


def test_pip_audit_missing(monkeypatch):
    monkeypatch.setattr(deps_pack, "pip_audit_available", lambda: False)
    assert_unknown(run(), "none", "tool_missing")


def test_timeout(pip_audit):
    pip_audit(raises=subprocess.TimeoutExpired(cmd="pip-audit", timeout=120))
    assert_unknown(run(), "pip-audit", "timeout")


@pytest.mark.parametrize("stdout", ["not json", "{\"dependencies\": 5}", "{\"unexpected\": []}", "",
                                    "{\"dependencies\": [{\"name\": \"x\", \"version\": \"1\", \"vulns\": \"no\"}]}"])
def test_bad_output_is_unparseable(pip_audit, stdout):
    pip_audit(stdout=stdout)
    assert_unknown(run(), "pip-audit", "unparseable")


@pytest.mark.parametrize(
    "stderr",
    [
        "requests.exceptions.ConnectionError: HTTPSConnectionPool(host='pypi.org', port=443): Max retries exceeded",
        "socket.gaierror: [Errno 11001] getaddrinfo failed",
        "ProxyError('Cannot connect to proxy.')",
        "ssl.SSLCertVerificationError: certificate verify failed",
        "HTTPError: 503 Server Error: Service Unavailable",
        "429 Too Many Requests",
    ],
)
def test_network_errors(pip_audit, stderr):
    pip_audit(stdout="", stderr=stderr, returncode=1)
    assert_unknown(run(), "pip-audit", "network")


def test_nonzero_exit_without_vulns_or_network_error_is_unparseable(pip_audit):
    pip_audit(stdout=CLEAN, stderr="ValueError: something odd", returncode=1)
    assert_unknown(run(), "pip-audit", "unparseable")


def test_tool_text_never_reaches_facts_or_output(monkeypatch, pip_audit, caplog):
    secret_stderr = "ConnectionError: proxy user:hunter2@proxy.internal refused"
    pip_audit(stdout="", stderr=secret_stderr, returncode=1)
    install_fake_gait(monkeypatch, FakeGait(), credential=None)
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(["--pack", "deps", "--dry-run", "--json"], out=out, err=err)
    assert code == 0  # unknown is INFORMATIONAL
    assert cli.main(["--pack", "deps", "--no-send", "--fail-on-unknown"], out=io.StringIO(), err=io.StringIO()) == 1
    everything = out.getvalue() + err.getvalue() + caplog.text
    assert "hunter2" not in everything and "proxy.internal" not in everything
    data = json.loads(out.getvalue())
    assert data["results"][0]["facts"] == {"tool": "pip-audit", "reason": "network"}


# --- osv-scanner -----------------------------------------------------------------------------------
def test_osv_scanner_command_uses_a_temp_requirements_lockfile(osv, monkeypatch):
    monkeypatch.setattr(deps_pack, "installed_requirements", lambda: f"{CLEAN_PACKAGE}==1.0.0\npip==23.1.2\n")
    seen = {}

    runner = osv(stdout=OSV, returncode=1)
    original = runner.__call__

    def capture(cmd, **kwargs):
        lockfile = cmd[-1].split(":", 1)[1]
        with open(lockfile, encoding="utf-8") as handle:
            seen["contents"] = handle.read()
        seen["path"] = lockfile
        return original(cmd, **kwargs)

    monkeypatch.setattr(deps_pack, "RUNNER", capture)
    item = run("osv-scanner")
    cmd, kwargs = runner.calls[0]
    assert cmd[:4] == ["/usr/local/bin/osv-scanner", "--format", "json", "--lockfile"]
    assert cmd[4].startswith("requirements.txt:")
    assert kwargs["timeout"] == 120
    assert "pip==23.1.2" in seen["contents"]
    import os

    assert not os.path.exists(seen["path"])  # the temp file is removed
    assert item.facts["tool"] == "osv-scanner"


def test_osv_scanner_results(osv):
    osv(stdout=OSV, returncode=1)
    item = run("osv-scanner")
    assert item.outcome == "fail"
    assert (item.facts["vulnerable_count"], item.facts["unfixed_count"]) == (2, 1)
    assert item.facts["items"] == [
        {"package": "pip", "version": "23.1.2", "advisory_id": "PYSEC-2023-228", "fixed_in": "23.3"},
        {"package": "ecdsa", "version": "0.19.1", "advisory_id": "GHSA-wj6h-64fc-37mp"},
    ]


def test_osv_scanner_clean(osv):
    osv(stdout=json.dumps({"results": []}))
    assert run("osv-scanner").outcome == "ok"


def test_osv_scanner_missing(monkeypatch):
    monkeypatch.setattr(deps_pack, "osv_scanner_path", lambda: None)
    assert_unknown(run("osv-scanner"), "none", "tool_missing")


def test_osv_scanner_timeout_and_bad_output(osv):
    osv(raises=subprocess.TimeoutExpired(cmd="osv-scanner", timeout=120))
    assert_unknown(run("osv-scanner"), "osv-scanner", "timeout")
    osv(stdout="{\"results\": {}}")
    assert_unknown(run("osv-scanner"), "osv-scanner", "unparseable")
    osv(stdout="", stderr="failed to query OSV: dial tcp: lookup api.osv.dev: no such host; connection refused",
        returncode=127)
    assert_unknown(run("osv-scanner"), "osv-scanner", "network")


def test_deps_tool_flag(osv, monkeypatch):
    osv(stdout=OSV, returncode=1)
    install_fake_gait(monkeypatch, FakeGait(), credential=None)
    out = io.StringIO()
    cli.main(["--pack", "deps", "--deps-tool", "osv-scanner", "--dry-run", "--json"], out=out, err=io.StringIO())
    assert json.loads(out.getvalue())["results"][0]["facts"]["tool"] == "osv-scanner"


def test_installed_requirements_lists_this_environment():
    text = deps_pack.installed_requirements()
    assert "gait-sdk==" in text.lower() or "gait_sdk==" in text.lower()
