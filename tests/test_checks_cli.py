"""CHK2a: `gait-check` and `python manage.py gait_check`. All HTTP is mocked;
the subprocess tests only use --dry-run / --no-send (no network)."""

import io
import json
import logging
import os
import subprocess
import sys
from importlib.metadata import entry_points
from pathlib import Path

import pytest
from django.core.management import call_command

from tests._checks_support import (
    SECRET_KEY,
    FakeGait,
    SleepRecorder,
    django_settings,
    fake_deps,
    install_fake_gait,
)

from gait_sdk.checks import cli, registry
from gait_sdk.exceptions import SecuritySignalRejected
from gait_sdk.management.commands.gait_check import Command

ROOT = Path(__file__).resolve().parents[1]
ALL = registry.check_ids("django")
FALLBACK_SENTINEL = "FALLBACKsentinel-Qm7Zr9Lw4Xb8Nc1Vd6Hy3Tp5Js0Kq-gA7uE2oI9wR4tY6"
WEAK_SENTINEL = "django-insecure-WEAKsentinel42"


def main(argv, **settings_overrides):
    out, err = io.StringIO(), io.StringIO()
    with django_settings(**settings_overrides):
        code = cli.main(argv, out=out, err=err, sleep=SleepRecorder())
    return code, out.getvalue(), err.getvalue()


# --- Dry run --------------------------------------------------------------------------
def test_dry_run_sends_nothing_and_needs_no_credential(monkeypatch):
    fake = install_fake_gait(monkeypatch, FakeGait(), credential=None)
    code, out, err = main(["--dry-run", "--run-id", "ci:1:2"])
    assert code == 0, err
    assert fake.verify_calls == 0 and fake.sent == []
    bodies = [json.loads(line) for line in out.splitlines() if line.startswith("{")]
    assert [b["signal_type"] for b in bodies] == list(ALL)
    for body in bodies:
        assert set(body) == {"signal_type", "result", "source_reference", "payload"}
        assert body["source_reference"] == "ci:1:2"
        registry.validate_payload(body["signal_type"], body["payload"], result=body["result"])


def test_dry_run_json(monkeypatch):
    install_fake_gait(monkeypatch, FakeGait(), credential=None)
    code, out, _ = main(["--dry-run", "--json", "--environment", "staging"])
    data = json.loads(out)
    assert code == 0
    assert data["environment"] == "staging" and data["application"] is None
    assert data["dry_run"] is True
    assert len(data["requests"]) == len(ALL)
    assert set(data["results"][0]) == {"id", "outcome", "result", "facts", "sent", "error"}
    assert data["unmapped_django_ids"] == []


def test_json_report_shape_when_sending(monkeypatch):
    install_fake_gait(monkeypatch, FakeGait(environment="ci"))
    code, out, _ = main(["--json", "--run-id", "ci:x:y"])
    data = json.loads(out)
    assert code == 0
    assert set(data) == {"run_id", "application", "environment", "results", "unmapped_django_ids"}
    assert data["run_id"] == "ci:x:y" and data["application"] == "lumen-api" and data["environment"] == "ci"
    assert all(r["sent"] for r in data["results"])


# --- Secret never leaks ------------------------------------------------------------------
@pytest.mark.parametrize("argv", [["--dry-run"], ["--dry-run", "--json"], ["--json"], []])
def test_secret_key_never_appears_in_payloads_output_or_logs(monkeypatch, caplog, argv):
    fake = install_fake_gait(monkeypatch, FakeGait())
    caplog.set_level(logging.DEBUG)
    overrides = {"SECRET_KEY_FALLBACKS": [FALLBACK_SENTINEL, "dev"]}
    code, out, err = main(argv, **overrides)
    everything = out + err + caplog.text + json.dumps(fake.sent)
    assert SECRET_KEY not in everything
    assert FALLBACK_SENTINEL not in everything
    # no fragment either
    for fragment in (SECRET_KEY[:12], SECRET_KEY[-12:], FALLBACK_SENTINEL[:16]):
        assert fragment not in everything
    assert code == 1  # weak fallback fails


def test_weak_secret_key_never_appears_either(monkeypatch, caplog):
    fake = install_fake_gait(monkeypatch, FakeGait())
    caplog.set_level(logging.DEBUG)
    code, out, err = main(["--json"], SECRET_KEY=WEAK_SENTINEL)
    assert "WEAKsentinel" not in out + err + caplog.text + json.dumps(fake.sent)
    data = json.loads(out)
    strength = next(r for r in data["results"] if r["id"] == "CHK.DJANGO.SIGNING_KEY_STRENGTH")
    assert strength["outcome"] == "fail" and strength["facts"]["insecure_prefix"] is True
    assert "security.W009" in strength["facts"]["django_ids"]
    assert code == 1


def test_a_crashing_check_does_not_leak_its_exception_text(monkeypatch):
    from gait_sdk.checks import django_pack

    def boom():
        raise ValueError(SECRET_KEY)

    monkeypatch.setitem(django_pack.CHECKS, "CHK.DJANGO.HSTS", boom)
    install_fake_gait(monkeypatch, FakeGait(), credential=None)
    code, out, err = main(["--dry-run"])
    assert SECRET_KEY not in out + err


# --- Exit codes ------------------------------------------------------------------------------
def test_exit_0_when_clean(monkeypatch):
    install_fake_gait(monkeypatch, FakeGait())
    assert main([])[0] == 0


def test_exit_1_on_fail(monkeypatch):
    install_fake_gait(monkeypatch, FakeGait())
    assert main([], DEBUG=True)[0] == 1


def test_fail_on_levels(monkeypatch):
    install_fake_gait(monkeypatch, FakeGait())
    weak = {"SECURE_HSTS_SECONDS": 3600}
    assert main([], **weak)[0] == 0
    assert main(["--fail-on", "warning"], **weak)[0] == 1
    assert main(["--fail-on", "never"], DEBUG=True)[0] == 0


def test_fail_on_unknown(monkeypatch):
    from gait_sdk.checks import django_pack

    install_fake_gait(monkeypatch, FakeGait())
    monkeypatch.setitem(django_pack.CHECKS, "CHK.DJANGO.HSTS", lambda: 1 / 0)
    assert main([])[0] == 0
    assert main(["--fail-on-unknown"])[0] == 1


def test_exit_2_on_per_check_400(monkeypatch):
    fake = FakeGait()
    fake.always["CHK.DJANGO.HSTS"] = SecuritySignalRejected("bad")
    install_fake_gait(monkeypatch, fake)
    code, out, _ = main([])
    assert code == 2
    assert "Delivery failed" in out
    assert len(fake.sent) == len(ALL)


def test_exit_2_on_rejected_credential(monkeypatch):
    from gait_sdk.exceptions import InvalidApplicationCredentialError

    fake = FakeGait()
    fake.verify_errors = [InvalidApplicationCredentialError("no")]
    install_fake_gait(monkeypatch, fake)
    code, _, err = main([])
    assert code == 2 and "401" in err


def test_exit_3_on_environment_mismatch(monkeypatch):
    fake = install_fake_gait(monkeypatch, FakeGait(environment="staging"))
    code, _, err = main(["--environment", "production"])
    assert code == 3
    assert "staging" in err
    assert fake.sent == []


@pytest.mark.parametrize(
    "argv",
    [
        ["--pack", "fastapi"],
        ["--pack", "hipaa"],
        ["--pack", "django", "--deps-tool", "trivy"],
        ["--environment", "moon"],
        ["--fail-on", "sometimes"],
        ["--only", "CHK.DJANGO.NOPE"],
        ["--skip", "CHK.NOPE.X"],
        ["--run-id", "x" * 257],
        ["--no-such-flag"],
    ],
)
def test_exit_3_on_usage_errors(monkeypatch, argv):
    fake = install_fake_gait(monkeypatch, FakeGait())
    assert main(argv + ["--dry-run"])[0] == 3
    assert fake.sent == []


def test_exit_3_when_credential_missing(monkeypatch):
    install_fake_gait(monkeypatch, FakeGait(), credential=None)
    code, _, err = main([])
    assert code == 3 and "GAIT_APPLICATION_CREDENTIAL" in err


def test_no_send_gates_without_contacting_gait(monkeypatch):
    fake = install_fake_gait(monkeypatch, FakeGait(), credential=None)
    assert main(["--no-send"], DEBUG=True)[0] == 1
    assert main(["--no-send", "--environment", "local"], DEBUG=True)[0] == 0  # DEBUG_OFF is env-gated
    assert fake.verify_calls == 0 and fake.sent == []


def test_only_and_skip_flags(monkeypatch):
    fake = install_fake_gait(monkeypatch, FakeGait())
    code, out, _ = main(["--json", "--only", "CHK.DJANGO.HSTS", "--only", "CHK.DJANGO.COOP"])
    assert [r["id"] for r in json.loads(out)["results"]] == ["CHK.DJANGO.HSTS", "CHK.DJANGO.COOP"]
    assert [c["signal_type"] for c in fake.sent] == ["CHK.DJANGO.HSTS", "CHK.DJANGO.COOP"]
    fake.sent.clear()
    main(["--skip", "CHK.DJANGO.HSTS"])
    assert "CHK.DJANGO.HSTS" not in {c["signal_type"] for c in fake.sent}
    assert len(fake.sent) == len(ALL) - 1


def test_table_output(monkeypatch):
    install_fake_gait(monkeypatch, FakeGait())
    code, out, _ = main([], SECURE_HSTS_SECONDS=3600)
    assert "CHK.DJANGO.HSTS" in out and "WARNING" in out and "hsts_seconds=3600" in out
    assert "21 checks:" in out


# --- Management command ----------------------------------------------------------------------
def _deps_must_not_run(monkeypatch):
    from gait_sdk.checks import deps_pack

    def fail(ctx):
        raise AssertionError("the deps pack ran without --pack deps")

    monkeypatch.setitem(deps_pack.CHECKS, deps_pack.CHECK_ID, fail)


def test_management_command_dry_run(monkeypatch):
    fake = install_fake_gait(monkeypatch, FakeGait(), credential=None)
    _deps_must_not_run(monkeypatch)
    out = io.StringIO()
    with django_settings():
        call_command(Command(), "--dry-run", "--json", stdout=out)
    data = json.loads(out.getvalue())
    # The django pack only: dependency checks send package names to PyPI/OSV, so they're opt-in.
    assert [r["id"] for r in data["results"]] == list(ALL)
    assert fake.sent == []


def test_management_command_deps_is_opt_in(monkeypatch):
    install_fake_gait(monkeypatch, FakeGait(), credential=None)
    fake_deps(monkeypatch)
    out = io.StringIO()
    with django_settings():
        call_command(Command(), "--pack", "django", "--pack", "deps", "--dry-run", "--json", stdout=out)
    assert [r["id"] for r in json.loads(out.getvalue())["results"]] == list(ALL) + ["CHK.DEPS.KNOWN_VULNS"]


def test_management_command_rejects_the_fastapi_pack(monkeypatch):
    install_fake_gait(monkeypatch, FakeGait(), credential=None)
    with django_settings(), pytest.raises(SystemExit) as exc:
        call_command(Command(), "--pack", "fastapi", "--dry-run", stdout=io.StringIO(), stderr=io.StringIO())
    assert exc.value.code == 3


def test_management_command_django_pack_only(monkeypatch):
    install_fake_gait(monkeypatch, FakeGait(), credential=None)
    out = io.StringIO()
    with django_settings():
        call_command(Command(), "--pack", "django", "--dry-run", "--json", stdout=out)
    assert [r["id"] for r in json.loads(out.getvalue())["results"]] == list(ALL)


def test_management_command_sends_and_exits_with_the_same_codes(monkeypatch):
    fake = install_fake_gait(monkeypatch, FakeGait())
    _deps_must_not_run(monkeypatch)
    with django_settings(DEBUG=True), pytest.raises(SystemExit) as exc:
        call_command(Command(), "--run-id", "ci:m:1", stdout=io.StringIO())
    assert exc.value.code == 1
    assert len(fake.sent) == len(ALL)
    assert {c["source_reference"] for c in fake.sent} == {"ci:m:1"}


def test_management_command_environment_mismatch(monkeypatch):
    install_fake_gait(monkeypatch, FakeGait(environment="ci"))
    fake_deps(monkeypatch)
    with django_settings(), pytest.raises(SystemExit) as exc:
        call_command(Command(), "--environment", "production", stdout=io.StringIO(), stderr=io.StringIO())
    assert exc.value.code == 3


def test_management_command_has_no_settings_flag_of_its_own():
    parser = Command().create_parser("manage.py", "gait_check")
    own = {a.dest for a in parser._actions}
    assert "settings_module" not in own
    for dest in ("packs", "dry_run", "no_send", "environment", "as_json", "fail_on", "fail_on_unknown",
                 "run_id", "only", "skip"):
        assert dest in own


# --- Entry points, for real (subprocess; dry-run and no-send only, no network) -----------------------
def _env():
    env = dict(os.environ)
    env.pop("GAIT_APPLICATION_CREDENTIAL", None)
    env.pop("DJANGO_SETTINGS_MODULE", None)
    env["PYTHONPATH"] = str(ROOT)
    return env


def test_console_script_is_declared():
    scripts = {ep.name: ep.value for ep in entry_points(group="console_scripts")}
    assert scripts.get("gait-check") == "gait_sdk.checks.cli:main"


def test_gait_check_console_script_dry_run():
    exe = Path(sys.executable).parent / ("gait-check.exe" if os.name == "nt" else "gait-check")
    if not exe.exists():
        pytest.skip("gait-check script not installed in this environment")
    proc = subprocess.run(
        [str(exe), "--settings", "tests.checks_settings", "--dry-run", "--json"],
        capture_output=True, cwd=str(ROOT), env=_env(), timeout=120,
    )
    assert proc.returncode == 0, proc.stderr.decode()
    data = json.loads(proc.stdout.decode("utf-8"))
    assert len(data["requests"]) == len(ALL)
    assert SECRET_KEY.encode() not in proc.stdout + proc.stderr


def test_cli_module_without_settings_is_a_usage_error():
    proc = subprocess.run(
        [sys.executable, "-m", "gait_sdk.checks.cli", "--dry-run"],
        capture_output=True, cwd=str(ROOT), env=_env(), timeout=120,
    )
    assert proc.returncode == 3
    assert b"--settings" in proc.stderr


def test_cli_with_unimportable_settings_is_a_usage_error():
    proc = subprocess.run(
        [sys.executable, "-m", "gait_sdk.checks.cli", "--settings", "no_such_module.settings", "--dry-run"],
        capture_output=True, cwd=str(ROOT), env=_env(), timeout=120,
    )
    assert proc.returncode == 3


def test_manage_py_style_command_no_send():
    proc = subprocess.run(
        [sys.executable, "-m", "django", "gait_check", "--settings", "tests.checks_settings", "--pack", "django",
         "--no-send", "--environment", "local", "--json"],
        capture_output=True, cwd=str(ROOT), env=_env(), timeout=120,
    )
    assert proc.returncode == 0, proc.stderr.decode()
    data = json.loads(proc.stdout.decode("utf-8"))
    assert data["environment"] == "local"
    gated = [r for r in data["results"] if registry.get_check(r["id"]).env_gated]
    assert gated and all(r["outcome"] == "not_applicable" and r["facts"] == {} for r in gated)
