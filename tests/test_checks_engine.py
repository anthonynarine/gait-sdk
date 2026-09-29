"""CHK2a: the engine's delivery rules. All HTTP is mocked."""

import httpx
import pytest

from tests._checks_support import FakeGait, SleepRecorder, django_settings, install_fake_gait

from gait_sdk.checks import engine, registry
from gait_sdk.exceptions import (
    AuthServiceUnavailable,
    InvalidApplicationCredentialError,
    SecuritySignalRejected,
)

ALL = registry.check_ids("django")


def run(monkeypatch, fake=None, sleep=None, **kwargs):
    fake = fake or FakeGait()
    install_fake_gait(monkeypatch, fake)
    sleep = sleep or SleepRecorder()
    with django_settings():
        report = engine.execute(sleep=sleep, run_id=kwargs.pop("run_id", "ci:abc:build-1"), **kwargs)
    return report, fake, sleep


def test_every_payload_for_every_check_validates(monkeypatch):
    report, fake, _ = run(monkeypatch)
    assert [c["signal_type"] for c in fake.sent] == list(ALL)
    for call in fake.sent:
        registry.validate_payload(call["signal_type"], call["payload"], result=call["result"])
        assert call["source_reference"] == "ci:abc:build-1"
        assert call["result"] == registry.result_for_outcome(call["payload"]["outcome"])
    assert all(r.sent for r in report.results)
    assert engine.exit_code(report) == 0


@pytest.mark.parametrize("environment", ["local", "test", "ci", "staging", "production"])
def test_payloads_validate_in_every_environment_and_bad_config(monkeypatch, environment):
    fake = install_fake_gait(monkeypatch, FakeGait(environment=environment))
    with django_settings(DEBUG=True, ALLOWED_HOSTS=["*"], SECRET_KEY="dev", SECRET_KEY_FALLBACKS=["x"] * 5,
                         MIDDLEWARE=[], SECURE_HSTS_SECONDS=0, SECURE_REFERRER_POLICY=None,
                         SECURE_CROSS_ORIGIN_OPENER_POLICY="bogus", REST_FRAMEWORK={},
                         AUTH_PASSWORD_VALIDATORS=[], EMAIL_USE_TLS=False):
        report = engine.execute(sleep=SleepRecorder())
    assert len(fake.sent) == len(ALL)
    for call in fake.sent:
        registry.validate_payload(call["signal_type"], call["payload"], result=call["result"])
    assert report.environment == environment


def test_environment_comes_from_the_verified_application(monkeypatch):
    fake = FakeGait(environment="local")
    report, _, _ = run(monkeypatch, fake)
    assert report.environment == "local"
    assert report.application == "lumen-api"
    debug = next(r for r in report.results if r.check_id == "CHK.DJANGO.DEBUG_OFF")
    assert debug.outcome == "not_applicable"


def test_environment_mismatch_is_a_usage_error_and_sends_nothing(monkeypatch):
    fake = FakeGait(environment="staging")
    with pytest.raises(engine.EnvironmentMismatch):
        run(monkeypatch, fake, environment="production")
    assert fake.sent == []


def test_environment_assertion_that_matches_is_fine(monkeypatch):
    report, _, _ = run(monkeypatch, FakeGait(environment="staging"), environment="staging")
    assert report.environment == "staging"


# --- Retries --------------------------------------------------------------------------
def test_unavailable_is_retried_with_backoff_and_the_same_source_reference(monkeypatch):
    fake = FakeGait()
    fake.errors["CHK.DJANGO.HSTS"] = [AuthServiceUnavailable("down"), AuthServiceUnavailable("down")]
    report, fake, sleep = run(monkeypatch, fake)
    attempts = fake.attempts("CHK.DJANGO.HSTS")
    assert len(attempts) == 3
    assert {a["source_reference"] for a in attempts} == {"ci:abc:build-1"}
    assert attempts[0] == attempts[1] == attempts[2]
    assert sleep.calls == [1, 2]
    assert all(r.sent for r in report.results)
    assert engine.exit_code(report) == 0


def test_unavailable_after_all_retries_is_a_delivery_failure(monkeypatch):
    fake = FakeGait()
    fake.always["CHK.DJANGO.HSTS"] = AuthServiceUnavailable("down")
    report, fake, sleep = run(monkeypatch, fake)
    assert len(fake.attempts("CHK.DJANGO.HSTS")) == 1 + len(engine.RETRY_DELAYS)
    assert sleep.calls == [1, 2, 4]
    assert report.delivery_failed
    assert engine.exit_code(report) == 2
    # Gait is down: the remaining checks aren't attempted.
    later = ALL[ALL.index("CHK.DJANGO.HSTS") + 1:]
    for check_id in later:
        assert fake.attempts(check_id) == []
    assert all(not r.sent for r in report.results if r.check_id in later)


def test_400_is_never_retried_and_doesnt_stop_the_others(monkeypatch):
    fake = FakeGait()
    fake.always["CHK.DJANGO.HSTS"] = SecuritySignalRejected("bad")
    report, fake, sleep = run(monkeypatch, fake)
    assert len(fake.attempts("CHK.DJANGO.HSTS")) == 1
    assert sleep.calls == []
    assert len(fake.sent) == len(ALL)
    by_id = {r.check_id: r for r in report.results}
    assert not by_id["CHK.DJANGO.HSTS"].sent and "400" in by_id["CHK.DJANGO.HSTS"].error
    assert sum(r.sent for r in report.results) == len(ALL) - 1
    assert engine.exit_code(report) == 2


def test_401_is_never_retried(monkeypatch):
    fake = FakeGait()
    fake.always[ALL[0]] = InvalidApplicationCredentialError("no")
    report, fake, sleep = run(monkeypatch, fake)
    assert len(fake.sent) == 1
    assert sleep.calls == []
    assert engine.exit_code(report) == 2


def test_401_on_verify_is_a_delivery_failure(monkeypatch):
    fake = FakeGait()
    fake.verify_errors = [InvalidApplicationCredentialError("no")]
    with pytest.raises(engine.DeliveryError):
        run(monkeypatch, fake)
    assert fake.verify_calls == 1
    assert fake.sent == []


def test_verify_is_retried_when_unavailable(monkeypatch):
    fake = FakeGait()
    fake.verify_errors = [AuthServiceUnavailable("down")]
    report, fake, sleep = run(monkeypatch, fake)
    assert fake.verify_calls == 2
    assert sleep.calls == [1]
    assert all(r.sent for r in report.results)


def test_missing_credential_is_a_usage_error(monkeypatch):
    install_fake_gait(monkeypatch, FakeGait(), credential=None)
    with django_settings(), pytest.raises(engine.UsageError):
        engine.execute(sleep=SleepRecorder())


# --- Local validation ---------------------------------------------------------------
def test_an_invalid_payload_is_never_sent(monkeypatch):
    from gait_sdk.checks import django_pack

    monkeypatch.setitem(django_pack.CHECKS, "CHK.DJANGO.NOSNIFF", lambda: ("ok", {"nosniff": "yes please"}))
    report, fake, _ = run(monkeypatch)
    assert fake.attempts("CHK.DJANGO.NOSNIFF") == []
    item = next(r for r in report.results if r.check_id == "CHK.DJANGO.NOSNIFF")
    assert not item.valid and not item.sent
    assert "facts.nosniff" in item.error
    assert len(fake.sent) == len(ALL) - 1
    assert engine.exit_code(report) == 2


# --- Offline modes --------------------------------------------------------------------
def test_no_send_needs_no_credential_and_sends_nothing(monkeypatch):
    fake = install_fake_gait(monkeypatch, FakeGait(), credential=None)
    with django_settings():
        report = engine.execute(send=False)
    assert fake.verify_calls == 0 and fake.sent == []
    assert report.environment == "production"
    assert report.application is None


def test_offline_environment_flag_is_used(monkeypatch):
    with django_settings():
        report = engine.execute(send=False, environment="test")
    assert report.environment == "test"


# --- Selection ------------------------------------------------------------------------
def test_only_and_skip(monkeypatch):
    report, fake, _ = run(monkeypatch, only=["CHK.DJANGO.HSTS", "CHK.DJANGO.COOP"])
    assert [r.check_id for r in report.results] == ["CHK.DJANGO.HSTS", "CHK.DJANGO.COOP"]
    report, fake, _ = run(monkeypatch, skip=["CHK.DJANGO.HSTS"])
    assert "CHK.DJANGO.HSTS" not in [c["signal_type"] for c in fake.sent]
    assert len(fake.sent) == len(ALL) - 1


def test_unknown_check_id_is_a_usage_error(monkeypatch):
    fake = FakeGait()
    with pytest.raises(engine.UsageError):
        run(monkeypatch, fake, only=["CHK.DJANGO.NOPE"])
    assert fake.verify_calls == 0


def test_bad_run_id_is_a_usage_error(monkeypatch):
    with pytest.raises(engine.UsageError):
        run(monkeypatch, run_id="x" * 257)
    with pytest.raises(engine.UsageError):
        run(monkeypatch, run_id="")


def test_default_run_id_shape():
    run_id = engine.default_run_id()
    assert run_id.startswith("run:") and len(run_id) == 40


# --- Exit codes -----------------------------------------------------------------------
def _report(*pairs, delivery_failed=False):
    report = engine.RunReport(run_id="r", environment="production", delivery_failed=delivery_failed)
    for outcome in pairs:
        report.results.append(engine.CheckResult("CHK.DJANGO.HSTS", outcome, {}, registry.result_for_outcome(outcome)))
    return report


@pytest.mark.parametrize(
    "outcomes,fail_on,unknown,expected",
    [
        (("ok", "not_applicable"), "fail", False, 0),
        (("ok", "fail"), "fail", False, 1),
        (("ok", "weak"), "fail", False, 0),
        (("ok", "weak"), "warning", False, 1),
        (("fail",), "never", False, 0),
        (("ok", "error"), "fail", False, 0),
        (("ok", "error"), "fail", True, 1),
        (("ok", "unknown"), "never", True, 1),
        (("ok", "not_applicable"), "fail", True, 0),
    ],
)
def test_exit_codes(outcomes, fail_on, unknown, expected):
    assert engine.exit_code(_report(*outcomes), fail_on, unknown) == expected


def test_delivery_failure_beats_threshold():
    assert engine.exit_code(_report("fail", delivery_failed=True)) == 2


# --- Real wire path (httpx mocked) ---------------------------------------------------
def test_real_send_path_posts_one_signal_per_check(monkeypatch):
    import gait_sdk.application as application
    import gait_sdk.security as security

    monkeypatch.setattr(application, "GAIT_APPLICATION_CREDENTIAL", "cred-value")
    monkeypatch.setattr(security, "GAIT_APPLICATION_CREDENTIAL", "cred-value")
    posted = []

    class Resp:
        def __init__(self, status, body):
            self.status_code = status
            self._body = body

        def json(self):
            return self._body

    async def fake_post(self, url, headers=None, json=None):
        posted.append((url, json))
        if url.endswith("/applications/verify/"):
            return Resp(200, {"application_id": "a", "application_slug": "lumen-api", "organization_id": "o",
                              "organization_slug": "acme", "environment": "production"})
        if json["signal_type"] == "CHK.DJANGO.COOP":
            return Resp(400, {"detail": "Invalid tenant security signal."})
        return Resp(201, {"signal_id": "s", "control_key": "c", "evidence_id": None, "received_at": "t"})

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    with django_settings():
        report = engine.execute(run_id="ci:sha:job", sleep=SleepRecorder())
    signals = [body for url, body in posted if url.endswith("/security/tenant-signals/")]
    assert len(signals) == len(ALL)
    assert {s["source_reference"] for s in signals} == {"ci:sha:job"}
    assert set(signals[0]) == {"signal_type", "result", "source_reference", "payload"}
    assert engine.exit_code(report) == 2
    assert sum(r.sent for r in report.results) == len(ALL) - 1
