"""CHK2b: the accepted-types endpoint and batch delivery. All HTTP is mocked."""

import asyncio
import io
import json

import httpx
import pytest

from tests._checks_support import FakeGait, SleepRecorder, django_settings, install_fake_gait

from gait_sdk import security
from gait_sdk.application import APPLICATION_CREDENTIAL_HEADER
from gait_sdk.checks import cli, engine, registry
from gait_sdk.exceptions import (
    AuthServiceUnavailable,
    InvalidApplicationCredentialError,
    SecuritySignalRejected,
    SignalEndpointNotFound,
    SignalRateLimited,
)

ALL = registry.check_ids("django")


def execute(monkeypatch, fake, **kwargs):
    install_fake_gait(monkeypatch, fake)
    sleep = kwargs.pop("sleep", SleepRecorder())
    with django_settings():
        report = engine.execute(run_id="ci:batch:1", sleep=sleep, **kwargs)
    return report, sleep


def rejected(index=None, field=None, code="PAYLOAD_SCHEMA"):
    exc = SecuritySignalRejected("Invalid tenant security signal.")
    exc.code_name, exc.index, exc.field = code, index, field
    return exc


# --- Engine: chunking and fallbacks ---------------------------------------------------------
def test_types_are_fetched_once_and_chunks_respect_batch_max(monkeypatch):
    fake = FakeGait().enable_batch(batch_max=8)
    report, _ = execute(monkeypatch, fake)
    assert fake.types_calls == 1
    assert [len(b) for b in fake.batches] == [8, 8, 5]
    assert fake.sent == []  # no single POSTs
    flat = [s for b in fake.batches for s in b]
    assert [s["signal_type"] for s in flat] == list(ALL)
    assert {s["source_reference"] for s in flat} == {"ci:batch:1"}
    for s in flat:
        assert set(s) == {"signal_type", "result", "source_reference", "payload"}
        registry.validate_payload(s["signal_type"], s["payload"], result=s["result"])
    assert all(r.sent for r in report.results)
    assert engine.exit_code(report) == 0


def test_one_batch_when_everything_fits(monkeypatch):
    fake = FakeGait().enable_batch(batch_max=50)
    execute(monkeypatch, fake)
    assert [len(b) for b in fake.batches] == [len(ALL)]


def test_unsupported_ids_are_skipped_and_dont_fail_the_run(monkeypatch):
    supported = [cid for cid in ALL if cid != "CHK.DJANGO.HSTS"]
    fake = FakeGait().enable_batch(signal_types=supported)
    report, _ = execute(monkeypatch, fake)
    flat = [s["signal_type"] for b in fake.batches for s in b]
    assert "CHK.DJANGO.HSTS" not in flat and len(flat) == len(ALL) - 1
    hsts = next(r for r in report.results if r.check_id == "CHK.DJANGO.HSTS")
    assert not hsts.sent and hsts.error == engine.NOT_SUPPORTED
    assert engine.exit_code(report) == 0


def test_types_without_batch_max_means_single_posts(monkeypatch):
    fake = FakeGait().enable_batch(batch_max=None)
    report, _ = execute(monkeypatch, fake)
    assert fake.batches == []
    assert len(fake.sent) == len(ALL)


def test_batch_404_falls_back_to_single_posts(monkeypatch):
    fake = FakeGait().enable_batch(batch_max=8)
    fake.batch_errors = [SignalEndpointNotFound()]
    report, _ = execute(monkeypatch, fake)
    assert len(fake.batches) == 1  # tried once
    assert [s["signal_type"] for s in fake.sent] == list(ALL)
    assert all(r.sent for r in report.results)
    assert engine.exit_code(report) == 0


@pytest.mark.parametrize("error", [SignalEndpointNotFound(), AuthServiceUnavailable("down")])
def test_types_endpoint_missing_or_down_sends_everything_singly(monkeypatch, error):
    fake = FakeGait()
    fake.types = error
    report, sleep = execute(monkeypatch, fake)
    assert fake.batches == []
    assert len(fake.sent) == len(ALL)
    assert engine.exit_code(report) == 0
    if isinstance(error, AuthServiceUnavailable):
        assert fake.types_calls == 1 + len(engine.RETRY_DELAYS)  # retried like any unavailable


def test_types_401_is_a_delivery_failure(monkeypatch):
    fake = FakeGait()
    fake.types = InvalidApplicationCredentialError("no")
    with pytest.raises(engine.DeliveryError):
        execute(monkeypatch, fake)
    assert fake.sent == [] and fake.batches == []


def test_no_batch_forces_single_posts(monkeypatch):
    fake = FakeGait().enable_batch(batch_max=50)
    report, _ = execute(monkeypatch, fake, batch=False)
    assert fake.batches == []
    assert len(fake.sent) == len(ALL)


def test_no_batch_cli_flag(monkeypatch):
    fake = install_fake_gait(monkeypatch, FakeGait().enable_batch())
    with django_settings():
        code = cli.main(["--no-batch"], out=io.StringIO(), err=io.StringIO(), sleep=SleepRecorder())
    assert code == 0
    assert fake.batches == [] and len(fake.sent) == len(ALL)


# --- Engine: errors -----------------------------------------------------------------------------
def test_400_marks_the_whole_chunk_with_index_and_field(monkeypatch):
    fake = FakeGait().enable_batch(batch_max=8)
    calls = {"n": 0}
    original = fake.send_security_signals_batch

    async def second_chunk_rejected(signals, credential=None):
        calls["n"] += 1
        if calls["n"] == 2:
            fake.batches.append(list(signals))
            raise rejected(index=3, field="facts.hsts_seconds")
        return await original(signals, credential)

    install_fake_gait(monkeypatch, fake)
    monkeypatch.setattr(security, "send_security_signals_batch", second_chunk_rejected)
    with django_settings():
        report = engine.execute(run_id="ci:batch:1", sleep=SleepRecorder())
    chunk2 = ALL[8:16]
    by_id = {r.check_id: r for r in report.results}
    for position, cid in enumerate(chunk2):
        assert not by_id[cid].sent
        if position == 3:
            assert "batch item 3" in by_id[cid].error and "facts.hsts_seconds" in by_id[cid].error
        else:
            assert by_id[cid].error == "not sent: batch rejected (400)"
    assert all(by_id[cid].sent for cid in ALL[:8] + ALL[16:])  # the other chunks went through
    assert engine.exit_code(report) == 2
    assert "400" in report.delivery_error


def test_400_is_never_retried(monkeypatch):
    fake = FakeGait().enable_batch()
    fake.batch_errors = [rejected(code="BATCH_INVALID")]
    report, sleep = execute(monkeypatch, fake)
    assert len(fake.batches) == 1
    assert sleep.calls == []
    assert engine.exit_code(report) == 2


def test_429_waits_retry_after_once_then_retries(monkeypatch):
    fake = FakeGait().enable_batch()
    fake.batch_errors = [SignalRateLimited(retry_after=7)]
    report, sleep = execute(monkeypatch, fake)
    assert sleep.calls == [7]
    assert len(fake.batches) == 2 and fake.batches[0] == fake.batches[1]
    assert all(r.sent for r in report.results)
    assert engine.exit_code(report) == 0


def test_429_wait_is_capped_at_60_seconds(monkeypatch):
    fake = FakeGait().enable_batch()
    fake.batch_errors = [SignalRateLimited(retry_after=600)]
    _, sleep = execute(monkeypatch, fake)
    assert sleep.calls == [60]


def test_429_twice_is_a_delivery_failure(monkeypatch):
    fake = FakeGait().enable_batch(batch_max=8)
    fake.batch_errors = [SignalRateLimited(retry_after=2), SignalRateLimited(retry_after=2)]
    report, sleep = execute(monkeypatch, fake)
    assert sleep.calls == [2]
    assert len(fake.batches) == 2  # the retry, then stop: the rest isn't attempted
    assert not any(r.sent for r in report.results)
    assert engine.exit_code(report) == 2


def test_unavailable_batch_is_retried_with_backoff(monkeypatch):
    fake = FakeGait().enable_batch()
    fake.batch_errors = [AuthServiceUnavailable("down"), AuthServiceUnavailable("down")]
    report, sleep = execute(monkeypatch, fake)
    assert sleep.calls == [1, 2]
    assert len(fake.batches) == 3 and fake.batches[0] == fake.batches[2]  # same source_reference
    assert engine.exit_code(report) == 0


def test_401_on_batch_stops_the_run(monkeypatch):
    fake = FakeGait().enable_batch(batch_max=8)
    fake.batch_errors = [InvalidApplicationCredentialError("no")]
    report, sleep = execute(monkeypatch, fake)
    assert len(fake.batches) == 1 and sleep.calls == []
    assert not any(r.sent for r in report.results)
    assert engine.exit_code(report) == 2


# --- HTTP layer (httpx mocked) --------------------------------------------------------------------
class Resp:
    def __init__(self, status, body=None, headers=None):
        self.status_code = status
        self._body = body
        self.headers = headers or {}

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


RESULT = {"signal_id": "s", "control_key": "TENANT.CHECK.DJANGO.HSTS", "evidence_id": None, "received_at": "t"}
SIGNAL = {"signal_type": "CHK.DJANGO.HSTS", "result": "PASS", "source_reference": "run:1",
          "payload": {"v": 1, "pack": "django", "pack_version": "1.0.0", "sdk_version": "0.6.0", "outcome": "ok",
                      "facts": {}}}


@pytest.fixture
def http(monkeypatch):
    monkeypatch.setattr(security, "GAIT_AUTH_URL", "https://gait.example.com/api")
    monkeypatch.setattr(security, "GAIT_APPLICATION_CREDENTIAL", "cred-value")
    captured = {}

    def respond(response, method="post"):
        async def handler(self, url, headers=None, json=None):
            captured.update(url=url, headers=headers or {}, json=json, method=method)
            if isinstance(response, Exception):
                raise response
            return response

        monkeypatch.setattr(httpx.AsyncClient, method, handler)
        return captured

    return respond


def test_batch_http_contract(http):
    captured = http(Resp(201, {"results": [RESULT, RESULT]}))
    results = asyncio.run(security.send_security_signals_batch([SIGNAL, SIGNAL]))
    assert captured["url"] == "https://gait.example.com/api/security/tenant-signals/batch/"
    assert captured["headers"] == {APPLICATION_CREDENTIAL_HEADER: "cred-value"}
    assert captured["json"] == {"signals": [SIGNAL, SIGNAL]}
    assert [r.control_key for r in results] == ["TENANT.CHECK.DJANGO.HSTS"] * 2


def test_batch_http_errors(http):
    http(Resp(404))
    with pytest.raises(SignalEndpointNotFound):
        asyncio.run(security.send_security_signals_batch([SIGNAL]))
    http(Resp(401))
    with pytest.raises(InvalidApplicationCredentialError):
        asyncio.run(security.send_security_signals_batch([SIGNAL]))
    http(Resp(400, {"detail": "x", "code": "PAYLOAD_SCHEMA", "index": 0, "field": "facts.debug"}))
    with pytest.raises(SecuritySignalRejected) as exc:
        asyncio.run(security.send_security_signals_batch([SIGNAL]))
    assert (exc.value.code_name, exc.value.index, exc.value.field) == ("PAYLOAD_SCHEMA", 0, "facts.debug")
    http(Resp(400, {"code": "BATCH_INVALID", "field": "<script>alert(1)</script>"}))
    with pytest.raises(SecuritySignalRejected) as exc:
        asyncio.run(security.send_security_signals_batch([SIGNAL]))
    assert exc.value.code_name == "BATCH_INVALID" and exc.value.field is None and exc.value.index is None
    http(Resp(429, {"code": "RATE_LIMITED"}, {"Retry-After": "12"}))
    with pytest.raises(SignalRateLimited) as exc:
        asyncio.run(security.send_security_signals_batch([SIGNAL]))
    assert exc.value.retry_after == 12
    http(Resp(429, {"code": "RATE_LIMITED"}))
    with pytest.raises(SignalRateLimited) as exc:
        asyncio.run(security.send_security_signals_batch([SIGNAL]))
    assert exc.value.retry_after is None
    http(Resp(201, {"results": [RESULT]}))  # wrong count
    with pytest.raises(AuthServiceUnavailable):
        asyncio.run(security.send_security_signals_batch([SIGNAL, SIGNAL]))
    http(httpx.ConnectError("down"))
    with pytest.raises(AuthServiceUnavailable):
        asyncio.run(security.send_security_signals_batch([SIGNAL]))
    http(Resp(502))
    with pytest.raises(AuthServiceUnavailable):
        asyncio.run(security.send_security_signals_batch([SIGNAL]))


def test_batch_rejects_bad_local_input_before_any_request(http):
    captured = http(Resp(201, {"results": [RESULT]}))
    for bad in ([], [dict(SIGNAL, extra=1)], [dict(SIGNAL, signal_type="")]):
        with pytest.raises(SecuritySignalRejected):
            asyncio.run(security.send_security_signals_batch(bad))
    assert captured == {}


def test_types_http_contract(http):
    body = {"signal_types": list(registry.check_ids()), "check_spec_version": 1,
            "check_spec_sha256": registry.CHECKS_V1_CANONICAL_SHA256, "batch_max": 50}
    captured = http(Resp(200, body), method="get")
    info = asyncio.run(security.get_signal_types())
    assert captured["url"] == "https://gait.example.com/api/security/tenant-signals/types/"
    assert captured["headers"] == {APPLICATION_CREDENTIAL_HEADER: "cred-value"}
    assert info.batch_max == 50 and set(info.signal_types) == set(registry.check_ids())


def test_types_http_errors(http):
    http(Resp(404), method="get")
    with pytest.raises(SignalEndpointNotFound):
        asyncio.run(security.get_signal_types())
    http(Resp(401), method="get")
    with pytest.raises(InvalidApplicationCredentialError):
        asyncio.run(security.get_signal_types())
    http(Resp(200, {"signal_types": "all"}), method="get")
    with pytest.raises(AuthServiceUnavailable):
        asyncio.run(security.get_signal_types())
    http(Resp(200, {"signal_types": ["CHK.DJANGO.HSTS"], "batch_max": "lots"}), method="get")
    assert asyncio.run(security.get_signal_types()).batch_max is None


def test_end_to_end_over_mocked_http(monkeypatch):
    """Types + batch through the real security functions (httpx mocked)."""
    import gait_sdk.application as application

    monkeypatch.setattr(application, "GAIT_APPLICATION_CREDENTIAL", "cred-value")
    monkeypatch.setattr(security, "GAIT_APPLICATION_CREDENTIAL", "cred-value")
    posts = []

    async def fake_get(self, url, headers=None):
        return Resp(200, {"signal_types": list(ALL), "check_spec_version": 1,
                          "check_spec_sha256": registry.CHECKS_V1_CANONICAL_SHA256, "batch_max": 10})

    async def fake_post(self, url, headers=None, json=None):
        posts.append((url, json))
        if url.endswith("/applications/verify/"):
            return Resp(200, {"application_id": "a", "application_slug": "lumen-api", "organization_id": "o",
                              "organization_slug": "acme", "environment": "production"})
        return Resp(201, {"results": [RESULT] * len(json["signals"])})

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)
    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    out = io.StringIO()
    with django_settings():
        code = cli.main(["--json", "--run-id", "ci:e2e:1"], out=out, err=io.StringIO(), sleep=SleepRecorder())
    assert code == 0
    batches = [body["signals"] for url, body in posts if url.endswith("/tenant-signals/batch/")]
    assert [len(b) for b in batches] == [10, 10, 1]
    assert all(r["sent"] for r in json.loads(out.getvalue())["results"])
