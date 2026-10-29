"""No real credentials/network; protocol/transport boundaries with MockTransport."""
import base64
from dataclasses import replace
import json
import asyncio
from functools import wraps
import httpx
import pytest
from gait_sdk.confidential import (
    ConfidentialConfig, AsyncConfidentialClient, ConfidentialDenied, ConfidentialThrottled,
    ConfidentialUnavailable, ConfidentialProtocolError, AmbiguousRefresh, StaleActivity,
)

def _run_async(function):
    @wraps(function)
    def run(*args, **kwargs):
        return asyncio.run(function(*args, **kwargs))
    return run


APP = "11111111-1111-4111-8111-111111111111"
SID = "22222222-2222-4222-8222-222222222222"
AUD = "urn:gait:application:33333333-3333-4333-8333-333333333333"
SECRET = "s" * 43
CONFIG = ConfidentialConfig("https://api.dev.example.test/api", APP, AUD, SECRET)


def token(aud=AUD):
    body = base64.urlsafe_b64encode(json.dumps({"aud": aud, "sid": SID}).encode()).decode().rstrip("=")
    return "e30." + body + ".synthetic-signature"


def pair(mfa=False):
    return {"access_token": token(), "refresh_token": "synthetic-refresh", "token_type": "Bearer", **({"sid": SID, "aud": AUD} if mfa else {})}


def status(assurance=True):
    return {"sid": SID, "aud": AUD, "policy_enabled": True, "server_time": "2026-10-20T12:00:00Z",
            "idle_expires_at": "2026-10-20T13:00:00Z", "overall_expires_at": "2026-10-21T12:00:00Z", "activity_generation": 2,
            **({"assurance": {"amr": ["pwd", "otp", "mfa"], "acr": "urn:gait:assurance:password-totp", "auth_time": 123, "gait_mfa_time": 123}} if assurance else {})}


@pytest.mark.parametrize("url", ["http://api.example.test/api", "https://api.example.test/api/", "https://USER@api.example.test/api", "https://api.example.test:443/api", "https://API.example.test/api", "https://api.example.test/api?x=y", "https://api.example.test/api#x", "https://localhost/api", "https://service.localhost/api", "https://127.1/api", "https://auth.123/api", "https://0x7f000001/api", "https://api.example.test/%61pi", "https://api.example.test/api\n"])
def test_noncanonical_api_denied(url):
    with pytest.raises(ValueError, match="Invalid confidential configuration"):
        replace(CONFIG, api_base_url=url)


@pytest.mark.parametrize("change", [{"application_id": APP.upper().replace("1", "A", 1)}, {"application_id": "{"+APP+"}"}, {"audience": "urn:gait:console"}, {"credential": "secret\r\nCookie: x"}, {"credential": ""}, {"audience": AUD.upper()}])
def test_config_identity_denials_and_hidden_repr(change):
    with pytest.raises(ValueError):replace(CONFIG, **change)
    assert SECRET not in repr(CONFIG)
    assert SECRET not in repr(AsyncConfidentialClient(CONFIG))


@_run_async
async def test_all_six_operations_fixed_paths_headers_bodies_no_ambient_cookies(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://untrusted-proxy.invalid")
    calls = []
    def handler(request):
        calls.append(request)
        assert request.url.host == "api.dev.example.test"
        assert request.headers["Gait-Application-Credential"] == SECRET
        assert not any(name in request.headers for name in ("cookie", "authorization", "origin"))
        operation = request.url.path.split("/")[-2]
        result = {"login": {"mfa_required": True, "mfa_transaction": "opaque", "expires_in": 120},
                  "mfa": pair(True), "refresh": pair(), "logout": {"revoked": True}, "status": status(), "activity": status(False)}[operation]
        return httpx.Response(200, json=result, headers={"Set-Cookie": "ambient=bad; Path=/"})
    client = AsyncConfidentialClient(CONFIG, transport=httpx.MockTransport(handler))
    assert (await client.login(email="synthetic@example.test", password="Unicode password ☃"))["mfa_required"]
    await client.complete_mfa(mfa_transaction="opaque", otp="123456")
    await client.refresh(refresh_token="synthetic")
    await client.logout(refresh_token="synthetic")
    await client.status(access_token="synthetic")
    await client.activity(access_token="synthetic", generation=2)
    assert len(calls) == 6
    assert all(request.url.path.startswith("/api/application-auth/"+APP+"/") for request in calls)
    assert json.loads(calls[-1].content) == {"access_token": "synthetic", "generation": 2}


@pytest.mark.parametrize("code,error", [(401, ConfidentialDenied), (403, ConfidentialDenied), (429, ConfidentialThrottled), (503, ConfidentialUnavailable), (302, ConfidentialProtocolError), (418, ConfidentialProtocolError)])
@_run_async
async def test_errors_are_secret_free_not_redirected_or_retried(code, error):
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(code, text=SECRET+" upstream body", headers={"Location": "https://evil.example/"})
    client = AsyncConfidentialClient(CONFIG, transport=httpx.MockTransport(handler))
    with pytest.raises(error) as caught:await client.login(email="a", password=SECRET)
    assert SECRET not in str(caught.value) and SECRET not in repr(caught.value)
    assert len(calls) == 1


@pytest.mark.parametrize("result", [None, [], {}, {"mfa_required": 1, "mfa_transaction": "opaque", "expires_in": 120}, {"mfa_required": True, "mfa_transaction": "opaque", "expires_in": True}, {"mfa_required": True, "mfa_transaction": "opaque", "expires_in": 120, "access_token": "unexpected"}])
@_run_async
async def test_malformed_login_responses_denied(result):
    client = AsyncConfidentialClient(CONFIG, transport=httpx.MockTransport(lambda r: httpx.Response(200, json=result)))
    with pytest.raises(ConfidentialProtocolError):await client.login(email="a", password="b")


@_run_async
async def test_optional_password_login_returns_bound_pair_without_mfa_call():
    result = {**pair(True), "mfa_required": False}
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=result)
    client = AsyncConfidentialClient(CONFIG, transport=httpx.MockTransport(handler))
    assert await client.login(email="synthetic@example.test", password="synthetic-password") == result
    assert len(calls) == 1
    assert calls[0].url.path.endswith("/login/")
    assert "mfa_transaction" not in result


@pytest.mark.parametrize("change", [
    {"mfa_required": 0}, {"mfa_required": "false"}, {"mfa_required": None},
    {"mfa_required": True}, {"mfa_transaction": "unexpected"}, {"expires_in": 120},
    {"sid": APP}, {"aud": "foreign"}, {"access_token": token("foreign")},
    {"refresh_token": ""}, {"token_type": "bearer"}, {"access_token": "malformed"},
])
@_run_async
async def test_optional_login_rejects_mixed_or_unbound_responses_without_retry(change):
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={**pair(True), "mfa_required": False, **change})
    client = AsyncConfidentialClient(CONFIG, transport=httpx.MockTransport(handler))
    with pytest.raises(ConfidentialProtocolError):
        await client.login(email="synthetic@example.test", password="synthetic-password")
    assert len(calls) == 1


@_run_async
async def test_pair_without_explicit_login_outcome_is_not_assumed_success():
    client = AsyncConfidentialClient(CONFIG, transport=httpx.MockTransport(lambda r: httpx.Response(200, json=pair(True))))
    with pytest.raises(ConfidentialProtocolError):
        await client.login(email="synthetic@example.test", password="synthetic-password")


@pytest.mark.parametrize("bad", [{**pair(True), "aud": "foreign"}, {**pair(True), "sid": APP}, {**pair(True), "access_token": token("foreign")}, {**pair(True), "token_type": "bearer"}, {**pair(True), "access_token": "malformed"}])
@_run_async
async def test_pair_identity_and_shape_denied(bad):
    client = AsyncConfidentialClient(CONFIG, transport=httpx.MockTransport(lambda r: httpx.Response(200, json=bad)))
    with pytest.raises(ConfidentialProtocolError):await client.complete_mfa(mfa_transaction="a", otp="b")


@pytest.mark.parametrize("bad", [{**status(), "aud": "foreign"}, {**status(), "activity_generation": True}, {**status(), "policy_enabled": False}, {**status(), "server_time": None}, {**status(), "idle_expires_at": "2020-01-01T00:00:00Z"}, {**status(), "assurance": {"acr": "x", "amr": "mfa"}}])
@_run_async
async def test_status_scope_and_clock_shape_denied(bad):
    client = AsyncConfidentialClient(CONFIG, transport=httpx.MockTransport(lambda r: httpx.Response(200, json=bad)))
    with pytest.raises(ConfidentialProtocolError):await client.status(access_token="a")


@pytest.mark.parametrize("failure", ["timeout", "503", "invalid-json", "wrong-audience", "redirect"])
@_run_async
async def test_refresh_ambiguous_outcome_is_never_retried(failure):
    count = 0
    def handler(request):
        nonlocal count
        count += 1
        if failure == "timeout":raise httpx.ReadTimeout(SECRET, request=request)
        if failure == "503":return httpx.Response(503, text=SECRET)
        if failure == "invalid-json":return httpx.Response(200, text=SECRET)
        if failure == "redirect":return httpx.Response(302, headers={"Location": "https://evil.example/"})
        return httpx.Response(200, json={**pair(), "access_token": token("foreign")})
    client = AsyncConfidentialClient(CONFIG, transport=httpx.MockTransport(handler))
    with pytest.raises(AmbiguousRefresh) as caught:await client.refresh(refresh_token=SECRET)
    assert count == 1 and SECRET not in str(caught.value)


@_run_async
async def test_total_timeout_and_stale_generation():
    async def slow(request):
        await asyncio.sleep(.1)
        return httpx.Response(200, json=pair())
    client = AsyncConfidentialClient(CONFIG, transport=httpx.MockTransport(slow), timeout=.01)
    with pytest.raises(AmbiguousRefresh):await client.refresh(refresh_token="a")
    client = AsyncConfidentialClient(CONFIG, transport=httpx.MockTransport(lambda r: httpx.Response(409)))
    with pytest.raises(StaleActivity):await client.activity(access_token="a", generation=1)


@_run_async
async def test_invalid_inputs_never_send_and_no_caller_client_or_headers():
    def handler(request):raise AssertionError("Must not send")
    client = AsyncConfidentialClient(CONFIG, transport=httpx.MockTransport(handler))
    with pytest.raises(ValueError):await client._request("unknown", {})
    with pytest.raises(ValueError):await client._request("login", {"email": "a", "password": "b", "Origin": "bad"})
    with pytest.raises(ValueError):await client.activity(access_token="a", generation=True)
    with pytest.raises(ValueError):await client.complete_mfa(mfa_transaction="a", otp="b", recovery_code="c")
    with pytest.raises(TypeError):AsyncConfidentialClient(CONFIG, client=object())
    with pytest.raises(TypeError):await client.login(email="a", password="b", headers={"Cookie": "bad"})


@_run_async
async def test_oversized_response_rejected():
    client = AsyncConfidentialClient(CONFIG, transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b"x"*131073)))
    with pytest.raises(ConfidentialProtocolError):await client.status(access_token="a")


@pytest.mark.parametrize("assurance", [
    {"amr": ["mfa"], "acr": "unknown-custom"},
    {"amr": ["pwd"], "acr": "urn:gait:assurance:recovery-code", "auth_time": 123, "gait_mfa_time": 123},
    {"amr": [], "acr": "urn:gait:assurance:unknown", "auth_time": 123},
    {"amr": ["pwd", "otp", "mfa"], "acr": "urn:gait:assurance:password-totp", "auth_time": 123},
])
@_run_async
async def test_inconsistent_assurance_denied(assurance):
    client = AsyncConfidentialClient(CONFIG, transport=httpx.MockTransport(lambda r: httpx.Response(200, json={**status(), "assurance": assurance})))
    with pytest.raises(ConfidentialProtocolError):await client.status(access_token="a")


@_run_async
async def test_tls_proxy_redirect_configuration_is_not_caller_mutable(monkeypatch):
    original = httpx.AsyncClient
    seen = []
    def construct(**kwargs):
        seen.append(kwargs)
        return original(**kwargs)
    monkeypatch.setattr(httpx, "AsyncClient", construct)
    client = AsyncConfidentialClient(CONFIG, transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"revoked": True})))
    await client.logout(refresh_token="synthetic")
    assert seen[0]["verify"] is True
    assert seen[0]["trust_env"] is False
    assert seen[0]["follow_redirects"] is False
    assert not any(key in seen[0] for key in ("cookies", "auth", "headers", "proxy", "proxies"))


@_run_async
async def test_success_body_wrong_content_type_denied():
    client = AsyncConfidentialClient(CONFIG, transport=httpx.MockTransport(lambda r: httpx.Response(200, text=json.dumps({"revoked": True}))))
    with pytest.raises(ConfidentialProtocolError):await client.logout(refresh_token="synthetic")
