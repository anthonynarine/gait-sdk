"""0.4.0 SessionChecker: live Gait session confirmation for sensitive operations."""

import httpx
import pytest

from auth_integration.exceptions import AuthServiceUnavailable, InvalidTokenError
from auth_integration.session import acheck_session_live, check_session_live


class _Resp:
    def __init__(self, status, body=None, raise_json=False):
        self.status_code = status
        self._body = body
        self._raise = raise_json

    def json(self):
        if self._raise:
            raise ValueError("bad json")
        return self._body


@pytest.fixture
def gait(monkeypatch):
    """Patch the live /whoami/ call (sync + async) and record what was sent."""
    state = {"response": _Resp(200, {"id": "123", "email": "tech@example.com"}), "error": None, "calls": []}

    def fake_get(url, headers=None, timeout=None):
        state["calls"].append((url, headers))
        if state["error"]:
            raise state["error"]
        return state["response"]

    async def fake_async_get(self, url, headers=None):
        return fake_get(url, headers=headers)

    monkeypatch.setattr(httpx, "get", fake_get)
    monkeypatch.setattr(httpx.AsyncClient, "get", fake_async_get)
    return state


def test_active_session_passes_and_calls_whoami_live(gait):
    assert check_session_live("tok", expected_subject="123") is None
    url, headers = gait["calls"][0]
    assert url == "https://dummy-auth.com/api/whoami/"
    assert headers == {"Authorization": "Bearer tok"}


def test_every_check_is_live_no_cache(gait):
    for _ in range(3):
        check_session_live("tok")
    assert len(gait["calls"]) == 3


def test_revoked_session_denied(gait):
    gait["response"] = _Resp(401, {"error": "unauthenticated"})
    with pytest.raises(InvalidTokenError):
        check_session_live("tok")


@pytest.mark.parametrize("error", [httpx.ConnectError("down"), httpx.ReadTimeout("slow"), httpx.ConnectTimeout("x")])
def test_gait_unreachable_denies(gait, error):
    gait["error"] = error
    with pytest.raises(AuthServiceUnavailable):
        check_session_live("tok")


@pytest.mark.parametrize("status", [500, 502, 503, 403, 404])
def test_unexpected_status_denies(gait, status):
    gait["response"] = _Resp(status, {})
    with pytest.raises(AuthServiceUnavailable):
        check_session_live("tok")


def test_malformed_body_denies(gait):
    gait["response"] = _Resp(200, raise_json=True)
    with pytest.raises(AuthServiceUnavailable):
        check_session_live("tok")


def test_subject_mismatch_denies(gait):
    with pytest.raises(InvalidTokenError):
        check_session_live("tok", expected_subject="999")


def test_empty_token_denied_without_network(gait):
    with pytest.raises(InvalidTokenError):
        check_session_live("")
    assert gait["calls"] == []


async def test_async_variant_same_semantics(gait):
    await acheck_session_live("tok", expected_subject="123")
    gait["response"] = _Resp(401, {})
    with pytest.raises(InvalidTokenError):
        await acheck_session_live("tok")
    gait["error"] = httpx.ConnectError("down")
    with pytest.raises(AuthServiceUnavailable):
        await acheck_session_live("tok")


def test_session_check_bypasses_jwks_and_bearer_caches(gait, monkeypatch):
    # Warm both caches; the live check must still hit Gait.
    from auth_integration.django import authentication as auth_module
    from tests._jwks_support import make_verifier, sign

    verifier, endpoint = make_verifier()
    token = sign()
    verifier.verify(token)
    auth_module._cache_set(token, {"id": "123", "email": "e", "role": "r", "first_name": "f", "last_name": "l"})
    gait["response"] = _Resp(401, {})
    with pytest.raises(InvalidTokenError):
        check_session_live(token)
    assert len(gait["calls"]) == 1
    assert endpoint.calls == 1
    auth_module._BEARER_CACHE.clear()
