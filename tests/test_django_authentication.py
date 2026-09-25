# Filename: tests/test_django_authentication.py
import types

import httpx
import pytest
from rest_framework.exceptions import AuthenticationFailed

from gait_sdk.django import authentication as auth_module
from gait_sdk.django.authentication import (
    ExternalJWTAuthentication,
    ClaimsUser,
    AuthenticationServiceUnavailable,
)


class DummyRequest:
    """Minimal request object for DRF auth testing."""

    def __init__(self, headers=None, meta=None, cookies=None):
        # Step 1: Simulate DRF/Django request interface used by our auth backend
        self.headers = headers or {}
        self.META = meta or {}
        self.COOKIES = cookies or {}


@pytest.fixture(autouse=True)
def clear_bearer_cache():
    """
    The Bearer-mode TTL cache is a module-level dict, so it persists across
    tests in the same process. Clear it before/after every test in this file
    so cache-hit/miss assertions (and any reused token strings) can't leak
    between tests.
    """
    auth_module._BEARER_CACHE.clear()
    yield
    auth_module._BEARER_CACHE.clear()


def test_shim_import_path_works():
    """
    Ensure stable import path exists for DRF settings strings.
    """
    # Step 1: Import from public entrypoint
    from gait_sdk.authentication import ExternalJWTAuthentication as ShimAuth

    assert ShimAuth is not None


def test_no_credentials_returns_none():
    """
    If no Bearer header and no auth cookies, DRF should treat as anonymous.
    """
    auth = ExternalJWTAuthentication()
    request = DummyRequest(headers={}, cookies={"csrftoken": "x"})  # non-auth cookie

    # Step 1: Should NOT attempt auth based on non-auth cookies
    result = auth.authenticate(request)
    assert result is None


def test_bearer_success_returns_claimsuser_and_claims(monkeypatch):
    """
    Bearer token -> validate_token -> ClaimsUser returned and request.user_claims set.
    """
    auth = ExternalJWTAuthentication()
    request = DummyRequest(headers={"Authorization": "Bearer abc.def.ghi"})

    # Step 1: Mock validate_token used by auth backend (async bridged internally)
    async def mock_validate_token(token: str):
        return {
            "id": "user123",
            "email": "tech@example.com",
            "role": "technologist",
            "first_name": "Jane",
            "last_name": "Doe",
        }

    monkeypatch.setattr(
        "gait_sdk.django.authentication.validate_token", mock_validate_token
    )

    user, auth_obj = auth.authenticate(request)

    # Step 2: Validate user object
    assert isinstance(user, ClaimsUser)
    assert user.is_authenticated is True
    assert user.email == "tech@example.com"
    assert user.role == "technologist"

    # Step 3: Validate claims storage
    assert hasattr(request, "user_claims")
    assert request.user_claims["id"] == "user123"

    # Step 4: request.auth should be claims (auth_obj)
    assert auth_obj["email"] == "tech@example.com"


def test_bearer_invalid_raises_authenticationfailed(monkeypatch):
    """
    Invalid Bearer token should map to DRF AuthenticationFailed (401).
    """
    auth = ExternalJWTAuthentication()
    request = DummyRequest(headers={"Authorization": "Bearer bad.token"})

    # Step 1: Mock validate_token to raise InvalidTokenError
    from gait_sdk.exceptions import InvalidTokenError

    async def mock_validate_token(token: str):
        raise InvalidTokenError("Invalid or expired token.")

    monkeypatch.setattr(
        "gait_sdk.django.authentication.validate_token", mock_validate_token
    )

    with pytest.raises(AuthenticationFailed):
        auth.authenticate(request)


def test_cookie_mode_skips_when_only_non_auth_cookies_present():
    """
    Cookie-mode should NOT run unless access_token/refresh_token/temp_token exists.
    """
    auth = ExternalJWTAuthentication()
    request = DummyRequest(cookies={"csrftoken": "x", "something": "y"})

    # Step 1: With no Bearer and no auth cookies, should return None
    assert auth.authenticate(request) is None


def test_cookie_mode_success(monkeypatch):
    """
    Auth cookies present -> /whoami/ called -> ClaimsUser returned.
    """
    monkeypatch.setenv("GAIT_ALLOW_COOKIE_AUTH", "True")  # legacy cookie mode is opt-in since 0.5.0
    auth = ExternalJWTAuthentication()
    request = DummyRequest(cookies={"access_token": "cookie.jwt.value", "csrftoken": "x"})

    # Step 1: Mock httpx cookie validation response
    class MockResp:
        status_code = 200

        def json(self):
            return {
                "id": "user999",
                "email": "doc@example.com",
                "role": "physician",
                "first_name": "Doc",
                "last_name": "McGee",
            }

    async def mock_get(self, url, cookies):
        return MockResp()

    monkeypatch.setattr(httpx.AsyncClient, "get", mock_get)

    user, auth_obj = auth.authenticate(request)

    assert isinstance(user, ClaimsUser)
    assert user.role == "physician"
    assert request.user_claims["id"] == "user999"
    assert auth_obj["email"] == "doc@example.com"


def test_cookie_mode_auth_service_unavailable_raises_503(monkeypatch):
    """
    If Gait is unreachable in cookie mode, raise 503 not 401.
    """
    monkeypatch.setenv("GAIT_ALLOW_COOKIE_AUTH", "True")  # legacy cookie mode is opt-in since 0.5.0
    auth = ExternalJWTAuthentication()
    request = DummyRequest(cookies={"access_token": "cookie.jwt.value"})

    async def mock_get(self, url, cookies):
        raise httpx.RequestError("Network down")

    monkeypatch.setattr(httpx.AsyncClient, "get", mock_get)

    with pytest.raises(AuthenticationServiceUnavailable):
        auth.authenticate(request)


# =============================================================================
# SDK1 A1 — authenticate_header() -> "Bearer"
# =============================================================================
def test_authenticate_header_returns_bearer():
    """
    Regression test for the v0.3.12 fix: without a non-empty
    authenticate_header() return value, DRF silently rewrites 401 -> 403 on
    every AuthenticationFailed, which disables client-side token refresh.
    This is the single most important behavioral contract this adapter
    makes (see root README "Correctness guarantee: 401 vs 403").
    """
    auth = ExternalJWTAuthentication()
    assert auth.authenticate_header(DummyRequest()) == "Bearer"


# =============================================================================
# SDK1 A2 — malformed-but-valid-JSON claims must fail closed
# =============================================================================
@pytest.mark.parametrize(
    "bad_claims",
    [
        # Missing required field
        {"email": "a@example.com", "role": "admin", "first_name": "A", "last_name": "B"},
        # Non-string role
        {"id": "1", "email": "a@example.com", "role": 123, "first_name": "A", "last_name": "B"},
        # Non-string id
        {"id": None, "email": "a@example.com", "role": "admin", "first_name": "A", "last_name": "B"},
        # Empty-string role (present, string-typed, but not a real value)
        {"id": "1", "email": "a@example.com", "role": "", "first_name": "A", "last_name": "B"},
        # Non-dict payload entirely
        "not-a-dict",
        None,
    ],
)
def test_bearer_malformed_claims_fail_closed(monkeypatch, bad_claims):
    """
    Well-formed JSON from Gait that has missing fields, wrong types, or an
    empty role must be treated as untrusted and denied — never turned into
    an authenticated (or anonymous-fallback) request, and never a
    partially-constructed ClaimsUser.
    """
    auth = ExternalJWTAuthentication()
    request = DummyRequest(headers={"Authorization": "Bearer some.token"})

    async def mock_validate_token(token: str):
        return bad_claims

    monkeypatch.setattr(
        "gait_sdk.django.authentication.validate_token", mock_validate_token
    )

    with pytest.raises(AuthenticationFailed):
        auth.authenticate(request)

    # No partially-created identity: request.user_claims must never be set
    # on a failed validation.
    assert not hasattr(request, "user_claims")


# =============================================================================
# SDK1 A3 — timeout in cookie mode must map to 503, not 401 or a crash
# =============================================================================
def test_cookie_mode_timeout_raises_503(monkeypatch):
    """
    httpx.TimeoutException during cookie-mode validation must translate to
    AuthenticationServiceUnavailable (503), exactly like any other
    unreachable-Gait case — explicitly proven with TimeoutException itself,
    not just a generic httpx.RequestError.
    """
    monkeypatch.setenv("GAIT_ALLOW_COOKIE_AUTH", "True")  # legacy cookie mode is opt-in since 0.5.0
    auth = ExternalJWTAuthentication()
    request = DummyRequest(cookies={"access_token": "cookie.jwt.value"})

    async def mock_get(self, url, cookies):
        raise httpx.TimeoutException("Timed out waiting for Gait")

    monkeypatch.setattr(httpx.AsyncClient, "get", mock_get)

    with pytest.raises(AuthenticationServiceUnavailable):
        auth.authenticate(request)


# =============================================================================
# SDK1 A4 — Bearer-mode TTL cache
# =============================================================================
def test_bearer_cache_hit_skips_revalidation(monkeypatch):
    """
    A second request with the same Bearer token, inside the TTL window, must
    be served from cache rather than re-hitting Gait.
    """
    auth = ExternalJWTAuthentication()
    token = "cache.me.please"
    call_count = {"n": 0}

    async def mock_validate_token(t: str):
        call_count["n"] += 1
        return {
            "id": "user1",
            "email": "cached@example.com",
            "role": "admin",
            "first_name": "Cached",
            "last_name": "User",
        }

    monkeypatch.setattr(
        "gait_sdk.django.authentication.validate_token", mock_validate_token
    )

    # Step 1: first call -> real validation (cache miss)
    request1 = DummyRequest(headers={"Authorization": f"Bearer {token}"})
    user1, _ = auth.authenticate(request1)
    assert call_count["n"] == 1
    assert user1.email == "cached@example.com"

    # Step 2: second call, same token, still within TTL -> cache hit
    request2 = DummyRequest(headers={"Authorization": f"Bearer {token}"})
    user2, _ = auth.authenticate(request2)
    assert call_count["n"] == 1  # validate_token NOT called again
    assert user2.email == "cached@example.com"


def test_bearer_cache_key_is_not_raw_token():
    """
    The cache must key on a hash of the token, never the raw token string —
    so a raw Bearer token is never held as a durable in-memory dict key.
    """
    token = "super.secret.raw.token"
    auth_module._cache_set(
        token,
        {
            "id": "1",
            "email": "x@example.com",
            "role": "admin",
            "first_name": "X",
            "last_name": "Y",
        },
    )

    assert token not in auth_module._BEARER_CACHE
    assert auth_module._hash_token(token) in auth_module._BEARER_CACHE


def test_bearer_cache_expired_entry_revalidates(monkeypatch):
    """
    Once a cached entry's TTL has elapsed, the next request for the same
    token must re-validate against Gait rather than serving stale claims.
    """
    auth = ExternalJWTAuthentication()
    token = "expiring.token"
    call_count = {"n": 0}

    async def mock_validate_token(t: str):
        call_count["n"] += 1
        return {
            "id": "user1",
            "email": "fresh@example.com",
            "role": "admin",
            "first_name": "Fresh",
            "last_name": "User",
        }

    monkeypatch.setattr(
        "gait_sdk.django.authentication.validate_token", mock_validate_token
    )

    fake_now = {"t": 1_000_000.0}
    monkeypatch.setattr(auth_module.time, "time", lambda: fake_now["t"])

    # Step 1: first call populates the cache at fake_now.
    request1 = DummyRequest(headers={"Authorization": f"Bearer {token}"})
    auth.authenticate(request1)
    assert call_count["n"] == 1

    # Step 2: advance the clock past the TTL window.
    fake_now["t"] += auth_module._BEARER_CACHE_TTL_SECONDS + 1

    # Step 3: same token again -> cache entry is expired -> revalidates.
    request2 = DummyRequest(headers={"Authorization": f"Bearer {token}"})
    auth.authenticate(request2)
    assert call_count["n"] == 2


# =============================================================================
# 0.5.0 hardening -- legacy cookie mode is opt-in and forwards only the access token
# =============================================================================
def test_cookie_mode_off_by_default_ignores_cookies(monkeypatch):
    monkeypatch.delenv("GAIT_ALLOW_COOKIE_AUTH", raising=False)

    async def must_not_call(self, url, cookies):  # pragma: no cover - must never run
        raise AssertionError("cookie mode must be off by default")

    monkeypatch.setattr(httpx.AsyncClient, "get", must_not_call)
    request = DummyRequest(cookies={"access_token": "a", "refresh_token": "r", "temp_token": "t"})
    assert ExternalJWTAuthentication().authenticate(request) is None


def test_cookie_mode_forwards_only_access_token(monkeypatch):
    monkeypatch.setenv("GAIT_ALLOW_COOKIE_AUTH", "True")
    sent = {}

    class MockResp:
        status_code = 200

        def json(self):
            return {"id": "u1", "email": "e@x.com", "role": "r", "first_name": "F", "last_name": "L"}

    async def capture(self, url, cookies):
        sent.update(cookies)
        return MockResp()

    monkeypatch.setattr(httpx.AsyncClient, "get", capture)
    request = DummyRequest(cookies={"access_token": "a", "refresh_token": "r", "temp_token": "t", "csrftoken": "c"})
    ExternalJWTAuthentication().authenticate(request)
    assert sent == {"access_token": "a"}  # never the 7-day refresh token or the 2FA temp token


def test_refresh_or_temp_cookie_alone_is_not_a_credential(monkeypatch):
    monkeypatch.setenv("GAIT_ALLOW_COOKIE_AUTH", "True")
    request = DummyRequest(cookies={"refresh_token": "r", "temp_token": "t"})
    assert ExternalJWTAuthentication().authenticate(request) is None
