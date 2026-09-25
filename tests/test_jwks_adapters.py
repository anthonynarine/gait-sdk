"""0.4.0 framework adapters in JWKS mode, verifier selection, and the role boundary.

The key regression: an RS256 token with no role authenticates successfully,
and the resulting ClaimsUser.role is empty -- proving consumers can
authenticate without any dependency on Gait roles.
"""

import httpx
import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from rest_framework.exceptions import AuthenticationFailed

from gait_sdk.django import authentication as auth_module
from gait_sdk.django.authentication import (
    AuthenticationServiceUnavailable,
    ClaimsUser,
    ExternalJWTAuthentication,
    require_live_session,
)
from gait_sdk.exceptions import AuthConfigurationError
from gait_sdk.fastapi.dependencies import get_current_user
from gait_sdk.fastapi.dependencies import require_live_session as fastapi_require_live_session
from gait_sdk.fastapi.dependencies import verify_token
from gait_sdk.verification import (
    IntrospectionVerifier,
    JwksVerifier,
    get_token_verifier,
    load_verifier_config,
    set_token_verifier,
)

from tests._jwks_support import AUDIENCE, ISSUER, JWKS_URL, KEY_B, make_verifier, sign


class DummyRequest:
    def __init__(self, headers=None, cookies=None):
        self.headers = headers or {}
        self.META = {}
        self.COOKIES = cookies or {}


@pytest.fixture(autouse=True)
def reset_verifier():
    set_token_verifier(None)
    auth_module._BEARER_CACHE.clear()
    yield
    set_token_verifier(None)
    auth_module._BEARER_CACHE.clear()


@pytest.fixture
def jwks_mode():
    verifier, endpoint = make_verifier()
    set_token_verifier(verifier)
    return verifier, endpoint


def _no_whoami(monkeypatch):
    def boom(*args, **kwargs):  # pragma: no cover - must never run
        raise AssertionError("JWKS mode must never call /whoami/")

    monkeypatch.setattr(auth_module, "validate_token", boom)
    monkeypatch.setattr("gait_sdk.fastapi.dependencies.validate_token", boom)
    monkeypatch.setattr(httpx.AsyncClient, "get", boom)


# --- Django adapter -------------------------------------------------------------
def test_django_jwks_rs256_without_role_authenticates_with_empty_role(jwks_mode, monkeypatch):
    _no_whoami(monkeypatch)
    token = sign(sub="123", sid="s-1")
    request = DummyRequest(headers={"Authorization": f"Bearer {token}"})
    user, claims = ExternalJWTAuthentication().authenticate(request)
    assert isinstance(user, ClaimsUser)
    assert user.id == "123" and user.email == "tech@example.com"
    assert user.role == "" and user.first_name == "" and user.last_name == ""
    assert user.is_authenticated
    assert request.verified_identity.session_id == "s-1"
    assert request.user_claims["role"] == ""
    assert claims["verified_by"] == "jwks"


def test_django_jwks_token_role_claim_never_reaches_claims_user(jwks_mode):
    token = sign(role="physician")
    user, _ = ExternalJWTAuthentication().authenticate(DummyRequest(headers={"Authorization": f"Bearer {token}"}))
    assert user.role == ""


def test_django_jwks_is_bearer_only_cookies_ignored(jwks_mode, monkeypatch):
    # 0.5.0 (audit M2): JWKS mode never reads cookies, even when legacy cookie
    # mode is enabled -- a cross-site page cannot attach an Authorization header,
    # so Bearer-only removes the CSRF exposure entirely.
    _no_whoami(monkeypatch)
    monkeypatch.setenv("GAIT_ALLOW_COOKIE_AUTH", "True")
    token = sign()
    assert ExternalJWTAuthentication().authenticate(DummyRequest(cookies={"access_token": token})) is None
    user, _ = ExternalJWTAuthentication().authenticate(DummyRequest(headers={"Authorization": f"Bearer {token}"}))
    assert user.id == "123"


def test_django_jwks_no_credentials_is_anonymous(jwks_mode):
    assert ExternalJWTAuthentication().authenticate(DummyRequest()) is None


def test_django_jwks_invalid_token_is_401(jwks_mode):
    with pytest.raises(AuthenticationFailed):
        ExternalJWTAuthentication().authenticate(DummyRequest(headers={"Authorization": "Bearer garbage"}))


def test_django_jwks_wrong_token_use_is_401(jwks_mode):
    with pytest.raises(AuthenticationFailed):
        ExternalJWTAuthentication().authenticate(
            DummyRequest(headers={"Authorization": f"Bearer {sign(token_use='refresh')}"})
        )


def test_django_jwks_gait_unavailable_is_503_not_downgrade(jwks_mode, monkeypatch):
    _no_whoami(monkeypatch)
    _, endpoint = jwks_mode
    endpoint.fail = httpx.ConnectError("down")
    with pytest.raises(AuthenticationServiceUnavailable):
        ExternalJWTAuthentication().authenticate(DummyRequest(headers={"Authorization": f"Bearer {sign()}"}))


def test_django_jwks_does_not_use_bearer_cache(jwks_mode):
    token = sign()
    ExternalJWTAuthentication().authenticate(DummyRequest(headers={"Authorization": f"Bearer {token}"}))
    assert auth_module._BEARER_CACHE == {}


def test_django_introspection_mode_keeps_legacy_role(monkeypatch):
    async def fake_validate(token):
        return {"id": "7", "email": "p@x.com", "role": "physician", "first_name": "P", "last_name": "X"}

    monkeypatch.setattr(auth_module, "validate_token", fake_validate)
    request = DummyRequest(headers={"Authorization": "Bearer t"})
    user, _ = ExternalJWTAuthentication().authenticate(request)
    assert user.role == "physician"  # LEGACY introspection behavior preserved
    assert request.verified_identity.subject == "7"
    assert request.verified_identity.source == "introspection"


def test_django_misconfigured_verifier_is_503(monkeypatch):
    monkeypatch.setenv("GAIT_TOKEN_VERIFIER", "jwks")
    monkeypatch.delenv("GAIT_JWKS_URL", raising=False)
    with pytest.raises(AuthenticationServiceUnavailable):
        ExternalJWTAuthentication().authenticate(DummyRequest(headers={"Authorization": "Bearer t"}))


# --- Django live session helper ----------------------------------------------------
def test_django_require_live_session_active_and_revoked(jwks_mode, monkeypatch):
    token = sign(sub="123")
    request = DummyRequest(headers={"Authorization": f"Bearer {token}"})
    ExternalJWTAuthentication().authenticate(request)

    class R:
        def __init__(self, status, body):
            self.status_code, self._b = status, body

        def json(self):
            return self._b

    monkeypatch.setattr(httpx, "get", lambda url, headers=None, timeout=None: R(200, {"id": "123"}))
    require_live_session(request)  # active -> no exception

    monkeypatch.setattr(httpx, "get", lambda url, headers=None, timeout=None: R(401, {}))
    with pytest.raises(AuthenticationFailed):
        require_live_session(request)

    def down(url, headers=None, timeout=None):
        raise httpx.ConnectError("down")

    monkeypatch.setattr(httpx, "get", down)
    with pytest.raises(AuthenticationServiceUnavailable):
        require_live_session(request)


def test_django_require_live_session_unauthenticated_request_denied():
    with pytest.raises(AuthenticationFailed):
        require_live_session(DummyRequest())


# --- FastAPI adapter ------------------------------------------------------------------
app = FastAPI()


@app.get("/secure")
async def secure(claims: dict = Depends(verify_token), current: dict = Depends(get_current_user)):
    return {"claims": claims, "current": current}


@app.post("/sensitive")
async def sensitive(claims: dict = Depends(fastapi_require_live_session)):
    return {"ok": True, "sub": claims["id"]}


client = TestClient(app)


def test_fastapi_jwks_rs256_without_role_authenticates_with_empty_role(jwks_mode, monkeypatch):
    _no_whoami(monkeypatch)
    response = client.get("/secure", headers={"Authorization": f"Bearer {sign(sub='55')}"})
    assert response.status_code == 200
    body = response.json()
    assert body["claims"]["id"] == "55" and body["claims"]["role"] == ""
    assert body["current"] == body["claims"]


def test_fastapi_jwks_invalid_token_401_with_challenge(jwks_mode):
    response = client.get("/secure", headers={"Authorization": f"Bearer {sign(key=KEY_B)}"})
    assert response.status_code == 401
    assert response.headers.get("www-authenticate") == "Bearer"


def test_fastapi_jwks_gait_unavailable_503(jwks_mode, monkeypatch):
    _no_whoami(monkeypatch)
    _, endpoint = jwks_mode
    endpoint.fail = httpx.ConnectError("down")
    assert client.get("/secure", headers={"Authorization": f"Bearer {sign()}"}).status_code == 503


def test_fastapi_require_live_session(jwks_mode, monkeypatch):
    calls = []

    class R:
        def __init__(self, status, body):
            self.status_code, self._b = status, body

        def json(self):
            return self._b

    state = {"resp": R(200, {"id": "123"})}

    async def fake_async_get(self, url, headers=None):
        calls.append(url)
        return state["resp"]

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_async_get)
    token = sign(sub="123")
    assert client.post("/sensitive", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    state["resp"] = R(401, {})
    assert client.post("/sensitive", headers={"Authorization": f"Bearer {token}"}).status_code == 401
    assert len(calls) == 2  # live every time


# --- configuration / selection -----------------------------------------------------------
def test_default_verifier_is_introspection(monkeypatch):
    monkeypatch.delenv("GAIT_TOKEN_VERIFIER", raising=False)
    assert isinstance(get_token_verifier(), IntrospectionVerifier)


def test_jwks_selected_explicitly(monkeypatch):
    monkeypatch.setenv("GAIT_TOKEN_VERIFIER", "jwks")
    monkeypatch.setenv("GAIT_JWKS_URL", JWKS_URL)
    monkeypatch.setenv("GAIT_ISSUER", ISSUER)
    monkeypatch.setenv("GAIT_AUDIENCE", AUDIENCE)
    verifier = get_token_verifier()
    assert isinstance(verifier, JwksVerifier)
    assert (verifier.issuer, verifier.audience) == (ISSUER, AUDIENCE)
    assert get_token_verifier() is verifier  # one shared instance -> one shared JWKS cache


@pytest.mark.parametrize("missing", ["GAIT_JWKS_URL", "GAIT_ISSUER", "GAIT_AUDIENCE"])
def test_jwks_mode_requires_all_settings(monkeypatch, missing):
    monkeypatch.setenv("GAIT_TOKEN_VERIFIER", "jwks")
    for name, value in (("GAIT_JWKS_URL", JWKS_URL), ("GAIT_ISSUER", ISSUER), ("GAIT_AUDIENCE", AUDIENCE)):
        monkeypatch.setenv(name, value)
    monkeypatch.delenv(missing)
    with pytest.raises(AuthConfigurationError):
        load_verifier_config()


def test_unknown_verifier_rejected(monkeypatch):
    monkeypatch.setenv("GAIT_TOKEN_VERIFIER", "auto")
    with pytest.raises(AuthConfigurationError):
        load_verifier_config()


def test_jwks_url_must_be_https(monkeypatch):
    monkeypatch.setenv("GAIT_TOKEN_VERIFIER", "jwks")
    monkeypatch.setenv("GAIT_JWKS_URL", "http://auth.gait.test/.well-known/jwks.json")
    monkeypatch.setenv("GAIT_ISSUER", ISSUER)
    monkeypatch.setenv("GAIT_AUDIENCE", AUDIENCE)
    with pytest.raises(AuthConfigurationError):
        load_verifier_config()


def test_django_appconfig_fails_startup_on_bad_config(monkeypatch):
    import gait_sdk
    from gait_sdk.apps import GaitSdkConfig

    monkeypatch.setenv("GAIT_TOKEN_VERIFIER", "jwks")
    monkeypatch.delenv("GAIT_JWKS_URL", raising=False)
    with pytest.raises(AuthConfigurationError):
        GaitSdkConfig("gait_sdk", gait_sdk).ready()


# --- deprecations -----------------------------------------------------------------------------
def test_role_helpers_warn_deprecated():
    from gait_sdk import permissions, utils

    with pytest.warns(DeprecationWarning):
        permissions.HasRole("physician")
    with pytest.warns(DeprecationWarning):
        permissions.HasAnyRole(["admin"])
    with pytest.warns(DeprecationWarning):
        permissions.require_role("admin")
    request = type("R", (), {"user_claims": {"role": "admin"}})()
    for helper in (utils.is_admin, utils.is_physician, utils.is_technologist, utils.get_user_role):
        with pytest.warns(DeprecationWarning):
            helper(request)


def test_role_helpers_deny_jwks_identity(jwks_mode):
    import warnings

    from gait_sdk import permissions

    request = DummyRequest(headers={"Authorization": f"Bearer {sign()}"})
    ExternalJWTAuthentication().authenticate(request)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        assert permissions.HasAnyRole(["admin", "physician", "technologist"]).has_permission(request, None) is False
        for role in ("admin", "physician", "technologist"):
            assert permissions.HasRole(role).has_permission(request, None) is False
