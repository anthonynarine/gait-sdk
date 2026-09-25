# Filename: tests/test_dependencies.py
"""
Regression tests for gait_sdk.fastapi.dependencies (SDK1 Part G).

Uses FastAPI's own TestClient with a tiny throwaway app wiring up
`verify_token`/`get_current_user` exactly the way a real consumer would,
so these exercise the real FastAPI dependency-injection path rather than
calling the coroutine functions in isolation. Nothing here talks to a real
Gait — `validate_token` is always monkeypatched.
"""

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from gait_sdk.exceptions import AuthServiceUnavailable, InvalidTokenError
from gait_sdk.fastapi.dependencies import get_current_user, verify_token


VALID_CLAIMS = {
    "id": "user123",
    "email": "tech@example.com",
    "role": "technologist",
    "first_name": "Jane",
    "last_name": "Doe",
}


app = FastAPI()


@app.get("/secure")
async def secure_route(claims: dict = Depends(verify_token)):
    return {"claims": claims}


@app.get("/secure-and-current-user")
async def secure_and_current_user_route(
    claims: dict = Depends(verify_token),
    current: dict = Depends(get_current_user),
):
    return {"claims": claims, "current": current}


@app.get("/current-user-only")
async def current_user_only_route(current: dict = Depends(get_current_user)):
    # No verify_token dependency at all -> request.state.user was never set.
    return {"current": current}


client = TestClient(app)


def _fake_validate_token(return_value=None, exc=None):
    async def _fake(token):
        if exc is not None:
            raise exc
        return return_value

    return _fake


# ---------------------------------------------------------------------------
# ✅ Valid Bearer token -> verified claims returned
# ---------------------------------------------------------------------------
def test_valid_bearer_returns_verified_claims(monkeypatch):
    monkeypatch.setattr(
        "gait_sdk.fastapi.dependencies.validate_token",
        _fake_validate_token(return_value=VALID_CLAIMS),
    )

    resp = client.get("/secure", headers={"Authorization": "Bearer good.token"})

    assert resp.status_code == 200
    assert resp.json()["claims"] == VALID_CLAIMS


# ---------------------------------------------------------------------------
# ❌ Missing Authorization header -> 401 + WWW-Authenticate: Bearer
# ---------------------------------------------------------------------------
def test_missing_authorization_header_returns_401_with_challenge():
    resp = client.get("/secure")

    assert resp.status_code == 401
    assert resp.headers.get("www-authenticate") == "Bearer"


# ---------------------------------------------------------------------------
# ❌ Invalid/expired token -> 401 + WWW-Authenticate: Bearer
# ---------------------------------------------------------------------------
def test_invalid_token_returns_401_with_challenge(monkeypatch):
    monkeypatch.setattr(
        "gait_sdk.fastapi.dependencies.validate_token",
        _fake_validate_token(exc=InvalidTokenError("Invalid or expired token.")),
    )

    resp = client.get("/secure", headers={"Authorization": "Bearer bad.token"})

    assert resp.status_code == 401
    assert resp.headers.get("www-authenticate") == "Bearer"


# ---------------------------------------------------------------------------
# 🚫 Gait unreachable -> 503 (no auth challenge header expected on 503)
# ---------------------------------------------------------------------------
def test_gait_unavailable_returns_503(monkeypatch):
    monkeypatch.setattr(
        "gait_sdk.fastapi.dependencies.validate_token",
        _fake_validate_token(exc=AuthServiceUnavailable("Authentication service unreachable.")),
    )

    resp = client.get("/secure", headers={"Authorization": "Bearer whatever"})

    assert resp.status_code == 503


# ---------------------------------------------------------------------------
# ⏱️ Timeout (surfaced by validate_token as AuthServiceUnavailable) -> 503
# ---------------------------------------------------------------------------
def test_timeout_maps_to_503(monkeypatch):
    async def _raise_timeout(token):
        # gait_sdk.client.validate_token already translates
        # httpx.TimeoutException into AuthServiceUnavailable (see
        # tests/test_client.py) — this proves the FastAPI adapter forwards
        # that outcome to a 503, not a 401 or an unhandled crash.
        raise AuthServiceUnavailable("Authentication service unreachable.")

    monkeypatch.setattr("gait_sdk.fastapi.dependencies.validate_token", _raise_timeout)

    resp = client.get("/secure", headers={"Authorization": "Bearer whatever"})

    assert resp.status_code == 503


# ---------------------------------------------------------------------------
# ⚠️ Malformed response from Gait -> 503, not a 500 crash
# ---------------------------------------------------------------------------
def test_malformed_gait_response_returns_503(monkeypatch):
    monkeypatch.setattr(
        "gait_sdk.fastapi.dependencies.validate_token",
        _fake_validate_token(
            exc=AuthServiceUnavailable("Malformed response from authentication service.")
        ),
    )

    resp = client.get("/secure", headers={"Authorization": "Bearer whatever"})

    assert resp.status_code == 503


# ---------------------------------------------------------------------------
# 🧯 Unexpected exception from validate_token -> fails closed as 401, not 500
# ---------------------------------------------------------------------------
def test_unexpected_exception_fails_closed_as_401(monkeypatch):
    async def _raise_unexpected(token):
        raise RuntimeError("boom")

    monkeypatch.setattr(
        "gait_sdk.fastapi.dependencies.validate_token", _raise_unexpected
    )

    resp = client.get("/secure", headers={"Authorization": "Bearer whatever"})

    assert resp.status_code == 401
    assert resp.headers.get("www-authenticate") == "Bearer"


# ---------------------------------------------------------------------------
# 🧩 request.state.user is set by verify_token and readable via get_current_user
# ---------------------------------------------------------------------------
def test_request_state_user_matches_verified_claims(monkeypatch):
    monkeypatch.setattr(
        "gait_sdk.fastapi.dependencies.validate_token",
        _fake_validate_token(return_value=VALID_CLAIMS),
    )

    resp = client.get(
        "/secure-and-current-user", headers={"Authorization": "Bearer good.token"}
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["claims"] == VALID_CLAIMS
    assert body["current"] == VALID_CLAIMS


# ---------------------------------------------------------------------------
# 🧩 get_current_user without verify_token having run -> {} (not an error)
# ---------------------------------------------------------------------------
def test_get_current_user_without_verify_token_returns_empty_dict():
    resp = client.get("/current-user-only")

    assert resp.status_code == 200
    assert resp.json()["current"] == {}
