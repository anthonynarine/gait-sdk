# Filename: tests/test_role_dependency_status_codes.py
"""
SDK2 Part 0.1.B — confirm the FastAPI role flow keeps authentication
failures (401) distinct from authorization failures (403):

    missing/invalid authentication -> 401 Unauthorized, WWW-Authenticate: Bearer
    authenticated but insufficient role -> 403 Forbidden

Exercised end-to-end through a real FastAPI app + TestClient (not by calling
the decorated function directly with a manufactured kwarg), since that is
the only way to prove Depends(verify_token) actually runs — and can fail
closed as 401 — before require_role's own wrapper body ever executes.
"""

import importlib
import sys

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from gait_sdk.exceptions import InvalidTokenError
from gait_sdk.fastapi.dependencies import verify_token


@pytest.fixture()
def fallback_permissions(monkeypatch):
    """Force gait_sdk.permissions to load its FastAPI fallback branch."""
    monkeypatch.setitem(sys.modules, "rest_framework.permissions", None)
    sys.modules.pop("gait_sdk.permissions", None)
    module = importlib.import_module("gait_sdk.permissions")
    try:
        yield module
    finally:
        sys.modules.pop("gait_sdk.permissions", None)


@pytest.fixture()
def client(fallback_permissions):
    require_role = fallback_permissions.require_role

    app = FastAPI()

    @app.get("/admin-only")
    @require_role("admin")
    async def admin_only(claims: dict = Depends(verify_token)):
        return {"ok": True, "role": claims["role"]}

    return TestClient(app)


ADMIN_CLAIMS = {
    "id": "1",
    "email": "admin@example.com",
    "role": "admin",
    "first_name": "A",
    "last_name": "B",
}
TECH_CLAIMS = {
    "id": "2",
    "email": "tech@example.com",
    "role": "technologist",
    "first_name": "T",
    "last_name": "C",
}


def test_missing_authorization_header_is_401_not_403(client):
    resp = client.get("/admin-only")
    assert resp.status_code == 401
    assert resp.headers.get("www-authenticate") == "Bearer"


def test_invalid_token_is_401_not_403(client, monkeypatch):
    async def fake_validate_token(token):
        raise InvalidTokenError("Invalid or expired token.")

    monkeypatch.setattr(
        "gait_sdk.fastapi.dependencies.validate_token", fake_validate_token
    )

    resp = client.get("/admin-only", headers={"Authorization": "Bearer bad.token"})
    assert resp.status_code == 401
    assert resp.headers.get("www-authenticate") == "Bearer"


def test_valid_auth_wrong_role_is_403(client, monkeypatch):
    async def fake_validate_token(token):
        return TECH_CLAIMS

    monkeypatch.setattr(
        "gait_sdk.fastapi.dependencies.validate_token", fake_validate_token
    )

    resp = client.get("/admin-only", headers={"Authorization": "Bearer good.token"})
    assert resp.status_code == 403


def test_valid_auth_correct_role_is_200(client, monkeypatch):
    async def fake_validate_token(token):
        return ADMIN_CLAIMS

    monkeypatch.setattr(
        "gait_sdk.fastapi.dependencies.validate_token", fake_validate_token
    )

    resp = client.get("/admin-only", headers={"Authorization": "Bearer good.token"})
    assert resp.status_code == 200
    assert resp.json()["role"] == "admin"
