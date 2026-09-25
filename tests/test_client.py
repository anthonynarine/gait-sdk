# ✅ Updated version without httpx-mock
# Filename: tests/test_client.py

# to run activate venv in path:
# (gait_int_venv) \gait_sdk> 
# pytest -v -s tests/test_client.py

import pytest
import httpx
from gait_sdk.client import validate_token
from gait_sdk.exceptions import InvalidTokenError, AuthServiceUnavailable


pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def mock_env(monkeypatch):
    """Automatically mock GAIT_AUTH_URL and GAIT_TIMEOUT."""
    monkeypatch.setenv("GAIT_AUTH_URL", "https://dummy-auth.com/api")
    monkeypatch.setenv("GAIT_TIMEOUT", "5")


# ---------------------------------------------------------------------
# ✅ Success case — 200 OK
# ---------------------------------------------------------------------
async def test_validate_token_success(monkeypatch):
    """Simulate a valid /whoami/ response (200 OK)."""

    class MockResponse:
        status_code = 200

        def json(self):
            return {
                "id": "user123",
                "email": "tech@example.com",
                "role": "technologist",
                "first_name": "Jane",
                "last_name": "Doe",
                "is_2fa_enabled": False,
            }

    async def mock_get(self, url, headers):
        return MockResponse()

    monkeypatch.setattr(httpx.AsyncClient, "get", mock_get)
    claims = await validate_token("valid.token")

    assert claims["email"] == "tech@example.com"
    assert claims["role"] == "technologist"


# ---------------------------------------------------------------------
# ❌ Invalid token — 401
# ---------------------------------------------------------------------
async def test_validate_token_invalid(monkeypatch):
    """Simulate a 401 Unauthorized response."""

    class MockResponse:
        status_code = 401

    async def mock_get(self, url, headers):
        return MockResponse()

    monkeypatch.setattr(httpx.AsyncClient, "get", mock_get)

    with pytest.raises(InvalidTokenError):
        await validate_token("invalid.token")


# ---------------------------------------------------------------------
# 🚫 API unreachable
# ---------------------------------------------------------------------
async def test_validate_token_unreachable(monkeypatch):
    """Simulate network failure."""
    async def mock_get(self, url, headers):
        raise httpx.RequestError("Connection failed")

    monkeypatch.setattr(httpx.AsyncClient, "get", mock_get)

    with pytest.raises(AuthServiceUnavailable):
        await validate_token("any.token")


# ---------------------------------------------------------------------
# ⚠️ Malformed JSON
# ---------------------------------------------------------------------
async def test_validate_token_malformed_json(monkeypatch):
    """Simulate a 200 OK but invalid JSON body."""

    class MockResponse:
        status_code = 200

        def json(self):
            raise ValueError("Invalid JSON")

    async def mock_get(self, url, headers):
        return MockResponse()

    monkeypatch.setattr(httpx.AsyncClient, "get", mock_get)

    with pytest.raises(AuthServiceUnavailable):
        await validate_token("valid.token")


# ---------------------------------------------------------------------
# ⏱️ Timeout — SDK1 A3: explicitly simulate httpx.TimeoutException
# ---------------------------------------------------------------------
async def test_validate_token_timeout_raises_auth_service_unavailable(monkeypatch):
    """
    A timeout talking to Gait must translate to AuthServiceUnavailable (503),
    the same as any other unreachable-service case.

    httpx.TimeoutException IS an httpx.RequestError subclass, so the existing
    `except httpx.RequestError` in validate_token() already covers this —
    this test proves that explicitly (by raising TimeoutException itself,
    not a generic RequestError) rather than trusting the inheritance
    relationship implicitly.
    """

    async def mock_get(self, url, headers):
        raise httpx.TimeoutException("Timed out waiting for Gait")

    monkeypatch.setattr(httpx.AsyncClient, "get", mock_get)

    with pytest.raises(AuthServiceUnavailable):
        await validate_token("any.token")
