# Filename: tests/test_application.py
"""
SDK2 — regression tests for gait_sdk.application (Gait Application
machine identity). Mirrors tests/test_client.py's style; never talks to a
real Gait — httpx is always monkeypatched.

Covers all of SDK2 Part 13's required scenarios, in order.
"""

import dataclasses
import logging

import httpx
import pytest

from gait_sdk.application import (
    APPLICATION_CREDENTIAL_HEADER,
    ApplicationPrincipal,
    verify_application,
)
from gait_sdk.exceptions import AuthServiceUnavailable, InvalidApplicationCredentialError

# Note: no module-level `pytestmark = pytest.mark.asyncio` here (unlike
# tests/test_client.py) — this file mixes async and sync tests, and
# pyproject.toml's `asyncio_mode = "auto"` already detects async def tests
# automatically without needing the explicit marker on every function.


VALID_RESPONSE = {
    "application_id": "11111111-1111-1111-1111-111111111111",
    "application_slug": "lumen-media",
    "organization_id": "22222222-2222-2222-2222-222222222222",
    "organization_slug": "mount-sinai",
    "environment": "production",
}


def _mock_post(status_code=200, json_result=None, json_exc=None, headers_captured=None):
    class MockResponse:
        def __init__(self):
            self.status_code = status_code

        def json(self):
            if json_exc is not None:
                raise json_exc
            return json_result

    async def mock_post(self, url, headers=None):
        if headers_captured is not None:
            headers_captured.update(headers or {})
        return MockResponse()

    return mock_post


# ---------------------------------------------------------------------
# 1. Valid application credential
# ---------------------------------------------------------------------
async def test_valid_credential_returns_application_principal(monkeypatch):
    monkeypatch.setattr(
        httpx.AsyncClient, "post", _mock_post(status_code=200, json_result=VALID_RESPONSE)
    )

    principal = await verify_application(credential="a-real-secret")

    assert isinstance(principal, ApplicationPrincipal)
    assert principal.application_id == VALID_RESPONSE["application_id"]
    assert principal.application_slug == "lumen-media"
    assert principal.organization_id == VALID_RESPONSE["organization_id"]
    assert principal.organization_slug == "mount-sinai"
    assert principal.environment == "production"


async def test_verify_application_sends_dedicated_credential_header_not_bearer(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        httpx.AsyncClient,
        "post",
        _mock_post(status_code=200, json_result=VALID_RESPONSE, headers_captured=captured),
    )

    await verify_application(credential="a-real-secret")

    assert captured.get(APPLICATION_CREDENTIAL_HEADER) == "a-real-secret"
    assert "Authorization" not in captured


# ---------------------------------------------------------------------
# 2. Invalid credential (Gait rejects with 401)
# ---------------------------------------------------------------------
async def test_invalid_credential_raises_invalid_application_credential_error(monkeypatch):
    monkeypatch.setattr(httpx.AsyncClient, "post", _mock_post(status_code=401))

    with pytest.raises(InvalidApplicationCredentialError):
        await verify_application(credential="wrong-secret")


# ---------------------------------------------------------------------
# 3. Missing credential (not passed, not configured)
# ---------------------------------------------------------------------
async def test_missing_credential_raises_explicitly(monkeypatch):
    monkeypatch.setattr("gait_sdk.application.GAIT_APPLICATION_CREDENTIAL", None)

    with pytest.raises(InvalidApplicationCredentialError):
        await verify_application()


async def test_missing_credential_never_calls_gait(monkeypatch):
    """A missing credential must fail before any network call, not after."""
    monkeypatch.setattr("gait_sdk.application.GAIT_APPLICATION_CREDENTIAL", None)
    called = {"n": 0}

    async def mock_post(self, url, headers=None):
        called["n"] += 1
        raise AssertionError("should never reach Gait with no credential")

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    with pytest.raises(InvalidApplicationCredentialError):
        await verify_application()
    assert called["n"] == 0


async def test_configured_credential_used_when_none_passed_explicitly(monkeypatch):
    monkeypatch.setattr("gait_sdk.application.GAIT_APPLICATION_CREDENTIAL", "configured-secret")
    captured = {}
    monkeypatch.setattr(
        httpx.AsyncClient,
        "post",
        _mock_post(status_code=200, json_result=VALID_RESPONSE, headers_captured=captured),
    )

    await verify_application()

    assert captured.get(APPLICATION_CREDENTIAL_HEADER) == "configured-secret"


# ---------------------------------------------------------------------
# 4. Gait unavailable (network failure)
# ---------------------------------------------------------------------
async def test_network_unavailable_raises_auth_service_unavailable(monkeypatch):
    async def mock_post(self, url, headers=None):
        raise httpx.RequestError("Connection failed")

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    with pytest.raises(AuthServiceUnavailable):
        await verify_application(credential="a-real-secret")


# ---------------------------------------------------------------------
# 5. Timeout
# ---------------------------------------------------------------------
async def test_timeout_raises_auth_service_unavailable(monkeypatch):
    async def mock_post(self, url, headers=None):
        raise httpx.TimeoutException("Timed out waiting for Gait")

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    with pytest.raises(AuthServiceUnavailable):
        await verify_application(credential="a-real-secret")


# ---------------------------------------------------------------------
# 6. Malformed JSON (200 OK, unparsable body)
# ---------------------------------------------------------------------
async def test_malformed_json_raises_auth_service_unavailable(monkeypatch):
    monkeypatch.setattr(
        httpx.AsyncClient,
        "post",
        _mock_post(status_code=200, json_exc=ValueError("Invalid JSON")),
    )

    with pytest.raises(AuthServiceUnavailable):
        await verify_application(credential="a-real-secret")


# ---------------------------------------------------------------------
# 7. Structurally-invalid response (valid JSON, wrong shape) — fail closed
# ---------------------------------------------------------------------
@pytest.mark.parametrize(
    "bad_response",
    [
        {},  # entirely empty
        {**VALID_RESPONSE, "application_id": None},
        {**VALID_RESPONSE, "application_id": ""},
        {**VALID_RESPONSE, "application_id": 12345},
        {**VALID_RESPONSE, "organization_id": None},
        {**VALID_RESPONSE, "environment": "not-a-real-environment"},
        {**VALID_RESPONSE, "environment": ""},
        {k: v for k, v in VALID_RESPONSE.items() if k != "application_slug"},  # missing key
        "not-a-dict",
        None,
        123,
    ],
)
async def test_structurally_invalid_response_fails_closed(monkeypatch, bad_response):
    monkeypatch.setattr(
        httpx.AsyncClient, "post", _mock_post(status_code=200, json_result=bad_response)
    )

    with pytest.raises(AuthServiceUnavailable):
        await verify_application(credential="a-real-secret")


async def test_unexpected_status_code_raises_auth_service_unavailable(monkeypatch):
    monkeypatch.setattr(httpx.AsyncClient, "post", _mock_post(status_code=500))

    with pytest.raises(AuthServiceUnavailable):
        await verify_application(credential="a-real-secret")


# ---------------------------------------------------------------------
# 8. ApplicationPrincipal construction
# ---------------------------------------------------------------------
def test_application_principal_construction():
    principal = ApplicationPrincipal(
        application_id="app-1",
        application_slug="lumen-media",
        organization_id="org-1",
        organization_slug="mount-sinai",
        environment="production",
    )
    assert principal.application_id == "app-1"
    assert principal.application_slug == "lumen-media"
    assert principal.organization_id == "org-1"
    assert principal.organization_slug == "mount-sinai"
    assert principal.environment == "production"


# ---------------------------------------------------------------------
# 9. ApplicationPrincipal immutability
# ---------------------------------------------------------------------
def test_application_principal_is_immutable():
    principal = ApplicationPrincipal(
        application_id="app-1",
        application_slug="lumen-media",
        organization_id="org-1",
        organization_slug="mount-sinai",
        environment="production",
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        principal.application_id = "app-2"  # type: ignore[misc]


# ---------------------------------------------------------------------
# 10. Raw credential absent from principal / repr
# ---------------------------------------------------------------------
async def test_raw_credential_absent_from_principal_repr(monkeypatch):
    secret = "super-secret-application-credential-value"
    monkeypatch.setattr(
        httpx.AsyncClient, "post", _mock_post(status_code=200, json_result=VALID_RESPONSE)
    )

    principal = await verify_application(credential=secret)

    assert secret not in repr(principal)
    assert secret not in str(principal)
    # Structural guarantee, not just an absence-of-value check: the
    # dataclass has no field capable of holding the credential at all.
    field_names = {f.name for f in dataclasses.fields(ApplicationPrincipal)}
    assert field_names == {
        "application_id",
        "application_slug",
        "organization_id",
        "organization_slug",
        "environment",
    }


# ---------------------------------------------------------------------
# 11. Raw credential absent from logs (success and failure paths)
# ---------------------------------------------------------------------
async def test_raw_credential_absent_from_logs_on_success(monkeypatch, caplog):
    secret = "super-secret-application-credential-value"
    monkeypatch.setattr(
        httpx.AsyncClient, "post", _mock_post(status_code=200, json_result=VALID_RESPONSE)
    )

    with caplog.at_level(logging.DEBUG, logger="gait_sdk.application"):
        await verify_application(credential=secret)

    assert secret not in caplog.text


async def test_raw_credential_absent_from_logs_on_rejection(monkeypatch, caplog):
    secret = "super-secret-application-credential-value"
    monkeypatch.setattr(httpx.AsyncClient, "post", _mock_post(status_code=401))

    with caplog.at_level(logging.DEBUG, logger="gait_sdk.application"):
        with pytest.raises(InvalidApplicationCredentialError):
            await verify_application(credential=secret)

    assert secret not in caplog.text


async def test_raw_credential_absent_from_exception_message(monkeypatch):
    secret = "super-secret-application-credential-value"
    monkeypatch.setattr(httpx.AsyncClient, "post", _mock_post(status_code=401))

    with pytest.raises(InvalidApplicationCredentialError) as exc_info:
        await verify_application(credential=secret)

    assert secret not in str(exc_info.value)


# ---------------------------------------------------------------------
# 12/13. Organization and environment come only from Gait's response
# ---------------------------------------------------------------------
async def test_organization_comes_only_from_gait_response(monkeypatch):
    monkeypatch.setattr(
        httpx.AsyncClient, "post", _mock_post(status_code=200, json_result=VALID_RESPONSE)
    )

    principal = await verify_application(credential="a-real-secret")

    assert principal.organization_id == VALID_RESPONSE["organization_id"]
    assert principal.organization_slug == VALID_RESPONSE["organization_slug"]


async def test_environment_comes_only_from_gait_response(monkeypatch):
    staging_response = {**VALID_RESPONSE, "environment": "staging"}
    monkeypatch.setattr(
        httpx.AsyncClient, "post", _mock_post(status_code=200, json_result=staging_response)
    )

    principal = await verify_application(credential="a-real-secret")

    assert principal.environment == "staging"


# ---------------------------------------------------------------------
# 14. No client-side tenant/environment override exists at all
# ---------------------------------------------------------------------
def test_verify_application_accepts_no_tenant_override_parameters():
    """
    Structural proof, not just behavioral: verify_application()'s only
    parameter is the credential itself. There is no organization_id,
    organization_slug, or environment argument a caller could pass to try
    to broaden or select tenant/environment authority.
    """
    import inspect

    params = list(inspect.signature(verify_application).parameters)
    assert params == ["credential"]


# ---------------------------------------------------------------------
# 15/16. Human/application identity independence (SDK2 Part 8)
# ---------------------------------------------------------------------
async def test_valid_human_with_no_app_credential_does_not_create_principal(monkeypatch):
    """A valid ClaimsUser existing tells verify_application() nothing — it
    still fails explicitly if no application credential is configured."""
    from gait_sdk.django.authentication import ClaimsUser

    human = ClaimsUser(
        id="u1", email="doc@example.com", role="physician",
        first_name="Doc", last_name="McGee",
    )
    monkeypatch.setattr("gait_sdk.application.GAIT_APPLICATION_CREDENTIAL", None)

    with pytest.raises(InvalidApplicationCredentialError):
        await verify_application()

    # The human identity object itself is completely untouched by this.
    assert human.email == "doc@example.com"


async def test_valid_app_credential_establishes_principal_with_no_user_at_all(monkeypatch):
    """Application identity can be verified with no ClaimsUser/user context
    in play whatsoever — the two are fully independent primitives."""
    monkeypatch.setattr(
        httpx.AsyncClient, "post", _mock_post(status_code=200, json_result=VALID_RESPONSE)
    )

    principal = await verify_application(credential="a-real-secret")

    assert isinstance(principal, ApplicationPrincipal)


async def test_invalid_human_token_does_not_affect_separately_verified_principal(monkeypatch):
    from gait_sdk.django.authentication import ExternalJWTAuthentication
    from gait_sdk.exceptions import InvalidTokenError

    class DummyRequest:
        def __init__(self):
            self.headers = {"Authorization": "Bearer bad.token"}
            self.META = {}
            self.COOKIES = {}

    # Step 1: verify an application identity first.
    monkeypatch.setattr(
        httpx.AsyncClient, "post", _mock_post(status_code=200, json_result=VALID_RESPONSE)
    )
    principal = await verify_application(credential="a-real-secret")

    # Step 2: separately, a human token fails validation.
    async def mock_validate_token(token):
        raise InvalidTokenError("Invalid or expired token.")

    monkeypatch.setattr(
        "gait_sdk.django.authentication.validate_token", mock_validate_token
    )
    from rest_framework.exceptions import AuthenticationFailed

    with pytest.raises(AuthenticationFailed):
        ExternalJWTAuthentication().authenticate(DummyRequest())

    # Step 3: the earlier ApplicationPrincipal is a plain, already-built
    # value object — nothing about the unrelated human auth failure could
    # have mutated or invalidated it.
    assert principal.application_slug == "lumen-media"
    assert principal.environment == "production"


async def test_invalid_application_credential_does_not_mutate_claims_user(monkeypatch):
    from gait_sdk.django.authentication import ClaimsUser

    human = ClaimsUser(
        id="u1", email="doc@example.com", role="physician",
        first_name="Doc", last_name="McGee",
    )
    monkeypatch.setattr(httpx.AsyncClient, "post", _mock_post(status_code=401))

    with pytest.raises(InvalidApplicationCredentialError):
        await verify_application(credential="wrong-secret")

    assert human.id == "u1"
    assert human.email == "doc@example.com"
    assert human.role == "physician"
    assert human.first_name == "Doc"
    assert human.last_name == "McGee"
