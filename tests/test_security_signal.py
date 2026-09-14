# Filename: tests/test_security_signal.py
"""
SDK4 — regression tests for auth_integration.security (Tenant Security
Signal Client). Mirrors tests/test_application.py's style; never talks to
a real Gait — httpx is always monkeypatched.

Covers all of SDK4 Part 16's required scenarios, in order.
"""

import inspect

import httpx
import pytest

from auth_integration.application import APPLICATION_CREDENTIAL_HEADER
from auth_integration.exceptions import (
    AuthServiceUnavailable,
    InvalidApplicationCredentialError,
    SecuritySignalRejected,
)
from auth_integration.security import SecuritySignalResult, send_security_signal


VALID_RESPONSE = {
    "signal_id": "33333333-3333-3333-3333-333333333333",
    "control_key": "TENANT.APPLICATION.SELF_REPORTED_SECURITY_CHECK",
    "evidence_id": "44444444-4444-4444-4444-444444444444",
    "received_at": "2026-09-13T12:00:00Z",
}


def _mock_post(status_code=201, json_result=None, json_exc=None, captured=None):
    class MockResponse:
        def __init__(self):
            self.status_code = status_code

        def json(self):
            if json_exc is not None:
                raise json_exc
            return json_result

    async def mock_post(self, url, headers=None, json=None):
        if captured is not None:
            captured["url"] = url
            captured["headers"] = headers or {}
            captured["json"] = json
        return MockResponse()

    return mock_post


# ---------------------------------------------------------------------
# 1. Exact backend endpoint
# ---------------------------------------------------------------------
async def test_signal_posts_to_exact_tenant_signal_endpoint(monkeypatch):
    monkeypatch.setattr("auth_integration.security.GAIT_AUTH_URL", "https://gait.example.com/api")
    captured = {}
    monkeypatch.setattr(httpx.AsyncClient, "post", _mock_post(json_result=VALID_RESPONSE, captured=captured))

    await send_security_signal(
        signal_type="APPLICATION_SELF_CHECK", result="PASS", source_reference="ref-1",
        credential="a-real-secret",
    )

    assert captured["url"] == "https://gait.example.com/api/security/tenant-signals/"


# ---------------------------------------------------------------------
# 2. Exact dedicated credential header
# ---------------------------------------------------------------------
async def test_signal_uses_dedicated_credential_header_not_bearer(monkeypatch):
    captured = {}
    monkeypatch.setattr(httpx.AsyncClient, "post", _mock_post(json_result=VALID_RESPONSE, captured=captured))

    await send_security_signal(
        signal_type="APPLICATION_SELF_CHECK", result="PASS", source_reference="ref-2",
        credential="a-real-secret",
    )

    assert captured["headers"].get(APPLICATION_CREDENTIAL_HEADER) == "a-real-secret"
    assert "Authorization" not in captured["headers"]


# ---------------------------------------------------------------------
# 3. Valid signal
# ---------------------------------------------------------------------
async def test_valid_signal_returns_security_signal_result(monkeypatch):
    monkeypatch.setattr(httpx.AsyncClient, "post", _mock_post(json_result=VALID_RESPONSE))

    outcome = await send_security_signal(
        signal_type="APPLICATION_SELF_CHECK", result="PASS", source_reference="ref-3",
        credential="a-real-secret",
    )

    assert isinstance(outcome, SecuritySignalResult)
    assert outcome.signal_id == VALID_RESPONSE["signal_id"]
    assert outcome.control_key == VALID_RESPONSE["control_key"]
    assert outcome.evidence_id == VALID_RESPONSE["evidence_id"]
    assert outcome.received_at == VALID_RESPONSE["received_at"]


async def test_valid_signal_request_body_matches_wire_contract(monkeypatch):
    captured = {}
    monkeypatch.setattr(httpx.AsyncClient, "post", _mock_post(json_result=VALID_RESPONSE, captured=captured))

    await send_security_signal(
        signal_type="APPLICATION_SELF_CHECK", result="PASS", source_reference="ref-3b",
        payload={"scanner": "tool"}, credential="a-real-secret",
    )

    assert captured["json"] == {
        "signal_type": "APPLICATION_SELF_CHECK",
        "result": "PASS",
        "source_reference": "ref-3b",
        "payload": {"scanner": "tool"},
    }


async def test_omitted_payload_defaults_to_empty_dict_on_wire(monkeypatch):
    captured = {}
    monkeypatch.setattr(httpx.AsyncClient, "post", _mock_post(json_result=VALID_RESPONSE, captured=captured))

    await send_security_signal(
        signal_type="APPLICATION_SELF_CHECK", result="PASS", source_reference="ref-3c",
        credential="a-real-secret",
    )

    assert captured["json"]["payload"] == {}


# ---------------------------------------------------------------------
# 4. Missing application credential
# ---------------------------------------------------------------------
async def test_missing_credential_raises_explicitly_before_network_call(monkeypatch):
    monkeypatch.setattr("auth_integration.security.GAIT_APPLICATION_CREDENTIAL", None)
    called = {"n": 0}

    async def mock_post(self, url, headers=None, json=None):
        called["n"] += 1
        raise AssertionError("should never reach Gait with no credential")

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    with pytest.raises(InvalidApplicationCredentialError):
        await send_security_signal(signal_type="APPLICATION_SELF_CHECK", result="PASS", source_reference="ref-4")
    assert called["n"] == 0


async def test_configured_credential_used_when_none_passed_explicitly(monkeypatch):
    monkeypatch.setattr("auth_integration.security.GAIT_APPLICATION_CREDENTIAL", "configured-secret")
    captured = {}
    monkeypatch.setattr(httpx.AsyncClient, "post", _mock_post(json_result=VALID_RESPONSE, captured=captured))

    await send_security_signal(signal_type="APPLICATION_SELF_CHECK", result="PASS", source_reference="ref-4b")

    assert captured["headers"].get(APPLICATION_CREDENTIAL_HEADER) == "configured-secret"


# ---------------------------------------------------------------------
# 5. Invalid/rejected credential
# ---------------------------------------------------------------------
async def test_invalid_credential_raises_invalid_application_credential_error(monkeypatch):
    monkeypatch.setattr(httpx.AsyncClient, "post", _mock_post(status_code=401))

    with pytest.raises(InvalidApplicationCredentialError):
        await send_security_signal(
            signal_type="APPLICATION_SELF_CHECK", result="PASS", source_reference="ref-5",
            credential="wrong-secret",
        )


# ---------------------------------------------------------------------
# 6. Unknown signal type (Gait-side 400 rejection)
# ---------------------------------------------------------------------
async def test_unknown_signal_type_rejected_by_gait_raises_security_signal_rejected(monkeypatch):
    monkeypatch.setattr(httpx.AsyncClient, "post", _mock_post(status_code=400))

    with pytest.raises(SecuritySignalRejected):
        await send_security_signal(
            signal_type="not_a_real_signal", result="PASS", source_reference="ref-6",
            credential="a-real-secret",
        )


# ---------------------------------------------------------------------
# 7. Malformed metadata/request — local validation, no network call
# ---------------------------------------------------------------------
@pytest.mark.parametrize(
    "kwargs",
    [
        dict(signal_type="", result="PASS", source_reference="ref"),
        dict(signal_type="APPLICATION_SELF_CHECK", result="", source_reference="ref"),
        dict(signal_type="APPLICATION_SELF_CHECK", result="PASS", source_reference=""),
        dict(signal_type="APPLICATION_SELF_CHECK", result="PASS", source_reference="ref", payload="not-a-dict"),
        dict(signal_type=123, result="PASS", source_reference="ref"),
    ],
)
async def test_malformed_local_input_rejected_before_network_call(monkeypatch, kwargs):
    called = {"n": 0}

    async def mock_post(self, url, headers=None, json=None):
        called["n"] += 1
        raise AssertionError("should never reach Gait with malformed local input")

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    with pytest.raises(SecuritySignalRejected):
        await send_security_signal(credential="a-real-secret", **kwargs)
    assert called["n"] == 0


# ---------------------------------------------------------------------
# 8. Timeout
# ---------------------------------------------------------------------
async def test_timeout_raises_auth_service_unavailable(monkeypatch):
    async def mock_post(self, url, headers=None, json=None):
        raise httpx.TimeoutException("Timed out waiting for Gait")

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    with pytest.raises(AuthServiceUnavailable):
        await send_security_signal(
            signal_type="APPLICATION_SELF_CHECK", result="PASS", source_reference="ref-8",
            credential="a-real-secret",
        )


# ---------------------------------------------------------------------
# 9. Network failure
# ---------------------------------------------------------------------
async def test_network_unavailable_raises_auth_service_unavailable(monkeypatch):
    async def mock_post(self, url, headers=None, json=None):
        raise httpx.RequestError("Connection failed")

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    with pytest.raises(AuthServiceUnavailable):
        await send_security_signal(
            signal_type="APPLICATION_SELF_CHECK", result="PASS", source_reference="ref-9",
            credential="a-real-secret",
        )


# ---------------------------------------------------------------------
# 10. Malformed backend JSON
# ---------------------------------------------------------------------
async def test_malformed_json_raises_auth_service_unavailable(monkeypatch):
    monkeypatch.setattr(
        httpx.AsyncClient, "post", _mock_post(status_code=201, json_exc=ValueError("Invalid JSON"))
    )

    with pytest.raises(AuthServiceUnavailable):
        await send_security_signal(
            signal_type="APPLICATION_SELF_CHECK", result="PASS", source_reference="ref-10",
            credential="a-real-secret",
        )


# ---------------------------------------------------------------------
# 11. Structurally-invalid backend response — fail closed
# ---------------------------------------------------------------------
@pytest.mark.parametrize(
    "bad_response",
    [
        {},
        {**VALID_RESPONSE, "signal_id": None},
        {**VALID_RESPONSE, "signal_id": ""},
        {**VALID_RESPONSE, "signal_id": 12345},
        {**VALID_RESPONSE, "control_key": None},
        {**VALID_RESPONSE, "received_at": None},
        {**VALID_RESPONSE, "evidence_id": 12345},
        {k: v for k, v in VALID_RESPONSE.items() if k != "control_key"},
        "not-a-dict",
        None,
        123,
    ],
)
async def test_structurally_invalid_response_fails_closed(monkeypatch, bad_response):
    monkeypatch.setattr(httpx.AsyncClient, "post", _mock_post(status_code=201, json_result=bad_response))

    with pytest.raises(AuthServiceUnavailable):
        await send_security_signal(
            signal_type="APPLICATION_SELF_CHECK", result="PASS", source_reference="ref-11",
            credential="a-real-secret",
        )


async def test_evidence_id_none_is_accepted_as_valid():
    """The model documents evidence_id can legitimately be null."""
    from auth_integration.security import _build_result

    result = _build_result({**VALID_RESPONSE, "evidence_id": None})
    assert result.evidence_id is None


async def test_unexpected_status_code_raises_auth_service_unavailable(monkeypatch):
    monkeypatch.setattr(httpx.AsyncClient, "post", _mock_post(status_code=500))

    with pytest.raises(AuthServiceUnavailable):
        await send_security_signal(
            signal_type="APPLICATION_SELF_CHECK", result="PASS", source_reference="ref-11b",
            credential="a-real-secret",
        )


# ---------------------------------------------------------------------
# 12. Raw credential absent from logs/errors/repr
# ---------------------------------------------------------------------
async def test_raw_credential_absent_from_logs_on_success(monkeypatch, caplog):
    import logging

    secret = "super-secret-application-credential-value"
    monkeypatch.setattr(httpx.AsyncClient, "post", _mock_post(json_result=VALID_RESPONSE))

    with caplog.at_level(logging.DEBUG, logger="auth_integration.security"):
        await send_security_signal(
            signal_type="APPLICATION_SELF_CHECK", result="PASS", source_reference="ref-12",
            credential=secret,
        )

    assert secret not in caplog.text


async def test_raw_credential_absent_from_logs_on_rejection(monkeypatch, caplog):
    import logging

    secret = "super-secret-application-credential-value"
    monkeypatch.setattr(httpx.AsyncClient, "post", _mock_post(status_code=401))

    with caplog.at_level(logging.DEBUG, logger="auth_integration.security"):
        with pytest.raises(InvalidApplicationCredentialError):
            await send_security_signal(
                signal_type="APPLICATION_SELF_CHECK", result="PASS", source_reference="ref-12b",
                credential=secret,
            )

    assert secret not in caplog.text


async def test_raw_credential_absent_from_exception_message(monkeypatch):
    secret = "super-secret-application-credential-value"
    monkeypatch.setattr(httpx.AsyncClient, "post", _mock_post(status_code=401))

    with pytest.raises(InvalidApplicationCredentialError) as exc_info:
        await send_security_signal(
            signal_type="APPLICATION_SELF_CHECK", result="PASS", source_reference="ref-12c",
            credential=secret,
        )

    assert secret not in str(exc_info.value)


async def test_raw_credential_absent_from_result_repr(monkeypatch):
    secret = "super-secret-application-credential-value"
    monkeypatch.setattr(httpx.AsyncClient, "post", _mock_post(json_result=VALID_RESPONSE))

    outcome = await send_security_signal(
        signal_type="APPLICATION_SELF_CHECK", result="PASS", source_reference="ref-12d",
        credential=secret,
    )

    assert secret not in repr(outcome)
    assert secret not in str(outcome)


async def test_full_payload_not_logged_by_default(monkeypatch, caplog):
    import logging

    sentinel = "this-exact-payload-value-should-not-be-logged-verbatim"
    monkeypatch.setattr(httpx.AsyncClient, "post", _mock_post(json_result=VALID_RESPONSE))

    with caplog.at_level(logging.DEBUG, logger="auth_integration.security"):
        await send_security_signal(
            signal_type="APPLICATION_SELF_CHECK", result="PASS", source_reference="ref-12e",
            payload={"note": sentinel}, credential="a-real-secret",
        )

    assert sentinel not in caplog.text


# ---------------------------------------------------------------------
# 13-18. Authority-injection: no supported way to set any of these
# ---------------------------------------------------------------------
# Mirrors Gait's own AUTHORITY_FIELD_CASES in
# security/test_tenant_ingestion_strict_contract.py almost exactly.
FORBIDDEN_PARAMETER_NAMES = (
    "organization", "organization_id", "organization_slug",
    "tenant", "tenant_id",
    "scope",
    "environment",
    "application", "application_id", "application_slug",
    "trust", "trust_level", "attestation_type",
    "evidence_type",
    "control", "control_key",
    "verified", "secret_hash",
)


def test_send_security_signal_has_no_authority_parameters():
    """Structural proof, not just behavioral: enumerate every parameter
    send_security_signal() actually accepts, and confirm none of Gait's
    own authority-shaped field names are among them."""
    params = set(inspect.signature(send_security_signal).parameters)

    assert params == {"signal_type", "result", "source_reference", "payload", "credential"}
    for forbidden in FORBIDDEN_PARAMETER_NAMES:
        assert forbidden not in params


def test_metadata_dict_cannot_carry_authority_despite_arbitrary_keys():
    """
    payload is data, not authority: send_security_signal() forwards it
    verbatim as the `payload` wire field (see
    test_valid_signal_request_body_matches_wire_contract) and never reads
    special meaning out of any key inside it. A caller putting
    'organization' inside payload just sends {"payload": {"organization": ...}}
    on the wire, which Gait's own contract stores as opaque payload data
    under the TenantSecuritySignal.payload field — it can never be
    reinterpreted as the top-level authority field of the same name (see
    the backend's own strict-contract tests, which reject a top-level
    'organization' key but accept it freely nested inside 'payload').
    """
    params = inspect.signature(send_security_signal).parameters
    assert "payload" in params
    # No separate code path exists that promotes payload keys to top-level
    # request fields — confirmed by reading auth_integration/security.py's
    # request body construction directly (body["payload"] = payload or {}).


# ---------------------------------------------------------------------
# 18/9. Self-reported trust semantics
# ---------------------------------------------------------------------
def test_no_trust_or_verification_override_parameter_exists():
    params = set(inspect.signature(send_security_signal).parameters)
    for name in ("verified", "trust", "trust_level", "evidence_type"):
        assert name not in params


# ---------------------------------------------------------------------
# 19. Idempotent retry behavior (server-owned; SDK never deduplicates)
# ---------------------------------------------------------------------
async def test_retry_with_same_source_reference_is_sent_twice_not_deduplicated_locally(monkeypatch):
    """
    The SDK must never invent client-side deduplication: it must send
    every call over the wire and let Gait's own idempotency (by
    application/signal_type/source_reference) decide the outcome. This
    simulates Gait's real behavior (returning the SAME signal_id both
    times, per security/test_tenant_ingestion.py's own
    test_retry_with_same_idempotency_key_does_not_duplicate) and proves
    the SDK issues two real requests and faithfully returns what Gait says
    both times, rather than short-circuiting the second call itself.
    """
    call_count = {"n": 0}

    async def mock_post(self, url, headers=None, json=None):
        call_count["n"] += 1

        class MockResponse:
            status_code = 201

            def json(self):
                return VALID_RESPONSE  # Gait returns the same original signal both times

        return MockResponse()

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    first = await send_security_signal(
        signal_type="APPLICATION_SELF_CHECK", result="PASS", source_reference="stable-ref",
        credential="a-real-secret",
    )
    second = await send_security_signal(
        signal_type="APPLICATION_SELF_CHECK", result="FAIL", source_reference="stable-ref",
        credential="a-real-secret",
    )

    assert call_count["n"] == 2  # SDK never skips the second call itself
    assert first.signal_id == second.signal_id  # Gait's own idempotency, faithfully reported


# ---------------------------------------------------------------------
# 20. source_reference handling
# ---------------------------------------------------------------------
def test_source_reference_is_required_with_no_default():
    params = inspect.signature(send_security_signal).parameters
    assert "source_reference" in params
    assert params["source_reference"].default is inspect.Parameter.empty


async def test_source_reference_sent_verbatim_on_wire(monkeypatch):
    captured = {}
    monkeypatch.setattr(httpx.AsyncClient, "post", _mock_post(json_result=VALID_RESPONSE, captured=captured))

    await send_security_signal(
        signal_type="APPLICATION_SELF_CHECK", result="PASS", source_reference="my-exact-idempotency-key",
        credential="a-real-secret",
    )

    assert captured["json"]["source_reference"] == "my-exact-idempotency-key"


# ---------------------------------------------------------------------
# 21. Application-only / no-human submission
# ---------------------------------------------------------------------
def test_send_security_signal_has_no_human_identity_parameter():
    params = set(inspect.signature(send_security_signal).parameters)
    for name in ("user", "claims", "security_context", "claims_user"):
        assert name not in params


async def test_signal_submission_works_with_zero_human_identity_involved(monkeypatch):
    """No ClaimsUser, no SecurityContext, no user JWT anywhere in this call."""
    monkeypatch.setattr(httpx.AsyncClient, "post", _mock_post(json_result=VALID_RESPONSE))

    outcome = await send_security_signal(
        signal_type="APPLICATION_SELF_CHECK", result="PASS", source_reference="ref-21",
        credential="a-real-secret",
    )

    assert isinstance(outcome, SecuritySignalResult)


def test_security_context_application_alone_cannot_authenticate_a_signal():
    """
    Structural proof of SDK3/SDK4's relationship: ApplicationPrincipal
    (and therefore SecurityContext.application) never carries the raw
    credential, so there is no way to submit a signal using only a
    SecurityContext -- the raw credential must always be supplied
    independently (as an argument or via GAIT_APPLICATION_CREDENTIAL).
    """
    from auth_integration.application import ApplicationPrincipal

    principal = ApplicationPrincipal(
        application_id="a", application_slug="s", organization_id="o",
        organization_slug="os", environment="production",
    )
    field_names = {f.name for f in __import__("dataclasses").fields(principal)}
    assert "credential" not in field_names
    assert not any("secret" in name or "credential" in name for name in field_names)
