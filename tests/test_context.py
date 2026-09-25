# Filename: tests/test_context.py
"""
SDK3 — regression tests for gait_sdk.context.SecurityContext.

Covers SDK3 Part 14's required test matrix items 1-10 (11-16 are the
existing suites, run alongside this file as part of the full run).
"""

import dataclasses

import httpx
import pytest

from gait_sdk.application import ApplicationPrincipal
from gait_sdk.context import SecurityContext


CLAIMS_USER_KWARGS = dict(
    id="u1", email="doc@example.com", role="physician",
    first_name="Doc", last_name="McGee",
)

CLAIMS_DICT = dict(CLAIMS_USER_KWARGS)

APPLICATION_KWARGS = dict(
    application_id="app-1",
    application_slug="lumen-media",
    organization_id="org-1",
    organization_slug="mount-sinai",
    environment="production",
)


def _real_claims_user():
    from gait_sdk.django.authentication import ClaimsUser

    return ClaimsUser(**CLAIMS_USER_KWARGS)


def _real_application_principal():
    return ApplicationPrincipal(**APPLICATION_KWARGS)


# ---------------------------------------------------------------------
# 1. User-only context
# ---------------------------------------------------------------------
def test_user_only_context_with_real_claims_user():
    user = _real_claims_user()
    context = SecurityContext(user=user)

    assert context.has_user is True
    assert context.has_application is False
    assert context.user is user
    assert context.application is None


def test_user_only_context_with_fastapi_claims_dict():
    """FastAPI's verify_token() returns a raw claims dict, never a
    ClaimsUser instance -- SecurityContext must accept that shape too."""
    context = SecurityContext(user=dict(CLAIMS_DICT))

    assert context.has_user is True
    assert context.user["email"] == "doc@example.com"


# ---------------------------------------------------------------------
# 2. Application-only context
# ---------------------------------------------------------------------
def test_application_only_context():
    application = _real_application_principal()
    context = SecurityContext(application=application)

    assert context.has_application is True
    assert context.has_user is False
    assert context.application is application
    assert context.user is None


# ---------------------------------------------------------------------
# 3. Both identities
# ---------------------------------------------------------------------
def test_both_identities_context():
    user = _real_claims_user()
    application = _real_application_principal()
    context = SecurityContext(user=user, application=application)

    assert context.has_user is True
    assert context.has_application is True
    assert context.user is user
    assert context.application is application


# ---------------------------------------------------------------------
# 4. Neither identity -- explicitly rejected
# ---------------------------------------------------------------------
def test_neither_identity_is_rejected():
    with pytest.raises(ValueError):
        SecurityContext()


def test_neither_identity_explicit_none_is_rejected():
    with pytest.raises(ValueError):
        SecurityContext(user=None, application=None)


# ---------------------------------------------------------------------
# 5. Immutability
# ---------------------------------------------------------------------
def test_security_context_is_immutable():
    context = SecurityContext(user=_real_claims_user())

    with pytest.raises(dataclasses.FrozenInstanceError):
        context.user = None  # type: ignore[misc]

    with pytest.raises(dataclasses.FrozenInstanceError):
        context.application = _real_application_principal()  # type: ignore[misc]


def test_composing_context_does_not_mutate_contained_principals():
    user = _real_claims_user()
    application = _real_application_principal()

    SecurityContext(user=user, application=application)

    # The exact same objects, untouched.
    assert user.email == "doc@example.com"
    assert application.environment == "production"


# ---------------------------------------------------------------------
# 6 / 7. Identity preserved exactly
# ---------------------------------------------------------------------
def test_user_identity_preserved_exactly():
    user = _real_claims_user()
    context = SecurityContext(user=user)

    assert context.user is user  # identity, not merely equality
    assert context.user.id == "u1"
    assert context.user.role == "physician"


def test_application_identity_preserved_exactly():
    application = _real_application_principal()
    context = SecurityContext(application=application)

    assert context.application is application
    assert context.application.organization_slug == "mount-sinai"
    assert context.application.environment == "production"


# ---------------------------------------------------------------------
# 8. No cross-derived fields
# ---------------------------------------------------------------------
def test_application_only_context_has_no_user_derived_fields():
    context = SecurityContext(application=_real_application_principal())

    assert context.user is None  # no human identity synthesized


def test_user_only_context_has_no_application_derived_fields():
    context = SecurityContext(user=_real_claims_user())

    assert context.application is None  # no application identity synthesized


def test_application_principal_has_no_role_field():
    """Structural proof: a human role could never be read off ApplicationPrincipal."""
    application = _real_application_principal()
    assert not hasattr(application, "role")


def test_claims_user_has_no_environment_or_organization_field():
    """Structural proof: environment/organization could never be read off ClaimsUser."""
    user = _real_claims_user()
    assert not hasattr(user, "environment")
    assert not hasattr(user, "organization_id")
    assert not hasattr(user, "organization_slug")


def test_environment_belongs_only_to_application_principal():
    context = SecurityContext(user=_real_claims_user(), application=_real_application_principal())

    assert context.application.environment == "production"
    assert not hasattr(context.user, "environment")


# ---------------------------------------------------------------------
# 9. Construction performs no network I/O
# ---------------------------------------------------------------------
def test_construction_performs_no_network_io(monkeypatch):
    async def _explode(*args, **kwargs):
        raise AssertionError("SecurityContext construction must never call Gait")

    monkeypatch.setattr(httpx.AsyncClient, "get", _explode)
    monkeypatch.setattr(httpx.AsyncClient, "post", _explode)

    # Should not raise, and certainly not touch the network.
    SecurityContext(user=_real_claims_user())
    SecurityContext(application=_real_application_principal())
    SecurityContext(user=dict(CLAIMS_DICT), application=_real_application_principal())


# ---------------------------------------------------------------------
# 10. Raw application credential absent from repr
# ---------------------------------------------------------------------
async def test_raw_application_credential_absent_from_context_repr(monkeypatch):
    from gait_sdk.application import verify_application

    secret = "super-secret-application-credential-value"

    class MockResponse:
        status_code = 200

        def json(self):
            return dict(APPLICATION_KWARGS)

    async def mock_post(self, url, headers=None):
        return MockResponse()

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)
    application = await verify_application(credential=secret)

    context = SecurityContext(user=_real_claims_user(), application=application)

    assert secret not in repr(context)
    assert secret not in str(context)


# ---------------------------------------------------------------------
# Type-validation: malformed local input fails closed (not network-shaped)
# ---------------------------------------------------------------------
def test_malformed_user_dict_missing_required_key_raises_type_error():
    bad = {k: v for k, v in CLAIMS_DICT.items() if k != "role"}
    with pytest.raises(TypeError):
        SecurityContext(user=bad)


def test_application_as_plain_dict_is_rejected():
    """Only a real, already-verified ApplicationPrincipal is accepted --
    never a dict shaped like one, which could be caller-fabricated."""
    with pytest.raises(TypeError):
        SecurityContext(application=dict(APPLICATION_KWARGS))


def test_user_as_unrelated_object_is_rejected():
    with pytest.raises(TypeError):
        SecurityContext(user=object())
