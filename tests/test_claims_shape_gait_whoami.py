"""0.5.2: the DRF introspection path accepts Gait's real /whoami/ shape.

Gait serializes its integer primary key as a JSON number, allows empty
profile names, and (per its token contract) is removing the legacy `role`
field. 0.5.1 required every field to be a non-empty string, so real Gait
responses failed with "Invalid authentication response." (401 on every
request). Identity (`id`, `email`) stays fail-closed.
"""

import pytest
from rest_framework.exceptions import AuthenticationFailed

from gait_sdk.django.authentication import (
    ClaimsUser,
    ExternalJWTAuthentication,
    _validate_claims_shape,
)


def whoami(**overrides):
    body = {
        "id": 42,  # Gait sends an int (BigAutoField)
        "first_name": "Ada",
        "last_name": "Lovelace",
        "email": "ada@example.com",
        "is_2fa_enabled": False,
        "role": "technologist",
        "email_verified": True,
        "is_superuser": False,
        "is_gait_operator": False,
    }
    body.update(overrides)
    return body


def test_int_id_is_normalized_to_str():
    claims = _validate_claims_shape(whoami(id=42))
    assert claims["id"] == "42"
    assert isinstance(claims["id"], str)


def test_str_id_is_unchanged():
    assert _validate_claims_shape(whoami(id="42"))["id"] == "42"


def test_validation_does_not_mutate_the_input():
    raw = whoami(id=7)
    _validate_claims_shape(raw)
    assert raw["id"] == 7


def test_extra_whoami_fields_are_preserved():
    claims = _validate_claims_shape(whoami())
    assert claims["email_verified"] is True
    assert claims["is_2fa_enabled"] is False


@pytest.mark.parametrize("bad_id", [True, False, None, "", 4.2, [], {}])
def test_bad_ids_fail_closed(bad_id):
    with pytest.raises(AuthenticationFailed):
        _validate_claims_shape(whoami(id=bad_id))


@pytest.mark.parametrize("field", ["first_name", "last_name"])
def test_empty_names_are_accepted(field):
    claims = _validate_claims_shape(whoami(**{field: ""}))
    assert claims[field] == ""


@pytest.mark.parametrize("field", ["role", "first_name", "last_name"])
def test_missing_optional_field_defaults_to_empty_string(field):
    body = whoami()
    del body[field]
    claims = _validate_claims_shape(body)
    assert claims[field] == ""


def test_whoami_without_role_still_authenticates():
    """Gait's contract removes `role` from /whoami/ (stage 4); that must not 401."""
    body = whoami()
    del body["role"]
    assert _validate_claims_shape(body)["role"] == ""


def test_empty_role_is_accepted():
    assert _validate_claims_shape(whoami(role=""))["role"] == ""


@pytest.mark.parametrize("field", ["role", "first_name", "last_name"])
@pytest.mark.parametrize("bad", [None, 1, ["x"]])
def test_non_string_optional_field_is_rejected(field, bad):
    with pytest.raises(AuthenticationFailed):
        _validate_claims_shape(whoami(**{field: bad}))


@pytest.mark.parametrize("bad", ["", None, 1])
def test_email_stays_fail_closed(bad):
    with pytest.raises(AuthenticationFailed):
        _validate_claims_shape(whoami(email=bad))


@pytest.mark.parametrize("field", ["id", "email"])
def test_missing_identity_key_is_rejected(field):
    body = whoami()
    del body[field]
    with pytest.raises(AuthenticationFailed):
        _validate_claims_shape(body)


class _Request:
    def __init__(self):
        self.headers = {"Authorization": "Bearer some.token"}
        self.META = {"HTTP_AUTHORIZATION": "Bearer some.token"}
        self.COOKIES = {}


def test_drf_authenticate_with_real_gait_shape_yields_string_identity(monkeypatch):
    """End to end through ExternalJWTAuthentication (introspection path)."""

    async def fake_validate_token(token):
        body = whoami(id=42, last_name="")
        del body["role"]
        return body

    monkeypatch.setattr("gait_sdk.django.authentication.validate_token", fake_validate_token)
    monkeypatch.setattr("gait_sdk.django.authentication._cache_get", lambda token: None)
    monkeypatch.setattr("gait_sdk.django.authentication._cache_set", lambda token, claims: None)

    request = _Request()
    user, claims = ExternalJWTAuthentication().authenticate(request)

    assert isinstance(user, ClaimsUser)
    assert user.id == "42"
    assert user.last_name == ""
    assert user.role == ""  # same shape the JWKS path yields
    assert claims["id"] == "42"
    assert request.verified_identity.subject == "42"
