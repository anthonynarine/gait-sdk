# Filename: gait_sdk/application.py
"""
gait_sdk.application — Gait Application (machine) identity
====================================================================

SDK2: adds Gait's machine/software identity to gait_sdk, kept
strictly independent of — and never merged with — human identity.

Framework-agnostic, deliberately mirroring `gait_sdk.client`'s own
structure and style:

- `ApplicationPrincipal` — an immutable value object representing a
  Gait-verified Application/Organization/environment identity.
- `verify_application()` — the one function that turns a raw
  `ApplicationCredential` secret into a verified `ApplicationPrincipal` by
  calling Gait's dedicated application-verification endpoint.

Identity separation (do not blur this):
-----------------------------------------------------------------------
- `ClaimsUser` / user claims (`gait_sdk.django.authentication`,
  `gait_sdk.fastapi.dependencies`) = HUMAN identity, derived from
  a user JWT via Gait's `/whoami/`.
- `ApplicationPrincipal` (this module) = SOFTWARE identity, derived from
  an `ApplicationCredential` secret via Gait's `/applications/verify/`.

Verifying one never establishes, requires, or invalidates the other — see
`tests/test_application.py`'s independence tests. Do not add an
organization/environment/application field to `ClaimsUser`, and do not add
a human role to `ApplicationPrincipal`.

Verified read-only against Gait's frozen backend contract
(`applications/views.py`, `applications/serializers.py`,
`applications/services.py`, `applications/test_verification_api.py` in the
Gait backend repo) — not invented. Endpoint: `POST /api/applications/verify/`
(same `GAIT_AUTH_URL` base as `/whoami/`). Credential transport: a
dedicated header, never the human `Authorization: Bearer` header — a
single request may need to carry both a user token and an application
credential at once. Every failure (missing/unknown/revoked/expired
credential, or a suspended/revoked owning Application) is a uniform 401
with no distinguishing detail — Gait deliberately does not give an
unauthenticated caller an oracle for probing credential/application state,
and this SDK does not attempt to recover a finer-grained reason either.

Security:
---------
- The raw ApplicationCredential is never logged, never stored on
  `ApplicationPrincipal`, and never echoed into any exception message.
- `organization_id`, `organization_slug`, and `environment` are exactly
  what Gait's verification response says — there is no parameter on
  `verify_application()` through which a caller can select, override, or
  broaden any of them.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Optional

import httpx

from gait_sdk.exceptions import AuthServiceUnavailable, InvalidApplicationCredentialError
from gait_sdk.settings import GAIT_APPLICATION_CREDENTIAL, GAIT_AUTH_URL, GAIT_TIMEOUT

# -----------------------------------------------------------------------------
# ⚙️ Logger (never logs the raw credential — see verify_application)
# -----------------------------------------------------------------------------
logger = logging.getLogger("gait_sdk.application")
logger.setLevel(logging.INFO)

# -----------------------------------------------------------------------------
# 🔑 Dedicated application-credential transport
# -----------------------------------------------------------------------------
# Must match Gait's own applications/views.py::APPLICATION_CREDENTIAL_HEADER
# exactly — confirmed by read-only inspection of the frozen backend, not
# guessed. Deliberately never Authorization: Bearer, which is reserved for
# human tokens (see module docstring).
APPLICATION_CREDENTIAL_HEADER = "Gait-Application-Credential"

# Gait's own Application.Environment choices (applications/models.py),
# mirrored here only so this SDK can fail closed on an unrecognized value.
# This module has no opinion about what any of these environments *mean* —
# it only refuses to build an ApplicationPrincipal around a value Gait
# itself wouldn't have produced.
_VALID_ENVIRONMENTS = frozenset({"local", "test", "ci", "staging", "production"})

_REQUIRED_STRING_FIELDS = (
    "application_id",
    "application_slug",
    "organization_id",
    "organization_slug",
    "environment",
)


# -----------------------------------------------------------------------------
# ✅ ApplicationPrincipal — verified machine identity
# -----------------------------------------------------------------------------
@dataclass(frozen=True)
class ApplicationPrincipal:
    """A Gait-verified machine/software identity.

    Represents "Gait has verified this software identity" — nothing about
    what that software is authorized to do, and nothing about any human.
    Every field comes directly from Gait's verification response; this SDK
    never fills in, defaults, or overrides any of them.

    Deliberately excludes: the credential itself, any credential hash/id,
    a human role, business-domain permissions, and a Lumen Facility or
    Lumen Organization. See module docstring for the identity-separation
    rationale this reflects.
    """

    application_id: str
    application_slug: str
    organization_id: str
    organization_slug: str
    environment: str


def _build_application_principal(raw: Any) -> ApplicationPrincipal:
    """Validate Gait's verification response shape before trusting it (fail closed).

    Authoritative but not blindly trusted: every required field must be a
    non-empty string, and `environment` must be one of Gait's own known
    values. A response missing, mistyping, or emptying any of these never
    produces a partially-populated ApplicationPrincipal — it raises
    AuthServiceUnavailable instead, the same failure class already used
    for "Gait's response can't be trusted" elsewhere in this package (see
    gait_sdk.client.validate_token's own malformed-JSON handling).
    """
    if not isinstance(raw, dict):
        raise AuthServiceUnavailable("Malformed response from authentication service.")

    for key in _REQUIRED_STRING_FIELDS:
        value = raw.get(key)
        if not isinstance(value, str) or not value:
            raise AuthServiceUnavailable("Malformed response from authentication service.")

    if raw["environment"] not in _VALID_ENVIRONMENTS:
        raise AuthServiceUnavailable("Malformed response from authentication service.")

    return ApplicationPrincipal(
        application_id=raw["application_id"],
        application_slug=raw["application_slug"],
        organization_id=raw["organization_id"],
        organization_slug=raw["organization_slug"],
        environment=raw["environment"],
    )


# -----------------------------------------------------------------------------
# 🔐 Public API — verify_application
# -----------------------------------------------------------------------------
async def verify_application(credential: Optional[str] = None) -> ApplicationPrincipal:
    """
    Verify a Gait ApplicationCredential and return the resulting ApplicationPrincipal.

    Args:
        credential: The raw ApplicationCredential secret. If omitted, falls
            back to the server-side `GAIT_APPLICATION_CREDENTIAL` setting.
            This value is a backend secret — never accept it from a
            browser/frontend request, and never pass a value a caller
            supplied over an untrusted channel.

    Returns:
        ApplicationPrincipal: the Gait-verified machine identity. Its
        `organization_id`, `organization_slug`, and `environment` are
        exactly what Gait returned — there is no argument here through
        which a caller can select or broaden any of them (see PART 9/10 of
        the SDK2 milestone this implements).

    Raises:
        InvalidApplicationCredentialError: the credential is missing (not
            configured/provided) or Gait rejected it (unknown, revoked,
            expired, or belongs to a suspended/revoked Application) — Gait
            itself does not distinguish these reasons in its own response,
            and this SDK does not attempt to re-derive a finer-grained one.
        AuthServiceUnavailable: Gait is unreachable, times out, or returns
            a response this SDK cannot parse or trust (malformed JSON, an
            unexpected status code, or a structurally invalid identity
            payload).
    """
    # Step 1: resolve the credential — explicit failure if none exists,
    # never a silently manufactured or fallback identity.
    raw_credential = credential if credential is not None else GAIT_APPLICATION_CREDENTIAL
    if not raw_credential:
        logger.error("No application credential configured or provided - cannot verify.")
        raise InvalidApplicationCredentialError("Application credential is not configured.")

    if not GAIT_AUTH_URL:
        logger.error("Missing GAIT_AUTH_URL - cannot verify application identity.")
        raise AuthServiceUnavailable("Authentication service misconfigured.")

    url = f"{GAIT_AUTH_URL.rstrip('/')}/applications/verify/"
    headers = {APPLICATION_CREDENTIAL_HEADER: raw_credential}

    # Step 2: call Gait. Never log `headers` or `raw_credential`.
    try:
        async with httpx.AsyncClient(timeout=GAIT_TIMEOUT) as client:
            response = await client.post(url, headers=headers)
    except httpx.RequestError:
        logger.error("Gait application-verification API unreachable.")
        raise AuthServiceUnavailable("Authentication service unreachable.")

    # Step 3: interpret the response.
    if response.status_code == 200:
        try:
            raw = response.json()
        except Exception:
            logger.error("Malformed JSON from Gait during application verification.")
            raise AuthServiceUnavailable("Malformed response from authentication service.")
        return _build_application_principal(raw)

    if response.status_code == 401:
        logger.warning("Application credential rejected by Gait.")
        raise InvalidApplicationCredentialError("Invalid application credential.")

    logger.error("Unexpected status %s from Gait during application verification.", response.status_code)
    raise AuthServiceUnavailable(f"Unexpected response: {response.status_code}")
