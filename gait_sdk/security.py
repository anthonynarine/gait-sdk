# Filename: gait_sdk/security.py
"""
gait_sdk.security — Tenant Security Signal Client
====================================================================

SDK4: lets a customer backend submit a narrowly-defined security signal
into the hosted Gait SaaS, authenticated as an APPLICATION (never a human),
using the same `GAIT_APPLICATION_CREDENTIAL`/verification mechanism SDK2
already established.

This is NOT:
    - a general Gait API client
    - an Observatory / findings-retrieval client (read-side; not built here)
    - agent orchestration
    - automatic telemetry (no middleware, no background thread, nothing
      calls this on your behalf — every signal is an explicit call site)

What a tenant security signal IS
---------------------------------
A customer-originated claim: "the application identified by this
ApplicationCredential is reporting this security-relevant outcome." Gait
records it as evidence, but — critically — as `CUSTOMER_REPORTED` evidence,
never as if it were Gait's own independent verification. Submitting a
signal never upgrades trust: a customer's own self-check always remains
self-reported, no matter what payload it carries.

What it is NOT
---------------
- Not proof of anything Gait itself observed or verified.
- Not a way to write PLATFORM-scope security state — every signal produced
  through this module is TENANT-scoped, to the calling Application's own
  Organization, and nothing else.
- Not a channel for asserting identity/authority. There is no parameter
  anywhere in this module for organization, environment, application,
  scope, tenant, trust level, evidence type, or control mapping — see
  "Authority derivation" below.

Wire contract (verified read-only against the frozen Gait backend)
--------------------------------------------------------------------
- `POST {GAIT_AUTH_URL}/security/tenant-signals/` — same `GAIT_AUTH_URL`
  base already used for `/whoami/` and `/applications/verify/`.
- Credential transport: the same dedicated `Gait-Application-Credential`
  header SDK2's `verify_application()` already uses — never
  `Authorization: Bearer`, and never a second/new credential setting.
- Request body: exactly `signal_type`, `result`, `source_reference`, and
  optional `payload` — Gait's own request serializer explicitly REJECTS
  (400, naming the field) any other top-level key, rather than silently
  discarding it. This module structurally cannot send anything else: it
  has no parameter for any authority-shaped field at all.
- Response (201): `signal_id`, `control_key`, `evidence_id`,
  `received_at` — see `SecuritySignalResult`.
- Response (401): credential missing/unknown/revoked/expired, or the
  owning Application/Organization suspended/revoked — one uniform
  response, same as `verify_application()`'s own 401 contract.
- Response (400): `signal_type` not in Gait's own approved registry,
  invalid `result`, missing/invalid `source_reference`, or an
  oversized/invalid `payload` — one uniform `{"detail": "..."}"`, no
  per-reason detail (Gait's own deliberate enumeration resistance).

Authority derivation (the part this module structurally cannot override)
--------------------------------------------------------------------------
Gait derives `organization`, `environment`, and `application` identity
entirely from the verified `ApplicationCredential` — never from anything
in the request body. `send_security_signal()` has no `organization`,
`environment`, `application`, `scope`, `trust`, `evidence_type`, or
`control` parameter; there is no supported way to pass one. See
`tests/test_security_signal.py`'s authority-injection tests for direct,
structural proof (via `inspect.signature`) that these parameters simply
do not exist on this function.

Human identity independence
-----------------------------
This endpoint authenticates the calling APPLICATION only — Gait's own view
has `authentication_classes = []` and never touches a human JWT/cookie/
`ClaimsUser` at all. `send_security_signal()` accordingly takes no user/
`ClaimsUser`/`SecurityContext` parameter. A verified `ApplicationPrincipal`
or `SecurityContext.application` is useful for a caller's own bookkeeping,
but NEVER substitutes for the credential here: this function always
independently authenticates with the raw credential, exactly like
`verify_application()` does, because Gait's endpoint re-verifies the
credential fresh on every request — there is no session or prior
verification to "reuse."

Idempotency
-----------
Gait deduplicates by the triple (application, signal_type,
source_reference): an exact retry returns the SAME persisted signal
(same `signal_id`/`control_key`/`evidence_id`), still with a `201`
response — Gait's contract does not distinguish "freshly created" from
"idempotent replay" in its response shape, so `SecuritySignalResult` does
not invent such a field either. If a retry's `result`/`payload` differ
from the first successful call, the ORIGINAL values win — Gait never
mutates an already-recorded signal. `source_reference` is therefore not
optional in this SDK's public API: callers must supply their own stable
idempotency key, exactly as Gait's own contract requires.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Optional

import httpx

from gait_sdk.application import APPLICATION_CREDENTIAL_HEADER
from gait_sdk.exceptions import (
    AuthServiceUnavailable,
    InvalidApplicationCredentialError,
    SecuritySignalRejected,
)
from gait_sdk.settings import GAIT_APPLICATION_CREDENTIAL, GAIT_AUTH_URL, GAIT_TIMEOUT

# -----------------------------------------------------------------------------
# ⚙️ Logger — never logs the raw credential or the full payload (see
# send_security_signal). Logs event category / status / signal type / a
# safe correlation identifier (source_reference) only.
# -----------------------------------------------------------------------------
logger = logging.getLogger("gait_sdk.security")
logger.setLevel(logging.INFO)

# One currently-known approved signal_type, exposed only as a convenience
# constant — NOT an exhaustive enum. Gait's own tenant_signal_registry.py
# is an explicitly growable, code-reviewed backend structure ("adding a new
# approved signal_type is a code change and a review, not a runtime
# configuration action"); duplicating its full contents into this SDK would
# create version drift — a new backend-approved signal_type would need a
# new SDK release before a typed caller could reference it, even though the
# wire contract itself (a plain string field) already supports it today.
# `signal_type` therefore stays a plain `str` parameter below, matching the
# same "don't bake the vocabulary in" decision SDK1 made for `role`.
APPLICATION_SELF_CHECK = "APPLICATION_SELF_CHECK"

# Gait's own SecurityEvidence.Result choices (security/models.py) — a
# small, stable set, unlike the growable signal-type registry. Documented
# here for caller convenience; not enforced client-side (Gait's own
# ChoiceField already fails closed on anything else).
KNOWN_RESULTS = ("PASS", "FAIL", "WARNING", "INFORMATIONAL")


@dataclass(frozen=True)
class SecuritySignalResult:
    """The verified outcome of a successful tenant security signal submission.

    Every field here is exactly what Gait's own response contains — nothing
    invented. In particular, there is no "duplicate"/"idempotent" flag:
    Gait's own response shape does not distinguish a freshly-created signal
    from an idempotent replay (see module docstring), so this object
    doesn't pretend to know the difference either.
    """

    signal_id: str
    control_key: str
    evidence_id: Optional[str]
    received_at: str


def _validate_local_input(signal_type: str, result: str, source_reference: str, payload: Any) -> None:
    """Reject obviously-malformed local input before any network call.

    Deliberately does NOT duplicate Gait's own numeric bounds (max payload
    keys, max string lengths) — those are the server's to own and could
    drift independently of this SDK; duplicating them risks a client-side
    rejection for something the server would actually have accepted. Only
    structural sanity (right type, non-empty) is checked here.
    """
    if not isinstance(signal_type, str) or not signal_type:
        raise SecuritySignalRejected("signal_type must be a non-empty string.")
    if not isinstance(result, str) or not result:
        raise SecuritySignalRejected("result must be a non-empty string.")
    if not isinstance(source_reference, str) or not source_reference:
        raise SecuritySignalRejected("source_reference must be a non-empty string.")
    if payload is not None and not isinstance(payload, dict):
        raise SecuritySignalRejected("payload must be a dict or None.")


def _build_result(raw: Any) -> SecuritySignalResult:
    """Validate Gait's response shape before trusting it (fail closed)."""
    if not isinstance(raw, dict):
        raise AuthServiceUnavailable("Malformed response from authentication service.")

    signal_id = raw.get("signal_id")
    control_key = raw.get("control_key")
    received_at = raw.get("received_at")
    evidence_id = raw.get("evidence_id")

    if not isinstance(signal_id, str) or not signal_id:
        raise AuthServiceUnavailable("Malformed response from authentication service.")
    if not isinstance(control_key, str) or not control_key:
        raise AuthServiceUnavailable("Malformed response from authentication service.")
    if not isinstance(received_at, str) or not received_at:
        raise AuthServiceUnavailable("Malformed response from authentication service.")
    if evidence_id is not None and not isinstance(evidence_id, str):
        raise AuthServiceUnavailable("Malformed response from authentication service.")

    return SecuritySignalResult(
        signal_id=signal_id,
        control_key=control_key,
        evidence_id=evidence_id,
        received_at=received_at,
    )


# -----------------------------------------------------------------------------
# 🔐 Public API — send_security_signal
# -----------------------------------------------------------------------------
async def send_security_signal(
    *,
    signal_type: str,
    result: str,
    source_reference: str,
    payload: Optional[dict] = None,
    credential: Optional[str] = None,
) -> SecuritySignalResult:
    """
    Submit one tenant security signal to Gait, authenticated as an application.

    Args:
        signal_type: Which approved signal this is (e.g.
            `gait_sdk.security.APPLICATION_SELF_CHECK`). Gait
            rejects any value not in its own approved registry — this SDK
            does not maintain a duplicate list of every valid value.
        result: The outcome — one of `KNOWN_RESULTS` today (`"PASS"`,
            `"FAIL"`, `"WARNING"`, `"INFORMATIONAL"`); not enforced
            client-side, Gait validates it.
        source_reference: Caller-supplied idempotency key. Required.
            Resubmitting the same (application, signal_type,
            source_reference) is a safe no-op that returns the original
            result, never a duplicate.
        payload: Optional, bounded, JSON-safe caller context (e.g. scanner
            name/version). Data only — it can never affect which
            organization, environment, application, or control this signal
            resolves to. There is no way to pass an authority-shaped
            field (`organization`, `scope`, `trust`, `control_key`, ...)
            through this parameter or any other — Gait's own request
            contract rejects unrecognized top-level keys outright, and
            this function has no parameter for any of them regardless.
        credential: The raw ApplicationCredential secret. If omitted,
            falls back to `GAIT_APPLICATION_CREDENTIAL`. Never accept this
            value from a browser/frontend request.

    Returns:
        SecuritySignalResult: the verified, Gait-assigned outcome.

    Raises:
        SecuritySignalRejected: `signal_type`/`result`/`source_reference`/
            `payload` is locally malformed, OR Gait rejected the signal's
            content (unknown/unapproved `signal_type`, invalid `result`,
            invalid `source_reference`, or an oversized/invalid `payload`).
        InvalidApplicationCredentialError: the credential is missing (not
            configured/provided) or Gait rejected it — same semantics as
            `verify_application()`.
        AuthServiceUnavailable: Gait is unreachable, times out, or returns
            a response this SDK cannot parse or trust.
    """
    # Step 1: reject obviously-malformed local input before any network call.
    _validate_local_input(signal_type, result, source_reference, payload)

    raw_credential = credential if credential is not None else GAIT_APPLICATION_CREDENTIAL
    if not raw_credential:
        logger.error("No application credential configured or provided - cannot submit signal.")
        raise InvalidApplicationCredentialError("Application credential is not configured.")

    if not GAIT_AUTH_URL:
        logger.error("Missing GAIT_AUTH_URL - cannot submit security signal.")
        raise AuthServiceUnavailable("Authentication service misconfigured.")

    url = f"{GAIT_AUTH_URL.rstrip('/')}/security/tenant-signals/"
    headers = {APPLICATION_CREDENTIAL_HEADER: raw_credential}
    body = {
        "signal_type": signal_type,
        "result": result,
        "source_reference": source_reference,
        "payload": payload or {},
    }

    # Step 2: call Gait. Log only safe, non-sensitive correlation data —
    # never the credential, never the full payload body.
    logger.info("Submitting tenant security signal (signal_type=%s).", signal_type)
    try:
        async with httpx.AsyncClient(timeout=GAIT_TIMEOUT) as client:
            response = await client.post(url, headers=headers, json=body)
    except httpx.RequestError:
        logger.error("Gait tenant-signal API unreachable.")
        raise AuthServiceUnavailable("Authentication service unreachable.")

    # Step 3: interpret the response.
    if response.status_code == 201:
        try:
            raw = response.json()
        except Exception:
            logger.error("Malformed JSON from Gait during signal submission.")
            raise AuthServiceUnavailable("Malformed response from authentication service.")
        result_obj = _build_result(raw)
        logger.info(
            "Tenant security signal accepted (signal_type=%s, source_reference=%s).",
            signal_type, source_reference,
        )
        return result_obj

    if response.status_code == 401:
        logger.warning("Application credential rejected by Gait during signal submission.")
        raise InvalidApplicationCredentialError("Invalid application credential.")

    if response.status_code == 400:
        logger.warning("Tenant security signal rejected by Gait (signal_type=%s).", signal_type)
        raise SecuritySignalRejected("Invalid tenant security signal.")

    logger.error("Unexpected status %s from Gait during signal submission.", response.status_code)
    raise AuthServiceUnavailable(f"Unexpected response: {response.status_code}")
