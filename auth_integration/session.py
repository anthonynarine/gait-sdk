# Filename: auth_integration/session.py
"""
auth_integration.session -- Live session check (hybrid revocation)
=================================================================

JWKS verification is local, so a revoked Gait session stays verifiable
until its access token expires. For sensitive operations the consuming
application decides to protect (in Lumen: exam sign/finalize/addendum,
membership and role changes), call `check_session_live()` AFTER local
verification and AFTER the application's own authorization check:

    sensitive action -> local JWT verification -> app authorization
        -> check_session_live() -> Gait /whoami/ LIVE
            active                        -> continue
            revoked / expired             -> deny (InvalidTokenError, 401)
            timeout / unavailable / 5xx   -> deny (AuthServiceUnavailable, 503)

Rules:
- Always a live network call. Never uses the Django bearer cache or the
  JWKS cache, and never falls back to anything if Gait is unavailable.
- It only answers "is this token's session still active at Gait". Which
  actions need it is the consuming application's decision, not this
  package's.
- If `expected_subject` is given, Gait's answer must be for that same user.
"""

from __future__ import annotations

import logging
from typing import Optional

import httpx

from auth_integration.exceptions import AuthServiceUnavailable, InvalidTokenError

logger = logging.getLogger("auth_integration.session")


def _whoami_url() -> str:
    from auth_integration.settings import _get_setting

    base = _get_setting("GAIT_AUTH_URL") or _get_setting("AUTH_API_URL")
    if not base:
        raise AuthServiceUnavailable("Authentication service misconfigured.")
    return f"{base.rstrip('/')}/whoami/"


def _timeout() -> float:
    from auth_integration.settings import _get_setting

    return float(_get_setting("GAIT_TIMEOUT", "5") or 5)


def _interpret(status_code: int, body_loader, expected_subject: Optional[str]) -> None:
    if status_code == 200:
        try:
            body = body_loader()
        except Exception:
            raise AuthServiceUnavailable("Malformed response from authentication service.")
        if not isinstance(body, dict) or body.get("id") in (None, ""):
            raise AuthServiceUnavailable("Malformed response from authentication service.")
        if expected_subject is not None and str(body["id"]) != str(expected_subject):
            logger.warning("Live session check returned a different subject; denying.")
            raise InvalidTokenError("Session is not active.")
        return
    if status_code == 401:
        raise InvalidTokenError("Session is not active.")
    logger.error("Live session check got unexpected status %s; denying.", status_code)
    raise AuthServiceUnavailable("Unable to confirm session.")


def check_session_live(token: str, *, expected_subject: Optional[str] = None) -> None:
    """Confirm with Gait, live, that this access token's session is still active.

    Returns None when active. Raises InvalidTokenError (401) when the
    session is revoked/expired, or AuthServiceUnavailable (503) when Gait
    cannot confirm it (timeout, unreachable, unexpected status). Both are
    denials; there is no fail-open path.
    """
    if not token:
        raise InvalidTokenError("Session is not active.")
    url = _whoami_url()
    try:
        response = httpx.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=_timeout())
    except httpx.HTTPError:
        logger.error("Live session check could not reach Gait; denying.")
        raise AuthServiceUnavailable("Unable to confirm session.")
    _interpret(response.status_code, response.json, expected_subject)


async def acheck_session_live(token: str, *, expected_subject: Optional[str] = None) -> None:
    """Async twin of check_session_live() with identical semantics."""
    if not token:
        raise InvalidTokenError("Session is not active.")
    url = _whoami_url()
    try:
        async with httpx.AsyncClient(timeout=_timeout()) as client:
            response = await client.get(url, headers={"Authorization": f"Bearer {token}"})
    except httpx.HTTPError:
        logger.error("Live session check could not reach Gait; denying.")
        raise AuthServiceUnavailable("Unable to confirm session.")
    _interpret(response.status_code, response.json, expected_subject)
