"""
auth_integration.fastapi.dependencies — FastAPI Authentication Dependency
=========================================================================

Purpose:
--------
Provides a reusable `verify_token` dependency for FastAPI applications that
authenticate requests against the centralized **Gait Auth API** via JWTs.

This module is the FastAPI equivalent of Django’s `ExternalJWTAuthentication`.
It verifies a Bearer token, returns the user claims, and raises an
`HTTPException(401)` if invalid.

Scope (SDK1, intentional): Bearer-token mode only. Django's adapter also
supports cookie-mode (forwarding whitelisted HttpOnly cookies to /whoami/)
because that's how Lumen's production cookie-based sessions work; no current
FastAPI consumer of this package needs that, so cookie-mode parity is out of
scope here rather than added speculatively. If a future FastAPI consumer
needs cookie-mode, add it as an additive extension, the same way Django's
adapter grew it on top of Bearer-mode.

Teaching Notes:
---------------
- Uses the shared async validator from `auth_integration.client`.
- Built for `Depends()` injection — lightweight and async-safe.
- Never logs or exposes PHI or token content.
"""

import logging
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_503_SERVICE_UNAVAILABLE

from auth_integration.client import validate_token
from auth_integration.exceptions import AuthConfigurationError, InvalidTokenError, AuthServiceUnavailable
from auth_integration.session import acheck_session_live
from auth_integration.verification import VERIFIER_INTROSPECTION, get_token_verifier, load_verifier_config

# Advertised on every 401 response, mirroring the Django adapter's
# authenticate_header() contract (see django/authentication.py). FastAPI has
# no DRF-style automatic 401->403 downgrade, so this isn't fixing a status-
# code bug here the way it did for DRF — it's kept so a client written
# against the Bearer/WWW-Authenticate challenge convention gets the same
# header from either framework's adapter.
_WWW_AUTHENTICATE_BEARER = {"WWW-Authenticate": "Bearer"}


# -----------------------------------------------------------------------------
# ⚙️ Logger (HIPAA-safe)
# -----------------------------------------------------------------------------
logger = logging.getLogger("auth_integration.fastapi.dependencies")
logger.setLevel(logging.INFO)


# -----------------------------------------------------------------------------
# 🧩 FastAPI Security Scheme
# -----------------------------------------------------------------------------
bearer_scheme = HTTPBearer(auto_error=False)


# -----------------------------------------------------------------------------
# 🔐 Core Dependency — verify_token
# -----------------------------------------------------------------------------
async def verify_token(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> dict:
    """
    FastAPI dependency that validates a Bearer JWT via Gait Auth API.

    Args:
        request (Request): The current request. Used only to attach the
            verified claims to `request.state.user` for `get_current_user()`
            — never read from for credentials (those come from `credentials`,
            via FastAPI's own `HTTPBearer` extraction).
        credentials (HTTPAuthorizationCredentials): Automatically extracted
            by FastAPI's `HTTPBearer` from the request header.

    Returns:
        dict: User claims (e.g. {"id": "user-123", "email": "...", "role": "physician"}).
            The same dict is attached to `request.state.user`, so either the
            return value or `get_current_user(request)` gives the identical,
            already-verified claims — there is exactly one verified-identity
            source of truth per request, not two.

    Raises:
        HTTPException(401): If the token is invalid or missing (with a
            `WWW-Authenticate: Bearer` header — see module docstring).
        HTTPException(503): If Gait Auth API is unreachable.

    Teaching Notes:
        - Designed for async use in FastAPI routes.
        - Keeps logs HIPAA-safe: no PHI or raw tokens printed.
        - Forwards all validation work to the shared async validator.
    """
    if not credentials or not credentials.credentials:
        logger.warning("Missing Authorization header or Bearer token.")
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Authorization header missing or malformed.",
            headers=_WWW_AUTHENTICATE_BEARER,
        )

    token = credentials.credentials

    # Explicitly configured verifier (GAIT_TOKEN_VERIFIER); no fallback between them.
    try:
        verifier = get_token_verifier()
    except AuthConfigurationError as e:
        logger.error(f"auth_integration misconfigured: {e}")
        raise HTTPException(status_code=HTTP_503_SERVICE_UNAVAILABLE, detail="Authentication service unavailable.")
    if verifier.name != VERIFIER_INTROSPECTION:
        return await _verify_local(request, verifier, token)

    try:
        logger.info("Validating Bearer token via Gait Auth API.")
        user_claims = await validate_token(token)
        logger.info("Token validated successfully (claims attached).")
        # Step: make the verified claims available via get_current_user()
        # too, so request.state.user is never stale/unset for a request
        # that successfully passed through this dependency.
        request.state.user = user_claims
        return user_claims

    except InvalidTokenError as e:
        logger.warning(f"Invalid or expired token: {e}")
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token.",
            headers=_WWW_AUTHENTICATE_BEARER,
        )
    except AuthServiceUnavailable as e:
        logger.error(f"Auth service unavailable: {e}")
        raise HTTPException(
            status_code=HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service unavailable.",
        )
    except Exception as e:
        logger.error(f"Unexpected error during token validation: {e.__class__.__name__}")
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Authentication error.",
            headers=_WWW_AUTHENTICATE_BEARER,
        )


async def _verify_local(request: Request, verifier, token: str) -> dict:
    """JWKS (local) verification: same core as the Django adapter, no /whoami/.

    Returns the identity dict (VerifiedIdentity.as_claims()): role,
    first_name and last_name are always "" -- Gait's RS256 contract is
    identity-only. A failure never downgrades to introspection.
    """
    try:
        identity = await verifier.averify(token)
    except InvalidTokenError:
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token.",
            headers=_WWW_AUTHENTICATE_BEARER,
        )
    except AuthServiceUnavailable:
        raise HTTPException(status_code=HTTP_503_SERVICE_UNAVAILABLE, detail="Authentication service unavailable.")
    except Exception as e:
        logger.error(f"Unexpected error during local token verification: {e.__class__.__name__}")
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Authentication error.",
            headers=_WWW_AUTHENTICATE_BEARER,
        )
    claims = identity.as_claims()
    request.state.user = claims
    request.state.verified_identity = identity
    return claims


async def require_live_session(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    claims: dict = Depends(verify_token),
) -> dict:
    """Dependency for sensitive routes: verify the token, then confirm the
    session with Gait LIVE (no cache, no fallback). 401 if revoked/expired,
    503 if Gait cannot confirm. Which routes need this is the application's
    decision."""
    try:
        await acheck_session_live(credentials.credentials, expected_subject=claims.get("id"))
    except InvalidTokenError:
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Session is not active.",
            headers=_WWW_AUTHENTICATE_BEARER,
        )
    except AuthServiceUnavailable:
        raise HTTPException(status_code=HTTP_503_SERVICE_UNAVAILABLE, detail="Unable to confirm session.")
    return claims


def validate_configuration() -> None:
    """Call at FastAPI startup: raises AuthConfigurationError on a bad verifier config."""
    load_verifier_config()


# -----------------------------------------------------------------------------
# 🧱 Optional: request-scoped helper
# -----------------------------------------------------------------------------
async def get_current_user(request: Request) -> dict:
    """
    Returns the user claims previously validated and attached to
    request.state.user by `verify_token()`.

    This only returns non-empty claims for a request that has already gone
    through `verify_token` as a dependency (directly or via another
    dependency that itself depends on it) earlier in the same request —
    it does not perform validation itself. Returns `{}` if `verify_token`
    has not run for this request (e.g. an anonymous-allowed route, or a
    route that doesn't depend on `verify_token` at all).
    """
    return getattr(request.state, "user", {})
