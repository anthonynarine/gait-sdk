# Filename: auth_integration/client.py
"""
auth_integration.client — Unified Async JWT Validation Client
=============================================================

Purpose:
--------
Framework-agnostic async client for validating JWTs against the centralized
Gait Auth API (/whoami/).

Why this file must stay framework-agnostic:
-------------------------------------------
- Django-only services (like lumen_reports) must not require FastAPI installed.
- FastAPI-specific dependency logic belongs in: auth_integration/fastapi/dependencies.py

Public API:
-----------
- validate_token(token) -> dict
- get_claims(authorization_header) -> dict (framework-agnostic helper)

Security:
---------
- Never logs raw tokens or PHI.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

import httpx

from auth_integration.exceptions import AuthServiceUnavailable, InvalidTokenError
from auth_integration.settings import GAIT_AUTH_URL, GAIT_TIMEOUT


# -----------------------------------------------------------------------------
# ⚙️ Logger (HIPAA-safe)
# -----------------------------------------------------------------------------
logger = logging.getLogger("auth_integration.client")
logger.setLevel(logging.INFO)


# -----------------------------------------------------------------------------
# 🔧 Helpers
# -----------------------------------------------------------------------------
def _extract_bearer_token(authorization: Optional[str]) -> Optional[str]:
    """
    Extract a Bearer token from an Authorization header string.

    Args:
        authorization (Optional[str]): e.g. "Bearer <token>"

    Returns:
        Optional[str]: token if present/valid format; otherwise None.
    """
    # Step 1: Guard
    if not authorization:
        return None

    # Step 2: Parse "Bearer <token>"
    parts = authorization.split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()

    return None


# -----------------------------------------------------------------------------
# 🔐 Public API
# -----------------------------------------------------------------------------
async def validate_token(token: str) -> Dict[str, Any]:
    """
    Validate a JWT token via Gait Auth API (/whoami/).

    Args:
        token (str): Raw JWT from Authorization: Bearer <token>.

    Returns:
        Dict[str, Any]: Claims dict from Gait.

    Raises:
        InvalidTokenError: If token is invalid/expired (401).
        AuthServiceUnavailable: If Gait is unreachable/misconfigured/returns bad data.
    """
    # Step 1: Validate configuration
    if not GAIT_AUTH_URL:
        logger.error("Missing GAIT_AUTH_URL - cannot validate token.")
        raise AuthServiceUnavailable("Authentication service misconfigured.")

    url = f"{GAIT_AUTH_URL.rstrip('/')}/whoami/"
    headers = {"Authorization": f"Bearer {token}"}

    # Step 2: Call Gait
    try:
        async with httpx.AsyncClient(timeout=GAIT_TIMEOUT) as client:
            # NOTE: Keep this signature: tests monkeypatch AsyncClient.get(self, url, headers)
            response = await client.get(url, headers=headers)
    except httpx.RequestError:
        logger.error("Auth API unreachable during token validation.")
        raise AuthServiceUnavailable("Authentication service unreachable.")

    # Step 3: Interpret response
    if response.status_code == 200:
        try:
            claims = response.json()
        except Exception:
            logger.error("Malformed JSON from Auth API during token validation.")
            raise AuthServiceUnavailable("Malformed response from authentication service.")

        return claims

    if response.status_code == 401:
        logger.warning("Token validation failed with 401.")
        raise InvalidTokenError("Invalid or expired token.")

    logger.error("Unexpected status %s from Auth API.", response.status_code)
    raise AuthServiceUnavailable(f"Unexpected response: {response.status_code}")


async def get_claims(authorization: Optional[str]) -> Dict[str, Any]:
    """
    Framework-agnostic helper that extracts a Bearer token from an Authorization
    header string and validates it via Gait.

    This is NOT a FastAPI dependency (no Header/Depends/HTTPException).
    FastAPI apps should use: auth_integration.fastapi.dependencies.verify_token

    Args:
        authorization (Optional[str]): Authorization header value.

    Returns:
        Dict[str, Any]: Validated claims.

    Raises:
        InvalidTokenError: Missing/invalid auth header OR invalid token.
        AuthServiceUnavailable: Auth API unreachable or error response.
    """
    # Step 1: Extract token
    token = _extract_bearer_token(authorization)
    if not token:
        raise InvalidTokenError("Authorization header missing or invalid.")

    # Step 2: Validate
    return await validate_token(token)
