# Filename: auth_integration/django/authentication.py
"""
auth_integration.django.authentication — DRF Adapter
====================================================

Purpose:
--------
Django REST Framework (DRF) authentication backend that validates requests
against the centralized Gait Auth API (/whoami/).

Modes:
------
1) DEV/Bearer Mode:
   - Reads "Authorization: Bearer <token>".
   - Validates via shared async validator `validate_token(token)`.

2) PROD/Cookie Mode:
   - If no Bearer token is present, forwards request.COOKIES to Gait /whoami/.

On success:
-----------
- Attaches `request.user_claims` (dict)
- Returns a lightweight authenticated `ClaimsUser` object for DRF permission checks.

Security & Privacy:
-------------------
- Never logs tokens or cookies.
- Treats malformed claim payloads as auth failures (fail closed).
- Keeps cache keys hashed (sha256(token)) — never stores raw tokens.

Performance:
------------
- Optional short TTL cache for Bearer validations to reduce /whoami/ calls.

Teaching Notes:
---------------
- DRF authentication backends are sync; we bridge async calls using `async_to_sync`.
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass
from typing import Optional, TypedDict, cast

import httpx
from asgiref.sync import async_to_sync
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import APIException, AuthenticationFailed

from auth_integration.client import validate_token  # async validator
from auth_integration.exceptions import AuthServiceUnavailable, InvalidTokenError
from auth_integration.settings import GAIT_AUTH_URL, GAIT_TIMEOUT


# -----------------------------------------------------------------------------
# ⚙️ Logger (HIPAA-safe)
# -----------------------------------------------------------------------------
logger = logging.getLogger("auth_integration.django.authentication")

# -----------------------------------------------------------------------------
# 🍪 Cookie whitelist (must match Gait)
# -----------------------------------------------------------------------------
# ✅ New Code: Only these cookies should trigger cookie-mode validation.
AUTH_COOKIE_KEYS: set[str] = {"access_token", "refresh_token", "temp_token"}

# -----------------------------------------------------------------------------
# 🧩 Types
# -----------------------------------------------------------------------------
class BaseUserClaims(TypedDict):
    id: str
    email: str
    # `role` is an opaque, consuming-application-defined string. This SDK does not
    # define or restrict the business role vocabulary (e.g. Lumen's
    # "admin"/"physician"/"technologist") — it only carries whatever Gait's
    # /whoami/ returns. See docs/settings.md / README "Authorization (RBAC)
    # guidance" for the identity-vs-authorization boundary this reflects.
    role: str
    first_name: str
    last_name: str


class UserClaims(BaseUserClaims, total=False):
    # Optional fields that may exist in /whoami/ responses.
    is_2fa_enabled: bool


# -----------------------------------------------------------------------------
# ✅ Claims-backed "User" for DRF
# -----------------------------------------------------------------------------
@dataclass(frozen=True)
class ClaimsUser:
    """Lightweight authenticated user backed by validated claims."""

    id: str
    email: str
    # Opaque, consuming-application-defined role string — see BaseUserClaims.role.
    role: str
    first_name: str
    last_name: str

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def is_anonymous(self) -> bool:
        return False

    def get_full_name(self) -> str:
        return f"{self.first_name} {self.last_name}".strip()

    def __str__(self) -> str:
        label = self.email or self.id
        return f"{label} ({self.role})"


# -----------------------------------------------------------------------------
# 🧯 DRF Exception for upstream auth outage
# -----------------------------------------------------------------------------
class AuthenticationServiceUnavailable(APIException):
    """Raised when the upstream Auth API is unreachable or misconfigured."""

    status_code = 503
    default_detail = "Authentication service unavailable."
    default_code = "auth_service_unavailable"


# -----------------------------------------------------------------------------
# 🚀 Tiny in-process TTL cache for Bearer validations (speed win)
# -----------------------------------------------------------------------------
# Key: sha256(token), Value: (expires_at_epoch, claims_dict)
_BEARER_CACHE: dict[str, tuple[float, UserClaims]] = {}
_BEARER_CACHE_MAX = 2048
_BEARER_CACHE_TTL_SECONDS = 45


def _hash_token(token: str) -> str:
    """Hash token for cache keying without storing the raw token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _cache_get(token: str) -> Optional[UserClaims]:
    """# Step 1: Return cached claims if present and not expired."""
    now = time.time()
    key = _hash_token(token)
    item = _BEARER_CACHE.get(key)
    if not item:
        return None

    expires_at, claims = item
    if expires_at <= now:
        _BEARER_CACHE.pop(key, None)
        return None

    return claims


def _cache_set(token: str, claims: UserClaims) -> None:
    """# Step 2: Store claims in cache with TTL; evict oldest opportunistically."""
    if _BEARER_CACHE_MAX <= 0 or _BEARER_CACHE_TTL_SECONDS <= 0:
        return

    if len(_BEARER_CACHE) >= _BEARER_CACHE_MAX:
        # Evict one arbitrary item (simple + fast). For LRU, add dependency later.
        _BEARER_CACHE.pop(next(iter(_BEARER_CACHE)), None)

    key = _hash_token(token)
    _BEARER_CACHE[key] = (time.time() + _BEARER_CACHE_TTL_SECONDS, claims)


# -----------------------------------------------------------------------------
# 🔧 Helpers
# -----------------------------------------------------------------------------
def _extract_bearer_token(request) -> Optional[str]:
    """
    Extract a raw JWT from the Authorization header (if present).

    Returns:
        Optional[str]: The token string without the "Bearer " prefix, or None.
    """
    auth_header = request.headers.get("Authorization") or request.META.get(
        "HTTP_AUTHORIZATION"
    )
    if not auth_header:
        return None

    parts = auth_header.split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()

    return None


def _filter_auth_cookies(cookies: dict) -> dict:
    """
    Filter request cookies down to only auth-related keys.

    Args:
        cookies (dict): Raw request.COOKIES.

    Returns:
        dict: Only cookies relevant to authentication.
    """
    # Step 1: Only forward known auth cookies to Gait (lighter + safer).
    return {k: v for k, v in cookies.items() if k in AUTH_COOKIE_KEYS}


def _validate_claims_shape(raw: object) -> UserClaims:
    """# Step 3: Validate the claim payload shape (fail closed).

    Args:
        raw: The parsed JSON object returned by Gait.

    Returns:
        UserClaims: A validated claims dict.

    Raises:
        AuthenticationFailed: If payload is missing required keys.
    """
    if not isinstance(raw, dict):
        raise AuthenticationFailed("Invalid authentication response.")

    # Step 1: Required keys must be present AND be non-empty strings. This is
    # deliberately generic about `role` — this SDK does not define or restrict
    # a consuming application's role vocabulary (see BaseUserClaims.role) — but
    # every one of these fields is documented as a string, so a non-string or
    # empty value is malformed identity data and must fail closed rather than
    # silently pass through as an anonymous or partially-formed user.
    required = ("id", "email", "role", "first_name", "last_name")
    for key in required:
        if key not in raw:
            raise AuthenticationFailed("Invalid authentication response.")
        value = raw[key]
        if not isinstance(value, str) or not value:
            raise AuthenticationFailed("Invalid authentication response.")

    return cast(UserClaims, raw)


async def _validate_with_cookies(cookies: dict) -> UserClaims:
    """
    Validate the session by forwarding HttpOnly cookies to the Gait /whoami/.

    Args:
        cookies (dict): Whitelisted auth cookies only.

    Returns:
        UserClaims: Validated claims.

    Raises:
        InvalidTokenError: If Gait returns 401.
        AuthServiceUnavailable: If Gait is unreachable or misconfigured.
    """
    if not GAIT_AUTH_URL:
        logger.error("Missing GAIT_AUTH_URL — cannot validate cookies.")
        raise AuthServiceUnavailable("Authentication service misconfigured.")

    url = f"{GAIT_AUTH_URL.rstrip('/')}/whoami/"
    logger.info("Validating session via cookies at /whoami/ (no PHI logged).")

    try:
        async with httpx.AsyncClient(timeout=GAIT_TIMEOUT) as client:
            resp = await client.get(url, cookies=cookies)
    except httpx.RequestError:
        logger.error("Auth API unreachable while validating cookies.")
        raise AuthServiceUnavailable("Authentication service unreachable.")

    if resp.status_code == 200:
        try:
            raw = resp.json()
            return _validate_claims_shape(raw)
        except AuthenticationFailed:
            raise
        except Exception:
            logger.error("Malformed JSON from Auth API during cookie validation.")
            raise AuthServiceUnavailable("Malformed response from authentication service.")

    if resp.status_code == 401:
        logger.warning("Cookie-based validation failed with 401.")
        raise InvalidTokenError("Invalid or expired session.")

    logger.error(
        "Unexpected status from Auth API during cookie validation: %s", resp.status_code
    )
    raise AuthServiceUnavailable(f"Unexpected response: {resp.status_code}")


# -----------------------------------------------------------------------------
# 🔐 DRF Authentication Class
# -----------------------------------------------------------------------------
class ExternalJWTAuthentication(BaseAuthentication):
    """
    DRF authentication backend delegating JWT/session validation to Gait Auth API.
    """

    def authenticate(self, request):
        # Step 1: Try Authorization Bearer (DEV fallback)
        token = _extract_bearer_token(request)

        # Step 2: Cookie-mode credentials exist only if auth cookies exist
        raw_cookies = getattr(request, "COOKIES", None) or {}
        auth_cookies = _filter_auth_cookies(raw_cookies)
        has_auth_cookies = bool(auth_cookies)

        # Step 3: No credentials (no Bearer and no auth cookies) -> DRF treats as anonymous
        if not token and not has_auth_cookies:
            return None

        try:
            if token:
                # Step 4: Prefer cache for Bearer validations (fast path)
                cached = _cache_get(token)
                if cached:
                    claims = cached
                else:
                    logger.info(
                        "Bearer token detected — validating via shared async client."
                    )
                    raw_claims = async_to_sync(validate_token)(token)
                    claims = _validate_claims_shape(raw_claims)
                    _cache_set(token, claims)
            else:
                # Step 5: Cookie mode (PROD with HttpOnly cookies)
                logger.info("No Bearer token — attempting cookie-based validation.")
                claims = async_to_sync(_validate_with_cookies)(auth_cookies)

        except InvalidTokenError as e:
            # Step 6: Invalid/expired credentials -> 401
            raise AuthenticationFailed(str(e))
        except AuthServiceUnavailable as e:
            # Step 7: Upstream failure -> 503
            raise AuthenticationServiceUnavailable(str(e))
        except AuthenticationFailed:
            # Step 8: Fail closed on malformed claim payloads
            raise
        except Exception as e:
            logger.error(
                "Unexpected error during authentication: %s", e.__class__.__name__
            )
            raise AuthenticationFailed("Authentication error.")

        # Step 9: Attach claims & return authenticated ClaimsUser
        request.user_claims = claims
        user = ClaimsUser(
            id=claims["id"],
            email=claims["email"],
            role=claims["role"],
            first_name=claims["first_name"],
            last_name=claims["last_name"],
        )

        # Step 10: Put claims in request.auth (more useful than returning the raw token)
        return (user, claims)

    def authenticate_header(self, request):
        """
        Advertise a WWW-Authenticate scheme so DRF returns 401 for auth failures.

        Without this, DRF's default `APIView.handle_exception` rewrites
        NotAuthenticated/AuthenticationFailed from 401 to 403 whenever no
        authenticator provides a challenge header (see DRF's
        `get_authenticate_header`). That silently broke every client's
        refresh-on-401 logic: an expired/invalid Bearer token was returned as
        403, which frontend interceptors correctly ignore (403 is also used
        for legitimate "authenticated but not permitted" cases and must not
        trigger a token-refresh retry). Returning a value here — any
        non-empty string — is what tells DRF this authenticator can present
        a real 401 challenge, so it stops downgrading the status code.
        """
        return "Bearer"
