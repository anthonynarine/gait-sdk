# Filename: gait_sdk/verification.py
"""
gait_sdk.verification -- Token verification core (0.4.0)
=================================================================

Boundary
--------
Gait authenticates. This package verifies and normalizes that identity.
The consuming application (e.g. Lumen) makes every authorization decision.
Nothing in this module grants, checks, or carries a role, organization,
facility, or permission.

Architecture
------------
                TokenVerifier
                /           \\
    IntrospectionVerifier   JwksVerifier
                \\           /
               VerifiedIdentity
    (subject, email, session_id, token_id, issuer)

- JwksVerifier verifies Gait RS256 access tokens locally against Gait's
  published JWKS. It never calls /whoami/, and a JWKS verification failure
  never downgrades to introspection.
- IntrospectionVerifier is the legacy path (Gait /whoami/ per request). It
  stays the default until a consumer deliberately cuts over.
- The verifier is selected explicitly by configuration (GAIT_TOKEN_VERIFIER).
  There is no automatic fallback from one verifier to the other.

Revocation is NOT this module's job: JWKS verification is local, so a
revoked session stays verifiable until the token expires (15 minutes).
Sensitive operations must additionally call
gait_sdk.session.check_session_live(), which asks Gait live.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Mapping, Optional, Protocol

import httpx
import jwt
from jwt.algorithms import RSAAlgorithm

from gait_sdk.exceptions import (
    AuthConfigurationError,
    AuthServiceUnavailable,
    InvalidTokenError,
)

logger = logging.getLogger("gait_sdk.verification")

VERIFIER_INTROSPECTION = "introspection"
VERIFIER_JWKS = "jwks"
SUPPORTED_VERIFIERS = frozenset({VERIFIER_INTROSPECTION, VERIFIER_JWKS})

ACCESS_TOKEN_USE = "access"
ALLOWED_ALGORITHM = "RS256"  # hard-pinned; never read from config or the token
REQUIRED_CLAIMS = ("exp", "iat", "sub", "iss", "aud", "jti", "sid", "token_use")
MIN_RSA_KEY_BITS = 2048

DEFAULT_JWKS_CACHE_SECONDS = 300  # fresh period
DEFAULT_JWKS_STALE_MAX_SECONDS = 3600  # hard cap on stale-key use during a Gait outage
DEFAULT_JWKS_REFRESH_COOLDOWN_SECONDS = 30  # min spacing of unknown-kid forced refreshes
DEFAULT_LEEWAY_SECONDS = 30  # clock-skew tolerance for exp/iat


# -----------------------------------------------------------------------------
# Identity contract
# -----------------------------------------------------------------------------
@dataclass(frozen=True)
class VerifiedIdentity:
    """A verified, normalized user identity. Identity only -- never authorization.

    `subject` is an opaque string. Consumers must not parse it or assume it
    is numeric; key identity on (issuer, subject).

    For JWKS verification every field is set. For legacy introspection,
    /whoami/ does not return session/token/issuer data, so those are None,
    and the raw /whoami/ body is kept in `legacy_whoami` purely so the
    Django adapter can keep populating the legacy ClaimsUser fields
    (first_name/last_name/role) for existing consumers. `legacy_whoami` is
    always None on the JWKS path, and nothing new should read it.
    """

    subject: str
    email: str
    session_id: Optional[str] = None
    token_id: Optional[str] = None
    issuer: Optional[str] = None
    source: str = VERIFIER_JWKS
    legacy_whoami: Optional[Mapping[str, Any]] = field(default=None, repr=False, compare=False)

    def as_claims(self) -> Dict[str, Any]:
        """Framework-neutral identity dict (FastAPI return value, Django request.auth).

        Keeps the legacy key names `id`/`first_name`/`last_name`/`role` so
        existing consumer code that indexes them does not KeyError. On the
        JWKS path, first_name/last_name/role are always "" -- Gait's RS256
        contract carries no profile or role data, by design.
        """
        legacy = self.legacy_whoami or {}
        return {
            "id": self.subject,
            "sub": self.subject,
            "email": self.email,
            "session_id": self.session_id,
            "token_id": self.token_id,
            "issuer": self.issuer,
            "first_name": legacy.get("first_name", "") if legacy else "",
            "last_name": legacy.get("last_name", "") if legacy else "",
            "role": legacy.get("role", "") if legacy else "",
            "verified_by": self.source,
        }


class TokenVerifier(Protocol):
    """Verifies a bearer access token and returns a VerifiedIdentity.

    Raises InvalidTokenError (401) for a token that is not valid, and
    AuthServiceUnavailable (503) when verification cannot be performed.
    """

    name: str

    async def averify(self, token: str) -> VerifiedIdentity: ...


# -----------------------------------------------------------------------------
# Introspection (legacy, default)
# -----------------------------------------------------------------------------
class IntrospectionVerifier:
    """Legacy verifier: asks Gait /whoami/ on every call (via client.validate_token)."""

    name = VERIFIER_INTROSPECTION

    def __init__(self, validate: Optional[Callable] = None):
        # Resolved lazily so tests that monkeypatch client.validate_token apply.
        self._validate = validate

    async def averify(self, token: str) -> VerifiedIdentity:
        if self._validate is not None:
            raw = await self._validate(token)
        else:
            from gait_sdk import client

            raw = await client.validate_token(token)
        return identity_from_whoami(raw)


def identity_from_whoami(raw: object) -> VerifiedIdentity:
    """Normalize a /whoami/ body into a VerifiedIdentity (legacy path)."""
    if not isinstance(raw, dict):
        raise AuthServiceUnavailable("Malformed response from authentication service.")
    subject = raw.get("id")
    email = raw.get("email")
    if subject is None or subject == "" or not isinstance(email, str):
        raise InvalidTokenError("Invalid authentication response.")
    return VerifiedIdentity(
        subject=str(subject),
        email=email,
        source=VERIFIER_INTROSPECTION,
        legacy_whoami=dict(raw),
    )


# -----------------------------------------------------------------------------
# JWKS (local RS256 verification)
# -----------------------------------------------------------------------------
class _JwksFetchFailed(Exception):
    """Network error, non-200, or a malformed/unsafe JWKS document."""


def parse_jwks(document: object) -> Dict[str, Any]:
    """Parse a JWKS document into {kid: RSA public key}.

    Fails safe: the whole document is rejected (raises _JwksFetchFailed) if
    it is not a JSON object with a `keys` list, or if any kid appears twice
    (ambiguous -- we cannot know which key the issuer meant). Individual
    keys that are not RSA signing keys are skipped. An RSA key that is
    malformed or under 2048 bits is also skipped, so it can never verify.
    """
    if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
        raise _JwksFetchFailed("JWKS document must be an object with a 'keys' list.")

    seen: set[str] = set()
    keys: Dict[str, Any] = {}
    for entry in document["keys"]:
        if not isinstance(entry, dict):
            continue
        kid = entry.get("kid")
        if isinstance(kid, str) and kid:
            if kid in seen:
                raise _JwksFetchFailed(f"Duplicate kid in JWKS: {kid!r}")
            seen.add(kid)
        if entry.get("kty") != "RSA" or not isinstance(kid, str) or not kid:
            continue
        if entry.get("use", "sig") != "sig" or entry.get("alg", ALLOWED_ALGORITHM) != ALLOWED_ALGORITHM:
            continue
        try:
            public_key = RSAAlgorithm.from_jwk(json.dumps(entry))
        except Exception:
            logger.warning("Skipping malformed JWKS key (kid=%s).", kid)
            continue
        if not hasattr(public_key, "public_numbers") or public_key.key_size < MIN_RSA_KEY_BITS:
            logger.warning("Skipping JWKS key that is not a strong RSA public key (kid=%s).", kid)
            continue
        keys[kid] = public_key
    return keys


class JwksVerifier:
    """Local RS256 verification of Gait access tokens against the published JWKS.

    Cache rules (all enforced here, thread-safe):
    - Fresh keys (fetched < cache_seconds ago) verify locally with no network.
    - Unknown kid -> at most one single-flight forced refresh, and at most
      one per cooldown window across all requests. During the cooldown an
      unknown kid fails immediately. This stops a stream of random kids from
      turning every request into a JWKS fetch against Gait.
    - A successful fetch REPLACES the key set: a kid missing from it is
      invalid immediately (emergency key removal takes effect at once).
    - A failed fetch (network error, non-200, malformed/duplicate-kid
      document) keeps the previous keys. A known kid may keep verifying
      while those keys are at most stale_max_seconds old; beyond that, or
      for an unknown kid, verification fails closed (503). After a failed
      fetch, further fetches back off for the cooldown window so a Gait
      outage does not make every request wait on the network.
    - Never falls back to /whoami/.
    """

    name = VERIFIER_JWKS

    def __init__(
        self,
        *,
        jwks_url: str,
        issuer: str,
        audience: str,
        timeout: float = 5.0,
        cache_seconds: float = DEFAULT_JWKS_CACHE_SECONDS,
        stale_max_seconds: float = DEFAULT_JWKS_STALE_MAX_SECONDS,
        refresh_cooldown_seconds: float = DEFAULT_JWKS_REFRESH_COOLDOWN_SECONDS,
        leeway_seconds: float = DEFAULT_LEEWAY_SECONDS,
        fetch: Optional[Callable[[str, float], object]] = None,
        clock: Callable[[], float] = time.monotonic,
    ):
        if not (jwks_url and issuer and audience):
            raise AuthConfigurationError("JwksVerifier requires jwks_url, issuer, and audience.")
        self.jwks_url = jwks_url
        self.issuer = issuer
        self.audience = audience
        self.timeout = timeout
        self.cache_seconds = cache_seconds
        self.stale_max_seconds = stale_max_seconds
        self.refresh_cooldown_seconds = refresh_cooldown_seconds
        self.leeway_seconds = leeway_seconds
        self._fetch_document = fetch or _http_fetch_json
        self._clock = clock

        self._lock = threading.Lock()
        self._keys: Dict[str, Any] = {}
        self._fetched_at: Optional[float] = None  # last SUCCESSFUL fetch
        self._last_forced_refresh_at: Optional[float] = None
        self._last_failed_at: Optional[float] = None  # backoff after a failed fetch
        self.fetch_count = 0  # observable for tests/metrics

    # -- key management -------------------------------------------------------
    def _refresh_locked(self) -> bool:
        """Fetch and replace the key set. Caller holds the lock. True on success."""
        self.fetch_count += 1
        try:
            document = self._fetch_document(self.jwks_url, self.timeout)
            keys = parse_jwks(document)
        except _JwksFetchFailed as exc:
            logger.error("JWKS refresh rejected: %s", exc)
            self._last_failed_at = self._clock()
            return False
        except Exception as exc:  # network, JSON, anything else
            logger.error("JWKS refresh failed: %s", exc.__class__.__name__)
            self._last_failed_at = self._clock()
            return False
        self._keys = keys
        self._fetched_at = self._clock()
        self._last_failed_at = None
        return True

    def _age(self) -> Optional[float]:
        return None if self._fetched_at is None else self._clock() - self._fetched_at

    def _get_key(self, kid: str):
        with self._lock:
            age = self._age()
            fresh = age is not None and age < self.cache_seconds

            if fresh:
                key = self._keys.get(kid)
                if key is not None:
                    return key
                # Unknown kid with a fresh set: one rate-limited forced refresh.
                now = self._clock()
                if (
                    self._last_forced_refresh_at is not None
                    and now - self._last_forced_refresh_at < self.refresh_cooldown_seconds
                ):
                    raise InvalidTokenError("Unknown signing key.")
                self._last_forced_refresh_at = now
                if self._refresh_locked():
                    key = self._keys.get(kid)
                    if key is None:
                        raise InvalidTokenError("Unknown signing key.")
                    return key
                # Gait unreachable and kid unknown: fail closed.
                raise AuthServiceUnavailable("Unable to refresh signing keys.")

            # Expired (or never fetched): normal refresh -- unless a fetch just
            # failed, in which case back off for the cooldown instead of making
            # every request during a Gait outage wait on the network.
            now = self._clock()
            backing_off = (
                self._last_failed_at is not None
                and now - self._last_failed_at < self.refresh_cooldown_seconds
            )
            if not backing_off and self._refresh_locked():
                key = self._keys.get(kid)
                if key is None:
                    raise InvalidTokenError("Unknown signing key.")
                return key

            # Refresh failed: bounded stale use of a KNOWN key only.
            age = self._age()
            key = self._keys.get(kid)
            if key is not None and age is not None and age <= self.stale_max_seconds:
                logger.warning("Verifying with stale JWKS (age %.0fs) during refresh failure.", age)
                return key
            raise AuthServiceUnavailable("Signing keys unavailable.")

    # -- verification ---------------------------------------------------------
    def verify(self, token: str) -> VerifiedIdentity:
        """Synchronous verification core (shared by every adapter)."""
        if not isinstance(token, str) or not token:
            raise InvalidTokenError("Invalid or expired token.")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            raise InvalidTokenError("Invalid or expired token.")

        # Hard pin: the token's own alg claim is only ever compared, never trusted.
        if header.get("alg") != ALLOWED_ALGORITHM:
            raise InvalidTokenError("Invalid or expired token.")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise InvalidTokenError("Invalid or expired token.")

        key = self._get_key(kid)

        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=[ALLOWED_ALGORITHM],
                issuer=self.issuer,
                audience=self.audience,
                leeway=self.leeway_seconds,
                options={"require": list(REQUIRED_CLAIMS)},
            )
        except jwt.PyJWTError:
            raise InvalidTokenError("Invalid or expired token.")

        return _identity_from_access_claims(claims)

    async def averify(self, token: str) -> VerifiedIdentity:
        # Verification is CPU-bound and a rare JWKS fetch is blocking I/O:
        # run it off the event loop so async consumers never stall.
        return await asyncio.to_thread(self.verify, token)


def _identity_from_access_claims(claims: Mapping[str, Any]) -> VerifiedIdentity:
    if claims.get("token_use") != ACCESS_TOKEN_USE:
        raise InvalidTokenError("Invalid or expired token.")
    for name in ("sub", "sid", "jti", "iss"):
        value = claims.get(name)
        if not isinstance(value, str) or not value:
            raise InvalidTokenError("Invalid or expired token.")
    email = claims.get("email")
    if not isinstance(email, str):
        raise InvalidTokenError("Invalid or expired token.")
    return VerifiedIdentity(
        subject=claims["sub"],
        email=email,
        session_id=claims["sid"],
        token_id=claims["jti"],
        issuer=claims["iss"],
        source=VERIFIER_JWKS,
    )


def _http_fetch_json(url: str, timeout: float) -> object:
    response = httpx.get(url, timeout=timeout, headers={"Accept": "application/json"})
    if response.status_code != 200:
        raise _JwksFetchFailed(f"JWKS endpoint returned {response.status_code}")
    try:
        return response.json()
    except ValueError as exc:
        raise _JwksFetchFailed("JWKS endpoint returned invalid JSON") from exc


# -----------------------------------------------------------------------------
# Configuration + selection
# -----------------------------------------------------------------------------
@dataclass(frozen=True)
class VerifierConfig:
    verifier: str
    jwks_url: str = ""
    issuer: str = ""
    audience: str = ""
    timeout: float = 5.0


def load_verifier_config() -> VerifierConfig:
    """Read and validate verifier settings. Raises AuthConfigurationError."""
    from gait_sdk.settings import _get_setting

    verifier = (_get_setting("GAIT_TOKEN_VERIFIER", VERIFIER_INTROSPECTION) or VERIFIER_INTROSPECTION).strip().lower()
    if verifier not in SUPPORTED_VERIFIERS:
        raise AuthConfigurationError(
            f"GAIT_TOKEN_VERIFIER must be one of {sorted(SUPPORTED_VERIFIERS)}, got {verifier!r}."
        )
    timeout = float(_get_setting("GAIT_TIMEOUT", "5") or 5)
    if verifier == VERIFIER_INTROSPECTION:
        return VerifierConfig(verifier=verifier, timeout=timeout)

    jwks_url = (_get_setting("GAIT_JWKS_URL") or "").strip()
    issuer = (_get_setting("GAIT_ISSUER") or "").strip()
    audience = (_get_setting("GAIT_AUDIENCE") or "").strip()
    missing = [n for n, v in (("GAIT_JWKS_URL", jwks_url), ("GAIT_ISSUER", issuer), ("GAIT_AUDIENCE", audience)) if not v]
    if missing:
        raise AuthConfigurationError(f"GAIT_TOKEN_VERIFIER=jwks requires {', '.join(missing)}.")
    if not jwks_url.startswith("https://") and not jwks_url.startswith("http://localhost") and not jwks_url.startswith("http://127.0.0.1"):
        raise AuthConfigurationError("GAIT_JWKS_URL must use https:// (http only for localhost).")
    return VerifierConfig(verifier=verifier, jwks_url=jwks_url, issuer=issuer, audience=audience, timeout=timeout)


_verifier_lock = threading.Lock()
_verifier: Optional[TokenVerifier] = None


def get_token_verifier() -> TokenVerifier:
    """The process-wide configured verifier (built once, so the JWKS cache is shared)."""
    global _verifier
    if _verifier is None:
        with _verifier_lock:
            if _verifier is None:
                config = load_verifier_config()
                if config.verifier == VERIFIER_JWKS:
                    _verifier = JwksVerifier(
                        jwks_url=config.jwks_url,
                        issuer=config.issuer,
                        audience=config.audience,
                        timeout=config.timeout,
                    )
                else:
                    _verifier = IntrospectionVerifier()
                logger.info("gait_sdk token verifier: %s", _verifier.name)
    return _verifier


def set_token_verifier(verifier: Optional[TokenVerifier]) -> None:
    """Override (or with None, reset) the process-wide verifier. For tests and wiring."""
    global _verifier
    with _verifier_lock:
        _verifier = verifier
