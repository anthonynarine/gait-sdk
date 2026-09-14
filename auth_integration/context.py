# Filename: auth_integration/context.py
"""
auth_integration.context — SecurityContext (identity composition)
====================================================================

SDK3: a small, framework-neutral object that composes the two identity
concepts this package already verifies independently, without merging or
inferring either from the other:

    HUMAN identity      -> ClaimsUser / user claims (auth_integration.django.
                            authentication, auth_integration.fastapi.dependencies)
    APPLICATION identity -> ApplicationPrincipal (auth_integration.application)

`SecurityContext` answers "what verified identities are present for this
execution/request?" — nothing more. It does NOT:

    - create authority (it composes identities already established
      elsewhere — see VERIFY -> COMPOSE -> USE below)
    - perform any verification or Gait network call itself
    - store a raw JWT or a raw ApplicationCredential
    - let a caller select/override an organization or environment
    - implement authorization (no can_access / is_authorized / allowed_roles
      / tenant or facility permissions — those belong to the consuming
      application or a future policy layer)

VERIFY -> COMPOSE -> USE
-------------------------
Identity verification always happens BEFORE a SecurityContext is built:

    user = <already verified ClaimsUser or FastAPI claims dict>
    application = await verify_application()   # verification, separate step

    context = SecurityContext(user=user, application=application)  # pure composition

`SecurityContext.__init__` never calls Gait and never raises a
network-shaped error (`AuthServiceUnavailable`, `InvalidTokenError`,
`InvalidApplicationCredentialError` are all impossible outcomes of
constructing one) — it only ever fails for locally-invalid input (see
`_looks_like_claims_user` below), which is a structural/type problem, not
a service problem.

Framework-neutral core, with one honest limitation
---------------------------------------------------
`ApplicationPrincipal` is framework-neutral already (see
`auth_integration.application`), so `SecurityContext.application` is
validated by a real `isinstance` check.

`ClaimsUser`, however, currently lives in
`auth_integration.django.authentication`, which unconditionally imports
`rest_framework`/`asgiref` at module level for its *other* code (the DRF
adapter itself) — so importing `ClaimsUser` for a runtime `isinstance`
check would force this core module to require Django/DRF just to be
imported, defeating the point of a framework-neutral SecurityContext.
Moving `ClaimsUser` to a neutral module was assessed and deliberately NOT
done in SDK3 (see the SDK3 report) — it would be exactly the kind of
identity-module refactor this milestone is told to avoid unless strictly
necessary, and it risks the existing stable `auth_integration.authentication.
ClaimsUser` / `auth_integration.django.authentication.ClaimsUser` import
paths.

Instead, `SecurityContext.user` accepts anything *structurally shaped*
like a `ClaimsUser` — checked by attribute (a real `ClaimsUser` instance,
from the Django adapter) or by key (a raw claims `dict`, which is exactly
what `auth_integration.fastapi.dependencies.verify_token()` already
returns — the FastAPI adapter never constructs a `ClaimsUser` instance at
all). This is a deliberate, minimal accommodation of an existing asymmetry
between the two adapters, not a new abstraction layer: no `UserPrincipal`,
no `Principal` protocol hierarchy was introduced for this.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Optional, Union

from auth_integration.application import ApplicationPrincipal

if TYPE_CHECKING:  # pragma: no cover - type-checking only, never imported at runtime
    from auth_integration.django.authentication import ClaimsUser

# The same field set auth_integration.django.authentication.BaseUserClaims/
# ClaimsUser already require (see django/authentication.py) — duplicated
# here only as plain strings for a structural check, not as an import.
_REQUIRED_CLAIMS_FIELDS = ("id", "email", "role", "first_name", "last_name")


def _looks_like_claims_user(value: Any) -> bool:
    """Structural check: does `value` carry every ClaimsUser-shaped field?

    Accepts either a real `ClaimsUser` instance (checked by attribute) or
    a raw claims dict (checked by key) — see module docstring for why both
    shapes exist and why this never imports `ClaimsUser` itself.
    """
    if isinstance(value, dict):
        return all(key in value for key in _REQUIRED_CLAIMS_FIELDS)
    return all(hasattr(value, attr) for attr in _REQUIRED_CLAIMS_FIELDS)


@dataclass(frozen=True)
class SecurityContext:
    """Composition of already-verified human and/or application identity.

    Valid states:
        - user only        (human identity, no application identity)
        - application only (application identity, no human identity)
        - both

    `SecurityContext(user=None, application=None)` — neither identity — is
    deliberately REJECTED (raises `ValueError`), not silently allowed. If
    nothing was verified, there is nothing to compose; an "empty" context
    object provides no ergonomic benefit over simply not having one (every
    consumer would need to null-check its contents anyway, exactly as they
    would null-check the absence of a SecurityContext at all). See the
    SDK3 report for the full reasoning.

    Fields carry only already-verified identity — no credential, no raw
    JWT, no tenant/environment override.
    """

    user: Optional[Union["ClaimsUser", dict]] = None
    application: Optional[ApplicationPrincipal] = None

    def __post_init__(self) -> None:
        # Step 1: reject a meaningless, identity-less context.
        if self.user is None and self.application is None:
            raise ValueError(
                "SecurityContext requires at least one verified identity "
                "(user and/or application) — construct one only after "
                "verification, never as a placeholder."
            )

        # Step 2: application identity, when present, must be a real,
        # already-verified ApplicationPrincipal — never a dict, never a
        # raw credential, never caller-fabricated fields.
        if self.application is not None and not isinstance(self.application, ApplicationPrincipal):
            raise TypeError(
                "SecurityContext.application must be an ApplicationPrincipal "
                "(from auth_integration.application.verify_application()) or None."
            )

        # Step 3: human identity, when present, must be ClaimsUser-shaped
        # (see module docstring for why this is structural, not isinstance).
        if self.user is not None and not _looks_like_claims_user(self.user):
            raise TypeError(
                "SecurityContext.user must be a ClaimsUser instance or a "
                "claims dict with id/email/role/first_name/last_name, or None."
            )

    # -------------------------------------------------------------------
    # Identity-presence helpers — presence only, never permission/authority.
    # -------------------------------------------------------------------
    @property
    def has_user(self) -> bool:
        """True if a verified human identity is present. Not an authorization check."""
        return self.user is not None

    @property
    def has_application(self) -> bool:
        """True if a verified application identity is present. Not an authorization check."""
        return self.application is not None
