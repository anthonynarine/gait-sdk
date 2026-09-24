"""
auth_integration.permissions
-----------------------------
Cross-framework permission classes and decorators for Django (DRF) and FastAPI.

Provides:
    - HasRole: DRF permission enforcing a single required role.
    - HasAnyRole: DRF permission allowing multiple roles.
    - require_role: Lightweight decorator for FastAPI route-level role checks.

Teaching Notes:
    This module detects whether Django REST Framework is available.
    If not, it provides FastAPI-safe fallbacks so importing this file
    never breaks in microservices that don’t use DRF.
"""

try:
    # ------------------------------------------------------------
    # Django / DRF Implementation
    # ------------------------------------------------------------
    from rest_framework.permissions import BasePermission

    class HasRole(BasePermission):
        """
        Custom permission class that grants access only to users with a specific role.

        Intended for use in Django REST Framework views that should be limited to one type of user.

        Example:
            class TechnologistView(APIView):
                permission_classes = [HasRole("technologist")]
        """

        def __init__(self, required_role: str):
            """Initialize with a single required role."""
            self.required_role = required_role

        def has_permission(self, request, view) -> bool:
            """Allow access if the user's role matches the required role."""
            user_claims = getattr(request, "user_claims", {})
            return user_claims.get("role") == self.required_role


    class HasAnyRole(BasePermission):
        """
        Grants access if the user has any one of the allowed roles.

        Example:
            class SharedView(APIView):
                permission_classes = [HasAnyRole(["admin", "physician"])]
        """

        def __init__(self, allowed_roles: list[str]):
            """Initialize with a list of acceptable role names."""
            self.allowed_roles = allowed_roles

        def has_permission(self, request, view) -> bool:
            """Allow access if the user's role is in the allowed roles."""
            user_claims = getattr(request, "user_claims", {})
            return user_claims.get("role") in self.allowed_roles


    def require_role(role: str):
        """
        DRF-compatible decorator (no-op by default, DRF handles permissions internally).
        Included for API parity with FastAPI services.
        """
        def decorator(func):
            return func
        return decorator


except ImportError:
    # ------------------------------------------------------------
    # FastAPI / Non-DRF Fallback Implementation
    # ------------------------------------------------------------
    # Security rule (SDK1): none of these may silently grant access just
    # because DRF isn't installed. Every path below fails closed (denies)
    # on missing/invalid claims or a role mismatch. Importing this module
    # never requires FastAPI (matches the file's own "importing never
    # breaks" design goal) — only *using* `require_role` without FastAPI
    # installed raises a clear RuntimeError instead of silently no-op'ing.
    import functools

    try:
        from fastapi import HTTPException
        _FASTAPI_AVAILABLE = True
    except ImportError:  # pragma: no cover - exercised only without fastapi installed
        HTTPException = None  # type: ignore[assignment]
        _FASTAPI_AVAILABLE = False

    def _require_fastapi() -> None:
        if not _FASTAPI_AVAILABLE:
            raise RuntimeError(
                "auth_integration.permissions.require_role requires FastAPI to "
                "be installed to enforce role checks. Install FastAPI, or use "
                "auth_integration.permissions.HasRole/HasAnyRole directly "
                "against verified claims."
            )

    def require_role(role: str):
        """
        FastAPI route decorator enforcing a single required role.

        Contract: the wrapped route function must receive its verified Gait
        claims via a `claims` keyword argument — the same convention as
        `auth_integration.fastapi.dependencies.verify_token` and the
        package README's FastAPI quickstart:

            @require_role("admin")
            async def admin_only(claims=Depends(verify_token)):
                ...

        Fails closed (raises HTTPException(403)) if `claims` is missing, is
        not a dict, or its `role` does not match — it never falls through
        to calling the wrapped function on missing/invalid identity.
        """
        def decorator(func):
            @functools.wraps(func)
            async def wrapper(*args, **kwargs):
                _require_fastapi()
                claims = kwargs.get("claims")
                if not isinstance(claims, dict) or claims.get("role") != role:
                    raise HTTPException(status_code=403, detail="Insufficient role.")
                return await func(*args, **kwargs)
            return wrapper
        return decorator

    class HasRole:
        """
        Non-DRF role check for FastAPI-style/framework-agnostic code.

        Not wired into any FastAPI dependency-injection mechanism — FastAPI
        has no `permission_classes` equivalent, so unlike the DRF version
        this is never invoked automatically. Call `has_permission` directly
        against verified claims, e.g.:

            checker = HasRole("admin")
            if not checker.has_permission(claims):
                raise HTTPException(status_code=403)

        Fails closed: returns False (never True) for missing/non-dict claims.
        """

        def __init__(self, required_role: str):
            self.required_role = required_role

        def has_permission(self, claims: "dict | None") -> bool:
            if not isinstance(claims, dict):
                return False
            return claims.get("role") == self.required_role

    class HasAnyRole:
        """
        Non-DRF check for "role is one of several allowed roles".

        Same caveat as HasRole: not wired into any FastAPI mechanism, call
        `has_permission` directly. Fails closed on missing/non-dict claims.
        """

        def __init__(self, allowed_roles: list[str]):
            self.allowed_roles = allowed_roles

        def has_permission(self, claims: "dict | None") -> bool:
            if not isinstance(claims, dict):
                return False
            return claims.get("role") in self.allowed_roles


# ------------------------------------------------------------
# Deprecation (0.4.0): scheduled for removal
# ------------------------------------------------------------
# auth_integration verifies and normalizes identity; the consuming
# application owns authorization. These helpers authorize on Gait's legacy
# `role` claim, which Gait's RS256 contract no longer carries -- under
# GAIT_TOKEN_VERIFIER=jwks, `role` is always "" and every check here
# denies. Behavior is otherwise unchanged (still fail-closed); they now
# warn on use and will be removed once no consumer depends on them.
import functools as _functools
import warnings as _warnings

_ROLE_HELPER_DEPRECATION = (
    "auth_integration.permissions.{name} is deprecated and will be removed. "
    "Authorization belongs to the consuming application (e.g. Lumen's "
    "OrganizationMember role), not to Gait's legacy role claim."
)


def _warn_role_helper(name: str) -> None:
    _warnings.warn(_ROLE_HELPER_DEPRECATION.format(name=name), DeprecationWarning, stacklevel=3)


def _deprecate_init(cls):
    original_init = cls.__init__

    @_functools.wraps(original_init)
    def __init__(self, *args, **kwargs):
        _warn_role_helper(cls.__name__)
        original_init(self, *args, **kwargs)

    cls.__init__ = __init__
    return cls


_deprecate_init(HasRole)
_deprecate_init(HasAnyRole)

_require_role_impl = require_role


@_functools.wraps(_require_role_impl)
def require_role(role: str):
    _warn_role_helper("require_role")
    return _require_role_impl(role)
