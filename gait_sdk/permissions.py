"""
gait_sdk.permissions
-----------------------------
Cross-framework permission classes and decorators for Django (DRF) and FastAPI.

Provides:
    - HasRole: permission enforcing a single required role.
    - HasAnyRole: permission allowing any of several roles.
    - require_role: route decorator enforcing a single required role against
      the verified claims passed to the route as its `claims` keyword argument.

Which *shape* HasRole/HasAnyRole take is decided by whether Django REST
Framework is importable: with DRF they are `BasePermission` subclasses
(`has_permission(request, view)`); without it they are plain classes
(`has_permission(claims)`).

DRF `permission_classes` takes CLASSES, which DRF instantiates with no
arguments; an instance there fails the request (GAIT-SEC-071). Subclass with
the role fixed and list the subclass:

    class PhysicianRole(HasRole):
        def __init__(self):
            super().__init__("physician")

    permission_classes = [PhysicianRole]

HasRole/HasAnyRole and every subclass of them are for DRF `permission_classes`
only. Never use them, or any subclass, with FastAPI's `Depends()`: FastAPI
would only construct them, never check the role (GAIT-SEC-074, GAIT-SEC-075).
Their signature makes FastAPI refuse such a route at registration. FastAPI
apps use an app-owned dependency, or `require_role` in the documented order.

`require_role` must sit BELOW a FastAPI route decorator (`@app.get(...)` on
top): the route decorator registers whatever function it is handed, so a
`require_role` placed above it wraps a function FastAPI never calls
(GAIT-SEC-070). It also trusts the route's `claims` keyword argument, which
must come from `Depends(verify_token)` (GAIT-SEC-073).

`require_role` does NOT depend on DRF at all (GAIT-SEC-029). It always
enforces, in every environment. It used to be a pass-through no-op whenever
DRF was importable, which left FastAPI/plain routes in an environment that
also had DRF installed completely unprotected. If it cannot enforce (FastAPI
is not installed, or it is applied to something that is not a function) it
raises at decoration time; it never silently returns the function unchanged.

Fail-closed rules shared by every helper here (GAIT-SEC-056):
    - A user whose role is missing, not a string, or empty/blank is denied.
    - `required_role` must be a non-empty string (validated at construction).
    - `allowed_roles` must be a non-empty collection of non-empty strings; a
      bare string is rejected (it would turn the check into a substring test).
"""

import functools
import inspect
from collections.abc import Iterable

try:
    from fastapi import HTTPException
    _FASTAPI_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without fastapi installed
    HTTPException = None  # type: ignore[assignment]
    _FASTAPI_AVAILABLE = False


# ------------------------------------------------------------
# Shared validation / fail-closed role helpers
# ------------------------------------------------------------
def _is_present_role(value) -> bool:
    """True only for a non-empty, non-blank string role."""
    return isinstance(value, str) and value.strip() != ""


def _validate_required_role(required_role) -> str:
    if not isinstance(required_role, str):
        raise TypeError(
            f"required_role must be a non-empty string, got {type(required_role).__name__}."
        )
    if not _is_present_role(required_role):
        raise ValueError("required_role must be a non-empty string.")
    return required_role


def _validate_allowed_roles(allowed_roles) -> frozenset:
    # A bare str/bytes is itself iterable and `in` on it is a substring test
    # ("" and "adm" are both "in" "admin"), so it is rejected outright.
    if isinstance(allowed_roles, (str, bytes, bytearray)) or not isinstance(
        allowed_roles, Iterable
    ):
        raise TypeError(
            "allowed_roles must be a collection (e.g. a list) of role strings, "
            f"not {type(allowed_roles).__name__}."
        )
    roles = list(allowed_roles)
    if not roles:
        raise ValueError("allowed_roles must contain at least one role.")
    for role in roles:
        if not isinstance(role, str):
            raise TypeError(
                f"allowed_roles entries must be strings, got {type(role).__name__}."
            )
        if not _is_present_role(role):
            raise ValueError("allowed_roles must not contain an empty role.")
    return frozenset(roles)


def _claims_role(claims):
    """The user's role from a claims dict, or None if absent/empty/invalid."""
    if not isinstance(claims, dict):
        return None
    role = claims.get("role")
    return role if _is_present_role(role) else None


def _claims_have_role(claims, required_role: str) -> bool:
    role = _claims_role(claims)
    return role is not None and role == required_role


def _claims_have_any_role(claims, allowed_roles: frozenset) -> bool:
    role = _claims_role(claims)
    return role is not None and role in allowed_roles


# ------------------------------------------------------------
# require_role: framework-independent, always enforces
# ------------------------------------------------------------
def require_role(role: str):
    """
    Route decorator enforcing a single required role.

    Contract: the wrapped route function must receive its verified Gait
    claims via a `claims` keyword argument — the same convention as
    `gait_sdk.fastapi.dependencies.verify_token` and the package README's
    FastAPI quickstart:

        @require_role("admin")
        async def admin_only(claims=Depends(verify_token)):
            ...

    Both `async def` and plain `def` routes are supported.

    Fails closed (raises HTTPException(403), never calling the wrapped
    function) if `claims` is missing, is not a dict, has a missing/empty
    `role`, or its `role` does not match. This holds whether or not Django
    REST Framework is installed (GAIT-SEC-029). For DRF views use
    a `HasRole` subclass in `permission_classes` instead (see the module docstring).

    Raises at decoration time (never silently passes through):
        - TypeError / ValueError if `role` is not a non-empty string;
        - RuntimeError if FastAPI is not installed (nothing to raise a 403 with);
        - TypeError if applied to something that is not a function.
    """
    required_role = _validate_required_role(role)

    def decorator(func):
        if not _FASTAPI_AVAILABLE:
            raise RuntimeError(
                "gait_sdk.permissions.require_role requires FastAPI to "
                "be installed to enforce role checks. Install FastAPI, or use "
                "gait_sdk.permissions.HasRole/HasAnyRole directly "
                "against verified claims."
            )
        if not (inspect.isfunction(func) or inspect.ismethod(func)):
            raise TypeError(
                "require_role can only decorate a route function, "
                f"got {type(func).__name__}."
            )

        def _check(kwargs) -> None:
            if not _claims_have_role(kwargs.get("claims"), required_role):
                raise HTTPException(status_code=403, detail="Insufficient role.")

        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                _check(kwargs)
                return await func(*args, **kwargs)
            return async_wrapper

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            _check(kwargs)
            return func(*args, **kwargs)
        return sync_wrapper

    return decorator


try:
    # ------------------------------------------------------------
    # Django / DRF shape of HasRole / HasAnyRole
    # ------------------------------------------------------------
    from rest_framework.permissions import BasePermission

    class HasRole(BasePermission):
        """
        DRF permission granting access only to users with a specific role.

        For DRF `permission_classes` only; never pass it or a subclass to
        FastAPI's `Depends()` (GAIT-SEC-074, GAIT-SEC-075).

        Example (list a CLASS; DRF instantiates it with no arguments --
        an instance in permission_classes fails, GAIT-SEC-071):
            class TechnologistRole(HasRole):
                def __init__(self):
                    super().__init__("technologist")

            class TechnologistView(APIView):
                permission_classes = [TechnologistRole]

        Denies when `request.user_claims` is missing/not a dict or its role
        is missing, empty, or different.
        """

        def __init__(self, required_role: str):
            self.required_role = _validate_required_role(required_role)

        def has_permission(self, request, view) -> bool:
            return _claims_have_role(getattr(request, "user_claims", None), self.required_role)


    class HasAnyRole(BasePermission):
        """
        DRF permission granting access if the user has any one of the allowed roles.

        For DRF `permission_classes` only; never pass it or a subclass to
        FastAPI's `Depends()` (GAIT-SEC-074, GAIT-SEC-075).

        Example (list a CLASS, as for HasRole):
            class AdminOrPhysician(HasAnyRole):
                def __init__(self):
                    super().__init__(["admin", "physician"])

            class SharedView(APIView):
                permission_classes = [AdminOrPhysician]

        `allowed_roles` must be a non-empty collection of non-empty strings.
        """

        def __init__(self, allowed_roles: "list[str]"):
            self.allowed_roles = _validate_allowed_roles(allowed_roles)

        def has_permission(self, request, view) -> bool:
            return _claims_have_any_role(
                getattr(request, "user_claims", None), self.allowed_roles
            )


except ImportError:
    # ------------------------------------------------------------
    # FastAPI / Non-DRF shape of HasRole / HasAnyRole
    # ------------------------------------------------------------
    class HasRole:
        """
        Non-DRF role check for FastAPI-style/framework-agnostic code.

        Not wired into any FastAPI dependency-injection mechanism — call
        `has_permission` directly against verified claims, e.g.:

            checker = HasRole("admin")
            if not checker.has_permission(claims):
                raise HTTPException(status_code=403)

        Fails closed: returns False for missing/non-dict claims and for a
        missing/empty role.
        """

        def __init__(self, required_role: str):
            self.required_role = _validate_required_role(required_role)

        def has_permission(self, claims: "dict | None") -> bool:
            return _claims_have_role(claims, self.required_role)

    class HasAnyRole:
        """
        Non-DRF check for "role is one of several allowed roles".

        Same caveat as HasRole: call `has_permission` directly. Fails closed
        on missing/non-dict claims and on a missing/empty role.
        """

        def __init__(self, allowed_roles: "list[str]"):
            self.allowed_roles = _validate_allowed_roles(allowed_roles)

        def has_permission(self, claims: "dict | None") -> bool:
            return _claims_have_any_role(claims, self.allowed_roles)


# ------------------------------------------------------------
# Deprecation (0.4.0): scheduled for removal
# ------------------------------------------------------------
# gait_sdk verifies and normalizes identity; the consuming
# application owns authorization. These helpers authorize on Gait's legacy
# `role` claim, which Gait's RS256 contract no longer carries -- under
# GAIT_TOKEN_VERIFIER=jwks, `role` is always "" and every check here
# denies. Behavior is otherwise unchanged (still fail-closed); they now
# warn on use and will be removed once no consumer depends on them.
import functools as _functools
import warnings as _warnings

_ROLE_HELPER_DEPRECATION = (
    "gait_sdk.permissions.{name} is deprecated and will be removed. "
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


# ------------------------------------------------------------
# Never a FastAPI dependency (GAIT-SEC-074, GAIT-SEC-075)
# ------------------------------------------------------------
# FastAPI's Depends() reads a dependency's signature, constructs it, and uses
# whatever it returns; it never calls has_permission. Handed HasRole,
# HasAnyRole or any subclass of them (e.g. the documented no-argument DRF
# subclass), it would build an instance and let every request through.
# Python never consults __signature__ when calling a class, and DRF only calls
# `cls()`, so DRF permission_classes are unaffected. FastAPI does consult it,
# and refuses to register a route whose dependency needs a parameter of a type
# it cannot read from a request. Subclasses inherit this.
class _NotAFastAPIDependency:
    """HasRole/HasAnyRole are not FastAPI dependencies. Use an app-owned
    dependency or require_role (see gait_sdk/docs/permissions.md)."""


_NOT_A_DEPENDENCY_SIGNATURE = inspect.Signature([
    inspect.Parameter(
        "role_helpers_are_not_fastapi_dependencies",
        inspect.Parameter.KEYWORD_ONLY,
        annotation=_NotAFastAPIDependency,
    )
])

HasRole.__signature__ = _NOT_A_DEPENDENCY_SIGNATURE
HasAnyRole.__signature__ = _NOT_A_DEPENDENCY_SIGNATURE

_require_role_impl = require_role


@_functools.wraps(_require_role_impl)
def require_role(role: str):
    _warn_role_helper("require_role")
    return _require_role_impl(role)
