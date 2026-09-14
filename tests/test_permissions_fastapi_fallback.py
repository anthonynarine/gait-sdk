# Filename: tests/test_permissions_fastapi_fallback.py
"""
Regression tests for auth_integration.permissions' FastAPI/non-DRF fallback
branch (SDK1 Part D).

This repo's test environment has djangorestframework installed, so
`auth_integration.permissions` normally loads its DRF branch. To exercise
the fallback branch that a real DRF-less FastAPI install would load, these
tests force `rest_framework.permissions` to fail importing (the standard
"set sys.modules[name] = None" trick) and reload the module under test.

Security contract under test: none of require_role/HasRole/HasAnyRole may
silently grant access just because DRF is unavailable. Every case here
proves a fail-closed (deny) outcome except the one "correct role" case per
class/function.
"""

import importlib
import sys

import pytest


@pytest.fixture()
def fallback_permissions(monkeypatch):
    """Load auth_integration.permissions with its FastAPI fallback branch active."""
    monkeypatch.setitem(sys.modules, "rest_framework.permissions", None)
    sys.modules.pop("auth_integration.permissions", None)
    module = importlib.import_module("auth_integration.permissions")
    try:
        yield module
    finally:
        # Drop the fallback-loaded module from the cache so any test that
        # runs afterward and imports auth_integration.permissions fresh gets
        # the normal DRF branch again (rest_framework.permissions is restored
        # by monkeypatch's own teardown, which runs after this fixture's).
        sys.modules.pop("auth_integration.permissions", None)


def test_module_loaded_fallback_branch(fallback_permissions):
    # Sanity check that the fixture actually forced the fallback branch,
    # rather than silently re-testing the normal DRF classes: the DRF
    # HasRole.has_permission takes (request, view); the fallback takes a
    # single `claims` argument.
    import inspect

    params = list(inspect.signature(fallback_permissions.HasRole.has_permission).parameters)
    assert params == ["self", "claims"]
    assert fallback_permissions._FASTAPI_AVAILABLE is True


# ---------------------------------------------------------------------------
# HasRole
# ---------------------------------------------------------------------------
def test_has_role_allows_correct_role(fallback_permissions):
    checker = fallback_permissions.HasRole("admin")
    assert checker.has_permission({"role": "admin"}) is True


def test_has_role_denies_incorrect_role(fallback_permissions):
    checker = fallback_permissions.HasRole("admin")
    assert checker.has_permission({"role": "technologist"}) is False


def test_has_role_denies_missing_role_key(fallback_permissions):
    checker = fallback_permissions.HasRole("admin")
    assert checker.has_permission({"id": "1"}) is False


@pytest.mark.parametrize("claims", [None, "not-a-dict", 123, {}])
def test_has_role_denies_missing_or_invalid_identity(fallback_permissions, claims):
    checker = fallback_permissions.HasRole("admin")
    assert checker.has_permission(claims) is False


# ---------------------------------------------------------------------------
# HasAnyRole
# ---------------------------------------------------------------------------
def test_has_any_role_allows_one_of_several(fallback_permissions):
    checker = fallback_permissions.HasAnyRole(["admin", "physician"])
    assert checker.has_permission({"role": "physician"}) is True


def test_has_any_role_denies_role_not_in_list(fallback_permissions):
    checker = fallback_permissions.HasAnyRole(["admin", "physician"])
    assert checker.has_permission({"role": "nurse"}) is False


def test_has_any_role_denies_missing_role_key(fallback_permissions):
    checker = fallback_permissions.HasAnyRole(["admin"])
    assert checker.has_permission({"id": "1"}) is False


@pytest.mark.parametrize("claims", [None, "not-a-dict", 123, {}])
def test_has_any_role_denies_missing_or_invalid_identity(fallback_permissions, claims):
    checker = fallback_permissions.HasAnyRole(["admin"])
    assert checker.has_permission(claims) is False


# ---------------------------------------------------------------------------
# require_role
# ---------------------------------------------------------------------------
async def test_require_role_allows_correct_role(fallback_permissions):
    require_role = fallback_permissions.require_role

    @require_role("admin")
    async def handler(claims=None):
        return {"ok": True, "role": claims["role"]}

    result = await handler(claims={"role": "admin"})
    assert result == {"ok": True, "role": "admin"}


async def test_require_role_denies_incorrect_role(fallback_permissions):
    require_role = fallback_permissions.require_role
    HTTPException = fallback_permissions.HTTPException

    @require_role("admin")
    async def handler(claims=None):
        return {"ok": True}

    with pytest.raises(HTTPException) as exc_info:
        await handler(claims={"role": "technologist"})
    assert exc_info.value.status_code == 403


async def test_require_role_denies_missing_claims_kwarg(fallback_permissions):
    require_role = fallback_permissions.require_role
    HTTPException = fallback_permissions.HTTPException

    @require_role("admin")
    async def handler(**kwargs):
        return {"ok": True}

    with pytest.raises(HTTPException) as exc_info:
        await handler()
    assert exc_info.value.status_code == 403


async def test_require_role_denies_none_claims(fallback_permissions):
    require_role = fallback_permissions.require_role
    HTTPException = fallback_permissions.HTTPException

    @require_role("admin")
    async def handler(claims=None):
        return {"ok": True}

    with pytest.raises(HTTPException) as exc_info:
        await handler(claims=None)
    assert exc_info.value.status_code == 403


async def test_require_role_never_calls_wrapped_function_on_denial(fallback_permissions):
    """
    Belt-and-suspenders: prove the underlying route function itself is never
    invoked on a denied request, not just that an exception surfaces.
    """
    require_role = fallback_permissions.require_role
    HTTPException = fallback_permissions.HTTPException
    called = {"n": 0}

    @require_role("admin")
    async def handler(claims=None):
        called["n"] += 1
        return {"ok": True}

    with pytest.raises(HTTPException):
        await handler(claims={"role": "not-admin"})

    assert called["n"] == 0
