# Filename: tests/test_role_helpers_fail_closed.py
"""
GAIT-1b regression tests for two authorization findings in the legacy role
helpers (gait_sdk.permissions / gait_sdk.utils).

GAIT-SEC-029 (high): `require_role` used to be a pass-through no-op whenever
Django REST Framework was *importable*, regardless of which framework the
route used. A FastAPI (or plain) route in an environment that also had DRF
installed was therefore never role-checked. These tests run with DRF AND
FastAPI installed together (this repo's test environment) and prove that
`require_role` enforces anyway, and that it raises at decoration time rather
than passing through when it cannot enforce.

GAIT-SEC-056 (low): the helpers failed open on an empty/missing role
(`"" in "admin"` is True; `[""]` admitted role-less users; HasRole("")
matched a role-less user). These tests prove every helper denies an empty or
missing role, and construction rejects a str / empty-entry allowed_roles and
an empty required_role.

Every test runs against BOTH shapes of the module: the DRF branch (normal
import here) and the non-DRF fallback branch (forced by hiding
rest_framework.permissions).
"""

import importlib
import sys
import warnings
from types import SimpleNamespace

import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient

from gait_sdk.fastapi.dependencies import verify_token


def _load_permissions(monkeypatch, branch):
    if branch == "fallback":
        monkeypatch.setitem(sys.modules, "rest_framework.permissions", None)
    sys.modules.pop("gait_sdk.permissions", None)
    return importlib.import_module("gait_sdk.permissions")


@pytest.fixture(params=["drf", "fallback"])
def perms(request, monkeypatch):
    module = _load_permissions(monkeypatch, request.param)
    module._branch = request.param
    try:
        yield module
    finally:
        sys.modules.pop("gait_sdk.permissions", None)


@pytest.fixture()
def drf_perms(monkeypatch):
    """The DRF branch, i.e. what any app with DRF installed gets."""
    module = _load_permissions(monkeypatch, "drf")
    try:
        yield module
    finally:
        sys.modules.pop("gait_sdk.permissions", None)


def _check(perms, checker, claims_or_missing):
    """Call has_permission in whichever shape the loaded branch uses."""
    if perms._branch == "drf":
        if claims_or_missing is _MISSING:
            request = SimpleNamespace()
        else:
            request = SimpleNamespace(user_claims=claims_or_missing)
        return checker.has_permission(request, None)
    claims = None if claims_or_missing is _MISSING else claims_or_missing
    return checker.has_permission(claims)


_MISSING = object()

# Every way a user can lack a usable role.
ROLELESS_CLAIMS = [
    _MISSING,
    None,
    {},
    {"id": "1"},
    {"id": "1", "role": ""},
    {"id": "1", "role": "   "},
    {"id": "1", "role": None},
    {"id": "1", "role": 0},
    {"id": "1", "role": ["admin"]},
]


# ===========================================================================
# GAIT-SEC-029: require_role must enforce even when DRF is installed
# ===========================================================================
def test_drf_and_fastapi_are_both_installed(drf_perms):
    """Precondition for the SEC-029 tests: both frameworks present together."""
    from rest_framework.permissions import BasePermission

    assert issubclass(drf_perms.HasRole, BasePermission)
    assert drf_perms._FASTAPI_AVAILABLE is True


async def test_require_role_with_drf_installed_denies_wrong_role(drf_perms):
    called = {"n": 0}

    @drf_perms.require_role("admin")
    async def handler(claims=None):
        called["n"] += 1
        return {"ok": True}

    with pytest.raises(HTTPException) as exc_info:
        await handler(claims={"role": "technologist"})
    assert exc_info.value.status_code == 403
    assert called["n"] == 0


async def test_require_role_with_drf_installed_denies_missing_claims(drf_perms):
    @drf_perms.require_role("admin")
    async def handler(**kwargs):
        return {"ok": True}

    with pytest.raises(HTTPException) as exc_info:
        await handler()
    assert exc_info.value.status_code == 403


async def test_require_role_with_drf_installed_allows_correct_role(drf_perms):
    @drf_perms.require_role("admin")
    async def handler(claims=None):
        return {"ok": True}

    assert await handler(claims={"role": "admin"}) == {"ok": True}


def test_require_role_with_drf_installed_never_returns_function_unchanged(perms):
    async def handler(claims=None):
        return {"ok": True}

    assert perms.require_role("admin")(handler) is not handler


def test_require_role_sync_route_is_enforced(perms):
    called = {"n": 0}

    @perms.require_role("admin")
    def handler(claims=None):
        called["n"] += 1
        return {"ok": True}

    with pytest.raises(HTTPException) as exc_info:
        handler(claims={"role": "technologist"})
    assert exc_info.value.status_code == 403
    assert called["n"] == 0
    assert handler(claims={"role": "admin"}) == {"ok": True}
    assert called["n"] == 1


def _fastapi_client(perms):
    app = FastAPI()

    @app.get("/admin-only")
    @perms.require_role("admin")
    async def admin_only(claims: dict = Depends(verify_token)):
        return {"ok": True}

    @app.get("/admin-only-sync")
    @perms.require_role("admin")
    def admin_only_sync(claims: dict = Depends(verify_token)):
        return {"ok": True}

    return TestClient(app)


@pytest.mark.parametrize("path", ["/admin-only", "/admin-only-sync"])
@pytest.mark.parametrize(
    "role, expected_status",
    [("technologist", 403), ("", 403), (None, 403), ("admin", 200)],
)
def test_fastapi_app_with_drf_installed_enforces_role(
    perms, monkeypatch, path, role, expected_status
):
    """End-to-end: a real FastAPI app, DRF also installed, routes role-checked."""
    claims = {"id": "1", "email": "u@example.com", "first_name": "", "last_name": ""}
    if role is not None:
        claims["role"] = role

    async def fake_validate_token(token):
        return claims

    monkeypatch.setattr("gait_sdk.fastapi.dependencies.validate_token", fake_validate_token)

    resp = _fastapi_client(perms).get(path, headers={"Authorization": "Bearer t"})
    assert resp.status_code == expected_status


def test_require_role_raises_at_decoration_time_without_fastapi(perms, monkeypatch):
    """Cannot enforce -> raise when decorating, never a silent pass-through."""
    monkeypatch.setattr(perms, "_FASTAPI_AVAILABLE", False)
    decorator = perms.require_role("admin")

    async def handler(claims=None):
        return {"ok": True}

    with pytest.raises(RuntimeError, match="requires FastAPI"):
        decorator(handler)


@pytest.mark.parametrize("target", [object(), "not-a-function", 42])
def test_require_role_rejects_non_function_at_decoration_time(perms, target):
    with pytest.raises(TypeError):
        perms.require_role("admin")(target)


def test_require_role_still_emits_deprecation_warning(perms):
    with pytest.warns(DeprecationWarning, match="require_role is deprecated"):
        perms.require_role("admin")


@pytest.mark.parametrize("cls_name, arg", [("HasRole", "admin"), ("HasAnyRole", ["admin"])])
def test_role_classes_still_emit_deprecation_warning(perms, cls_name, arg):
    with pytest.warns(DeprecationWarning, match=f"{cls_name} is deprecated"):
        getattr(perms, cls_name)(arg)


# ===========================================================================
# GAIT-SEC-056: construction rejects empty/ambiguous role specs
# ===========================================================================
@pytest.mark.parametrize("bad", ["", "   "])
def test_has_role_rejects_empty_required_role(perms, bad):
    with pytest.raises(ValueError):
        perms.HasRole(bad)


@pytest.mark.parametrize("bad", [None, 1, ["admin"]])
def test_has_role_rejects_non_string_required_role(perms, bad):
    with pytest.raises(TypeError):
        perms.HasRole(bad)


@pytest.mark.parametrize("bad", ["", "   "])
def test_require_role_rejects_empty_required_role(perms, bad):
    with pytest.raises(ValueError):
        perms.require_role(bad)


def test_require_role_rejects_non_string_required_role(perms):
    with pytest.raises(TypeError):
        perms.require_role(None)


@pytest.mark.parametrize("bad", ["admin", "", b"admin", None, 5])
def test_has_any_role_rejects_string_or_non_collection(perms, bad):
    with pytest.raises(TypeError):
        perms.HasAnyRole(bad)


@pytest.mark.parametrize("bad", [[""], ["admin", ""], ("admin", "  "), {""}, []])
def test_has_any_role_rejects_empty_entries_or_empty_collection(perms, bad):
    with pytest.raises(ValueError):
        perms.HasAnyRole(bad)


@pytest.mark.parametrize("bad", [[None], ["admin", None], ["admin", 1]])
def test_has_any_role_rejects_non_string_entries(perms, bad):
    with pytest.raises(TypeError):
        perms.HasAnyRole(bad)


@pytest.mark.parametrize(
    "make_roles",
    [
        lambda: ["admin", "physician"],
        lambda: ("admin", "physician"),
        lambda: {"admin", "physician"},
        lambda: (r for r in ["admin", "physician"]),
    ],
    ids=["list", "tuple", "set", "generator"],
)
def test_has_any_role_accepts_any_collection_of_roles(perms, make_roles):
    checker = perms.HasAnyRole(make_roles())
    assert _check(perms, checker, {"role": "physician"}) is True
    assert _check(perms, checker, {"role": "nurse"}) is False


# ===========================================================================
# GAIT-SEC-056: every helper denies an empty/missing role
# ===========================================================================
@pytest.mark.parametrize("claims", ROLELESS_CLAIMS)
def test_has_role_denies_roleless_user(perms, claims):
    assert _check(perms, perms.HasRole("admin"), claims) is False


@pytest.mark.parametrize("claims", ROLELESS_CLAIMS)
def test_has_any_role_denies_roleless_user(perms, claims):
    assert _check(perms, perms.HasAnyRole(["admin", "physician"]), claims) is False


def test_has_any_role_is_not_a_substring_test(perms):
    """A substring of an allowed role is not that role."""
    checker = perms.HasAnyRole(["admin"])
    assert _check(perms, checker, {"role": "adm"}) is False
    assert _check(perms, checker, {"role": "min"}) is False


def test_has_role_compares_exactly(perms):
    checker = perms.HasRole("admin")
    assert _check(perms, checker, {"role": "Admin"}) is False
    assert _check(perms, checker, {"role": "admin "}) is False
    assert _check(perms, checker, {"role": "admin"}) is True


@pytest.mark.parametrize(
    "claims", [None, "not-a-dict", {}, {"role": ""}, {"role": "  "}, {"role": None}]
)
async def test_require_role_denies_roleless_user(perms, claims):
    called = {"n": 0}

    @perms.require_role("admin")
    async def handler(claims=None):
        called["n"] += 1

    with pytest.raises(HTTPException) as exc_info:
        await handler(claims=claims)
    assert exc_info.value.status_code == 403
    assert called["n"] == 0


# --- gait_sdk.utils --------------------------------------------------------
UTILS_ROLELESS = [_MISSING, None, "not-a-dict", {}, {"role": ""}, {"role": "  "},
                  {"role": None}, {"role": 0}]


def _request(claims):
    return SimpleNamespace() if claims is _MISSING else SimpleNamespace(user_claims=claims)


@pytest.mark.parametrize("claims", UTILS_ROLELESS)
@pytest.mark.parametrize("helper", ["is_admin", "is_physician", "is_technologist"])
def test_utils_role_helpers_deny_roleless_user(claims, helper):
    from gait_sdk import utils

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        assert getattr(utils, helper)(_request(claims)) is False


@pytest.mark.parametrize("claims", UTILS_ROLELESS)
def test_utils_get_user_role_returns_none_for_roleless_user(claims):
    from gait_sdk.utils import get_user_role

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        assert get_user_role(_request(claims)) is None


@pytest.mark.parametrize("claims", [None, "not-a-dict", 5])
def test_utils_get_user_claims_non_dict_is_empty(claims):
    from gait_sdk.utils import get_user_claims

    assert get_user_claims(SimpleNamespace(user_claims=claims)) == {}
