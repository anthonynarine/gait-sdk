# Filename: tests/test_permissions_documented_usage.py
"""
GAIT-1b follow-up: the usage patterns the docs show for the legacy role
helpers must actually work, end to end, through the real frameworks, and the
patterns the docs warn against must never allow.

GAIT-SEC-071 (low): DRF `permission_classes` takes classes and instantiates
each with no arguments, so an instance there fails the request. The docs now
show the class form (a HasRole/HasAnyRole subclass with the role fixed),
which works on 0.5.2 and 0.5.3 alike. These tests run a real DRF APIView
through APIRequestFactory with exactly that form: the right role is allowed
(200); a wrong, empty, blank, padded or missing role, malformed claims and
missing claims are denied with 403 -- never a 500.

GAIT-SEC-074 (medium): HasRole/HasAnyRole must never be usable as a FastAPI
dependency. With DRF and FastAPI both installed, `Depends(HasRole(...))` and
`Depends(HasAnyRole([...]))`, in a route's `dependencies=[...]` or as a
parameter default, must be refused at route registration or answer 403;
any 200 fails the test.

GAIT-SEC-075 (low): the same holds for the classes themselves and any
subclass, including the documented no-argument DRF subclass; their
signature is one FastAPI refuses at route registration.

GAIT-SEC-070 (low): `require_role` must sit BELOW the FastAPI route
decorator (`@app.get(...)` on top), because the route decorator registers
whatever function it is given. These tests pin the documented order, and the
app-owned `Depends()` role check the docs steer users to, through a real
FastAPI app with DRF importable too (the mixed environment).
"""

import importlib
import sys
import warnings

import pytest

# ------------------------------------------------------------
# DRF (GAIT-SEC-071)
# ------------------------------------------------------------
_HEADER = "HTTP_X_TEST_CLAIMS"
_CLAIMS_BY_KEY = {
    "physician": {"id": "1", "email": "p@example.com", "role": "physician"},
    "admin": {"id": "2", "email": "a@example.com", "role": "admin"},
    "technologist": {"id": "3", "email": "t@example.com", "role": "technologist"},
    "empty": {"id": "4", "email": "e@example.com", "role": ""},
    "blank": {"id": "5", "email": "b@example.com", "role": "   "},
    "padded": {"id": "7", "email": "d@example.com", "role": " physician "},
    "no-role": {"id": "6", "email": "n@example.com"},
    "not-a-dict": ["role", "physician"],
}


@pytest.fixture(scope="module")
def drf_env():
    """Configure a minimal Django for real DRF views; restore afterwards."""
    from django.conf import settings
    from django.utils.functional import empty

    configured_here = False
    if not settings.configured:
        settings.configure(
            DEBUG=False,
            SECRET_KEY="test-only-not-a-secret",
            ALLOWED_HOSTS=["*"],
            INSTALLED_APPS=[
                "django.contrib.contenttypes",
                "django.contrib.auth",
                "rest_framework",
            ],
            REST_FRAMEWORK={"UNAUTHENTICATED_USER": None},
        )
        import django

        django.setup()
        configured_here = True

    sys.modules.pop("gait_sdk.permissions", None)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        perms = importlib.import_module("gait_sdk.permissions")

    from rest_framework.authentication import BaseAuthentication
    from rest_framework.response import Response
    from rest_framework.test import APIRequestFactory
    from rest_framework.views import APIView

    class _TestClaimsAuthentication(BaseAuthentication):
        """Stands in for ExternalJWTAuthentication: it authenticates the
        caller and attaches `request.user_claims`, or attaches nothing."""

        def authenticate(self, request):
            key = request.META.get(_HEADER)
            if key is None or key == "none":
                # Authenticated, but no claims were attached at all.
                return (object(), None)
            request.user_claims = _CLAIMS_BY_KEY[key]
            return (object(), None)

    def make_view(permission):
        class _View(APIView):
            authentication_classes = [_TestClaimsAuthentication]
            permission_classes = [permission]

            def get(self, request):
                return Response({"ok": True})

        return _View.as_view()

    # Exactly the documented class form (gait_sdk/docs/permissions.md).
    class PhysicianRole(perms.HasRole):
        def __init__(self):
            super().__init__("physician")

    class AdminOrPhysician(perms.HasAnyRole):
        def __init__(self):
            super().__init__(["admin", "physician"])

    views = {
        "has_role": make_view(PhysicianRole),
        "has_any_role": make_view(AdminOrPhysician),
    }

    try:
        yield views, APIRequestFactory()
    finally:
        sys.modules.pop("gait_sdk.permissions", None)
        if configured_here:
            settings._wrapped = empty


def _get(drf_env, view_name, key):
    views, factory = drf_env
    extra = {} if key is None else {_HEADER: key}
    return views[view_name](factory.get("/", **extra))


@pytest.mark.parametrize("view_name,key", [
    ("has_role", "physician"),
    ("has_any_role", "physician"),
    ("has_any_role", "admin"),
])
def test_documented_drf_class_form_allows_right_role(drf_env, view_name, key):
    assert _get(drf_env, view_name, key).status_code == 200


@pytest.mark.parametrize("view_name", ["has_role", "has_any_role"])
@pytest.mark.parametrize("key", [
    "technologist",  # wrong role
    "empty",         # empty role
    "blank",         # whitespace-only role
    "padded",        # right role with surrounding whitespace
    "no-role",       # role key missing
    "not-a-dict",    # malformed claims
    "none",          # no user_claims attached at all
])
def test_documented_drf_class_form_denies_with_403(drf_env, view_name, key):
    response = _get(drf_env, view_name, key)
    assert response.status_code == 403


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_drf_class_form_constructs_fresh_instance_per_request(drf_env):
    """DRF calls the listed class with no arguments; the subclass supplies the role."""
    perms = importlib.import_module("gait_sdk.permissions")

    class PhysicianRole(perms.HasRole):
        def __init__(self):
            super().__init__("physician")

    assert PhysicianRole().required_role == "physician"
    # Instances must stay non-callable: a callable instance is accepted by
    # FastAPI's Depends() without ever checking the role (GAIT-SEC-074).
    assert not callable(PhysicianRole())
    assert not callable(perms.HasRole("physician"))
    assert not callable(perms.HasAnyRole(["physician"]))


# ------------------------------------------------------------
# FastAPI must never accept HasRole/HasAnyRole as a dependency (GAIT-SEC-074)
# ------------------------------------------------------------
def _role_checkers(perms):
    """Every way HasRole/HasAnyRole could be handed to Depends()."""

    class PhysicianRole(perms.HasRole):  # the documented DRF class form
        def __init__(self):
            super().__init__("admin")

    class AdminOrPhysician(perms.HasAnyRole):
        def __init__(self):
            super().__init__(["admin", "physician"])

    return {
        "HasRole-instance": lambda: perms.HasRole("admin"),
        "HasAnyRole-instance": lambda: perms.HasAnyRole(["admin"]),
        "HasRole-subclass": lambda: PhysicianRole,
        "HasAnyRole-subclass": lambda: AdminOrPhysician,
        "HasRole-class": lambda: perms.HasRole,
        "HasAnyRole-class": lambda: perms.HasAnyRole,
    }


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
@pytest.mark.parametrize("branch", ["drf", "fallback"])
@pytest.mark.parametrize("checker_name", [
    "HasRole-instance", "HasAnyRole-instance",
    "HasRole-subclass", "HasAnyRole-subclass",
    "HasRole-class", "HasAnyRole-class",
])
@pytest.mark.parametrize("position", ["route_dependencies", "parameter_default"])
@pytest.mark.parametrize("role", ["admin", "technologist", "", None])
def test_role_helpers_as_fastapi_depends_never_allow(
    monkeypatch, branch, checker_name, position, role
):
    """GAIT-SEC-074 (instances) and GAIT-SEC-075 (classes, incl. the
    documented no-argument subclass): FastAPI must refuse the route at
    registration or answer 403; a 200 fails. `drf` is the mixed DRF+FastAPI
    environment; `fallback` hides DRF."""
    from fastapi import Depends, FastAPI
    from fastapi.exceptions import FastAPIError
    from fastapi.testclient import TestClient

    from gait_sdk.fastapi.dependencies import verify_token

    if branch == "fallback":
        monkeypatch.setitem(sys.modules, "rest_framework.permissions", None)
    sys.modules.pop("gait_sdk.permissions", None)
    try:
        perms = importlib.import_module("gait_sdk.permissions")
        if branch == "drf":
            from rest_framework.permissions import BasePermission
            assert issubclass(perms.HasRole, BasePermission)

        checker = _role_checkers(perms)[checker_name]()
        claims = {"id": "1", "email": "u@example.com"}
        if role is not None:
            claims["role"] = role

        app = FastAPI()
        try:
            if position == "route_dependencies":
                @app.get("/x", dependencies=[Depends(verify_token), Depends(checker)])
                async def route_a():
                    return {"ok": True}
            else:
                @app.get("/x")
                async def route_b(
                    claims: dict = Depends(verify_token), allowed=Depends(checker)
                ):
                    return {"ok": True}
        except (AssertionError, TypeError, FastAPIError):
            return  # refused at route registration: never reachable

        async def fake_verify_token():
            return claims

        app.dependency_overrides[verify_token] = fake_verify_token
        response = TestClient(app, raise_server_exceptions=False).get("/x")
        assert response.status_code != 200, (
            f"Depends({checker_name}) in {position} ({branch}) allowed role {role!r}"
        )
        assert response.status_code == 403
    finally:
        sys.modules.pop("gait_sdk.permissions", None)


# ------------------------------------------------------------
# FastAPI (GAIT-SEC-070)
# ------------------------------------------------------------
@pytest.fixture()
def fastapi_client(monkeypatch):
    from fastapi import Depends, FastAPI, HTTPException
    from fastapi.testclient import TestClient

    from gait_sdk.fastapi.dependencies import verify_token

    sys.modules.pop("gait_sdk.permissions", None)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        perms = importlib.import_module("gait_sdk.permissions")
        require_role = perms.require_role

        app = FastAPI()

        # Documented order: the route decorator on top, require_role below.
        @app.get("/decorator")
        @require_role("admin")
        async def decorated(claims: dict = Depends(verify_token)):
            return {"ok": True}

        @app.get("/decorator-sync")
        @require_role("admin")
        def decorated_sync(claims: dict = Depends(verify_token)):
            return {"ok": True}

    # The app-owned Depends() check the docs recommend instead.
    def role_required(role):
        async def dependency(claims: dict = Depends(verify_token)):
            if claims.get("role") != role:
                raise HTTPException(status_code=403, detail="Insufficient role.")
            return claims
        return dependency

    @app.get("/depends")
    async def via_depends(claims: dict = Depends(role_required("admin"))):
        return {"ok": True}

    state = {"claims": None}

    async def fake_verify_token():
        return state["claims"]

    app.dependency_overrides[verify_token] = fake_verify_token
    try:
        yield TestClient(app), state
    finally:
        sys.modules.pop("gait_sdk.permissions", None)


@pytest.mark.parametrize("path", ["/decorator", "/decorator-sync", "/depends"])
def test_documented_fastapi_patterns_allow_right_role(fastapi_client, path):
    client, state = fastapi_client
    state["claims"] = {"id": "1", "email": "a@example.com", "role": "admin"}
    assert client.get(path).status_code == 200


@pytest.mark.parametrize("path", ["/decorator", "/decorator-sync", "/depends"])
@pytest.mark.parametrize("claims", [
    {"id": "2", "email": "t@example.com", "role": "technologist"},
    {"id": "3", "email": "e@example.com", "role": ""},
    {"id": "4", "email": "n@example.com"},
])
def test_documented_fastapi_patterns_deny_with_403(fastapi_client, path, claims):
    client, state = fastapi_client
    state["claims"] = claims
    assert client.get(path).status_code == 403
