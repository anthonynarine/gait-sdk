# ✅ New Code
# Filename: tests/test_permissions.py

# to run activate venv in path:
# (gait_int_venv) \gait_sdk> 
# pytest -v -s tests/test_permissions.py


import pytest
from types import SimpleNamespace
from gait_sdk.permissions import HasRole, HasAnyRole


# ---------------------------------------------------------------------
# 🧩 Utility: Mock Request
# ---------------------------------------------------------------------
def make_request(user_claims=None):
    """
    Create a lightweight mock request object with optional user_claims.
    """
    if user_claims is None:
        user_claims = {}
    return SimpleNamespace(user_claims=user_claims)


# ---------------------------------------------------------------------
# ✅ Test: HasRole
# ---------------------------------------------------------------------
def test_has_role_grants_access():
    """
    Should grant access when the user's role matches the required role.
    """
    request = make_request({"role": "technologist"})
    perm = HasRole("technologist")
    assert perm.has_permission(request, None) is True


def test_has_role_denies_access():
    """
    Should deny access when the user's role does NOT match.
    """
    request = make_request({"role": "physician"})
    perm = HasRole("technologist")
    assert perm.has_permission(request, None) is False


def test_has_role_no_user_claims():
    """
    Should deny access if user_claims is missing or empty.
    """
    request = make_request()
    perm = HasRole("admin")
    assert perm.has_permission(request, None) is False


# ---------------------------------------------------------------------
# ✅ Test: HasAnyRole
# ---------------------------------------------------------------------
def test_has_any_role_grants_access():
    """
    Should grant access if user's role is in allowed_roles list.
    """
    request = make_request({"role": "physician"})
    perm = HasAnyRole(["admin", "physician", "technologist"])
    assert perm.has_permission(request, None) is True


def test_has_any_role_denies_access():
    """
    Should deny access if user's role not in allowed_roles list.
    """
    request = make_request({"role": "nurse"})
    perm = HasAnyRole(["admin", "physician", "technologist"])
    assert perm.has_permission(request, None) is False


def test_has_any_role_missing_claims():
    """
    Should deny access if request has no user_claims attribute.
    """
    request = SimpleNamespace()  # no user_claims at all
    perm = HasAnyRole(["admin"])
    assert perm.has_permission(request, None) is False
