# ✅ New Code
# Filename: tests/test_utils.py

# to run activate venv in path:
# (gait_int_venv) \gait_sdk> 
# pytest -v -s tests/test_utils.py

import pytest
from types import SimpleNamespace
from gait_sdk.utils import (
    get_user_claims,
    get_user_id,
    get_user_role,
    is_admin,
    is_physician,
    is_technologist,
)


# ---------------------------------------------------------------------
# 🧩 Utility: Mock Request Builder
# ---------------------------------------------------------------------
def make_request(user_claims=None):
    """Create a fake request object with optional user_claims."""
    if user_claims is None:
        user_claims = {}
    return SimpleNamespace(user_claims=user_claims)


# ---------------------------------------------------------------------
# ✅ Test: get_user_claims
# ---------------------------------------------------------------------
def test_get_user_claims_returns_dict():
    """Should return user_claims when present on request."""
    req = make_request({"id": "123", "role": "admin"})
    assert get_user_claims(req) == {"id": "123", "role": "admin"}


def test_get_user_claims_missing():
    """Should return empty dict when user_claims missing."""
    req = SimpleNamespace()  # no user_claims attribute
    assert get_user_claims(req) == {}


# ---------------------------------------------------------------------
# ✅ Test: get_user_id
# ---------------------------------------------------------------------
def test_get_user_id_found():
    """Should return user ID if present in claims."""
    req = make_request({"id": "abc123"})
    assert get_user_id(req) == "abc123"


def test_get_user_id_missing():
    """Should return None if id not present."""
    req = make_request({"role": "admin"})
    assert get_user_id(req) is None


# ---------------------------------------------------------------------
# ✅ Test: get_user_role
# ---------------------------------------------------------------------
def test_get_user_role_found():
    """Should return role if present."""
    req = make_request({"role": "physician"})
    assert get_user_role(req) == "physician"


def test_get_user_role_missing():
    """Should return None if role missing."""
    req = make_request()
    assert get_user_role(req) is None


# ---------------------------------------------------------------------
# ✅ Test: Role helpers (is_admin, is_physician, is_technologist)
# ---------------------------------------------------------------------
@pytest.mark.parametrize(
    "func, role, expected",
    [
        (is_admin, "admin", True),
        (is_admin, "physician", False),
        (is_physician, "physician", True),
        (is_physician, "technologist", False),
        (is_technologist, "technologist", True),
        (is_technologist, "admin", False),
    ],
)
def test_role_helpers(func, role, expected):
    """Should correctly evaluate role-based helpers."""
    req = make_request({"role": role})
    assert func(req) == expected
