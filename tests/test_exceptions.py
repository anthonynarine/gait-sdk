# ✅ New Code
# Filename: tests/test_exceptions.py

# to run activate venv in path:
# (gait_int_venv) \gait_sdk> 
# pytest -v -s tests/test_exceptions.py


import pytest
from rest_framework.exceptions import APIException
from gait_sdk.exceptions import AuthServiceUnavailable, InvalidTokenError


# ---------------------------------------------------------------------
# 🧩 Test: AuthServiceUnavailable
# ---------------------------------------------------------------------
def test_auth_service_unavailable_attributes():
    """
    Verify that AuthServiceUnavailable has correct defaults.
    """
    exc = AuthServiceUnavailable()

    # Step 1: Validate inheritance
    assert isinstance(exc, APIException)

    # Step 2: Validate status code and messages
    assert exc.status_code == 503
    assert "Authentication service" in str(exc.detail)
    assert exc.default_code == "auth_service_unavailable"


# ---------------------------------------------------------------------
# 🧩 Test: InvalidTokenError
# ---------------------------------------------------------------------
def test_invalid_token_error_attributes():
    """
    Verify that InvalidTokenError has correct defaults.
    """
    exc = InvalidTokenError()

    # Step 1: Validate inheritance
    assert isinstance(exc, APIException)

    # Step 2: Validate status code and messages
    assert exc.status_code == 401
    assert "Invalid or expired token" in str(exc.detail)
    assert exc.default_code == "invalid_token"


# ---------------------------------------------------------------------
# ⚙️ Test: Custom messages
# ---------------------------------------------------------------------
def test_custom_exception_messages():
    """
    Verify that custom messages override defaults correctly.
    """
    custom_503 = AuthServiceUnavailable("Gait API down.")
    custom_401 = InvalidTokenError("JWT expired.")

    assert str(custom_503.detail) == "Gait API down."
    assert str(custom_401.detail) == "JWT expired."
