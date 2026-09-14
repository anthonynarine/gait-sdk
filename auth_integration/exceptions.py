"""
auth_integration.exceptions
---------------------------
Cross-framework exception definitions for both Django and FastAPI.

Teaching Notes:
    - When Django REST Framework (DRF) is installed, we subclass its APIException
      so Django apps can return structured API responses automatically.
    - When DRF is not installed (e.g., in FastAPI microservices),
      we gracefully fall back to lightweight Python exceptions.
"""

try:
    # ✅ For Django or DRF environments
    from rest_framework.exceptions import APIException
    DRF_AVAILABLE = True
except ImportError:
    # ✅ For FastAPI or lightweight microservices (no DRF)
    DRF_AVAILABLE = False

    class APIException(Exception):
        """Fallback base exception when DRF is not installed."""
        status_code = 500
        default_detail = "Unhandled authentication error."
        default_code = "internal_error"

        def __init__(self, detail: str | None = None, code: str | None = None):
            self.detail = detail or self.default_detail
            self.code = code or self.default_code
            super().__init__(self.detail)


class AuthServiceUnavailable(APIException):
    """Raised when the external Auth API is unreachable or times out."""
    status_code = 503
    default_detail = "Authentication service is currently unavailable."
    default_code = "auth_service_unavailable"


class InvalidTokenError(APIException):
    """Raised when the provided JWT is invalid, expired, or unauthorized."""
    status_code = 401
    default_detail = "Invalid or expired token."
    default_code = "invalid_token"


class InvalidApplicationCredentialError(APIException):
    """Raised when a Gait ApplicationCredential (machine identity) is missing or rejected.

    Deliberately separate from `InvalidTokenError` (human JWT identity) —
    the two identity concepts (see `auth_integration.application`) must
    never be confused by a caller catching one and assuming it covers the
    other. Kept as a single exception (not a hierarchy of "expired" /
    "revoked" / "unknown" subtypes) because Gait's own verification
    endpoint deliberately does not distinguish these reasons in its
    response either — this SDK does not attempt to re-derive a
    finer-grained reason.
    """
    status_code = 401
    default_detail = "Invalid application credential."
    default_code = "invalid_application_credential"
