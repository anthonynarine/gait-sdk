"""
gait_sdk.utils
-----------------------
Framework-neutral claims/role helpers.

These only ever do structural attribute access (`getattr(request, "user_claims", {})`)
against whatever object a Django/DRF or FastAPI request-like object happens to be, so
they carry no runtime framework dependency. `HttpRequest` is imported only for type
checkers (never evaluated at import time) so this module can be imported in a
Django-less environment, e.g. a FastAPI-only install of this package.
"""

from __future__ import annotations

import warnings
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:  # pragma: no cover - type-checking only, no runtime import
    from django.http import HttpRequest


def _warn_legacy_role(name: str) -> None:
    # 0.4.0: role helpers are deprecated. Gait's RS256 contract carries no
    # role (under GAIT_TOKEN_VERIFIER=jwks the role claim is always ""), and
    # authorization belongs to the consuming application.
    warnings.warn(
        f"gait_sdk.utils.{name} is deprecated and will be removed. "
        "Authorization belongs to the consuming application, not Gait's legacy role claim.",
        DeprecationWarning,
        stacklevel=3,
    )


def get_user_claims(request: HttpRequest) -> dict:
    """
    Savely retrieves user clamis attatched to the request by the authentication class. 
    
    Returns an empty dict if clmais are missing.
    """
    return getattr(request, "user_claims", {})


def get_user_id(request: HttpRequest) -> Optional[str]:
    """
    Returns the user's ID (the opaque subject string) from the claims, or None.

    Treat it as an opaque string: do not parse it or assume it is numeric.
    """
    return get_user_claims(request).get("id")

def get_user_role(request: HttpRequest) -> Optional[str]:
    """
    Returns the user's role as an opaque string, or None. This SDK does not
    define or restrict the role vocabulary — it returns whatever the
    consuming application's Gait-issued claims contain (e.g. Lumen currently
    uses 'admin' / 'physician' / 'technologist', but a different consuming
    application may use entirely different values).
    """
    _warn_legacy_role("get_user_role")
    return get_user_claims(request).get("role")


# ---------------------------------------------------------------------------
# Backward-compatibility helpers
# ---------------------------------------------------------------------------
# is_admin / is_physician / is_technologist hard-code Lumen's current role
# vocabulary. They are kept for existing callers, but they are NOT part of
# the generic Gait SDK's role contract — a consuming application with a
# different role vocabulary should compare `get_user_role(request)` directly
# rather than relying on (or adding more of) these.
def is_admin(request: HttpRequest) -> bool:
    """
    Returns True if the user's role claim is 'admin'.

    Compatibility helper for Lumen's role vocabulary — see module note above.
    """
    _warn_legacy_role("is_admin")
    return get_user_claims(request).get("role") == "admin"


def is_physician(request: HttpRequest) -> bool:
    """
    Returns True if the user's role claim is 'physician'.

    Compatibility helper for Lumen's role vocabulary — see module note above.
    """
    _warn_legacy_role("is_physician")
    return get_user_claims(request).get("role") == "physician"

def is_technologist(request: HttpRequest) -> bool:
    """
    Returns True if the user's role claim is 'technologist'.

    Compatibility helper for Lumen's role vocabulary — see module note above.
    """
    _warn_legacy_role("is_technologist")
    return get_user_claims(request).get("role") == "technologist"
