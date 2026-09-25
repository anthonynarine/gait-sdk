"""0.5.0 rename: `auth_integration` is a deprecated alias for `gait_sdk`.

The shim must return the SAME module objects (shared process-wide state:
configured verifier, JWKS cache, bearer cache), keep every old import path
and DRF settings string working, and warn.
"""

import importlib
import subprocess
import sys
import textwrap
import warnings


def _run(code):
    return subprocess.run([sys.executable, "-c", textwrap.dedent(code)], capture_output=True, text=True, timeout=120)


def test_old_import_warns_deprecated():
    result = _run(
        """
        import warnings
        warnings.simplefilter("always")
        with warnings.catch_warnings(record=True) as caught:
            import auth_integration
        print(any(issubclass(w.category, DeprecationWarning) and "gait_sdk" in str(w.message) for w in caught))
        """
    )
    assert result.stdout.strip() == "True", result.stderr


def test_old_submodules_are_the_same_objects():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        import auth_integration  # noqa: F401

    for name in ("verification", "session", "settings", "exceptions", "client", "application", "security", "context"):
        old = importlib.import_module(f"auth_integration.{name}")
        new = importlib.import_module(f"gait_sdk.{name}")
        assert old is new, name


def test_old_framework_paths_resolve_to_same_objects():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        from auth_integration.authentication import ExternalJWTAuthentication as OldAuth
        from auth_integration.django.authentication import require_live_session as old_gate
        from auth_integration.fastapi.dependencies import verify_token as old_verify
    from gait_sdk.authentication import ExternalJWTAuthentication
    from gait_sdk.django.authentication import require_live_session
    from gait_sdk.fastapi.dependencies import verify_token

    assert OldAuth is ExternalJWTAuthentication
    assert old_gate is require_live_session
    assert old_verify is verify_token


def test_shared_state_across_names():
    # A verifier configured through the old name is the one the new name sees.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        from auth_integration.verification import set_token_verifier
    from gait_sdk.verification import IntrospectionVerifier, get_token_verifier

    marker = IntrospectionVerifier()
    try:
        set_token_verifier(marker)
        assert get_token_verifier() is marker
    finally:
        set_token_verifier(None)


def test_drf_dotted_setting_string_still_imports():
    # Lumen's settings reference the class by dotted string.
    from django.utils.module_loading import import_string

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        cls = import_string("auth_integration.authentication.ExternalJWTAuthentication")
    from gait_sdk.authentication import ExternalJWTAuthentication

    assert cls is ExternalJWTAuthentication


def test_unknown_old_submodule_still_raises():
    import pytest

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        import auth_integration  # noqa: F401
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("auth_integration.does_not_exist")


def test_version_is_shared():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        import auth_integration
    import gait_sdk

    assert auth_integration.__version__ == gait_sdk.__version__
