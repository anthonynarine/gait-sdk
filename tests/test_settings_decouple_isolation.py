"""Regression: importing auth_integration must not initialize decouple's GLOBAL config.

Before 0.4.1, auth_integration.settings called `decouple.config` at import
time. The global AutoConfig then cached a .env search rooted at this
package's install dir, so a host app (lumen_media) importing the SDK first
could no longer read its own .env (DATABASE_URL -> UndefinedValueError).
"""

import importlib
import subprocess
import sys
import textwrap


def test_sdk_uses_private_autoconfig():
    import decouple

    settings = importlib.import_module("auth_integration.settings")
    assert settings.config is not decouple.config


def test_importing_sdk_leaves_global_decouple_uninitialized(tmp_path):
    # Fresh interpreter, cwd with NO .env, so nothing else touches decouple first.
    script = textwrap.dedent(
        """
        import decouple
        import auth_integration.settings  # noqa: F401
        print("GLOBAL_TOUCHED" if decouple.config.config is not None else "GLOBAL_CLEAN")
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", script], cwd=tmp_path, capture_output=True, text=True, timeout=60
    )
    assert "GLOBAL_CLEAN" in result.stdout, result.stdout + result.stderr
