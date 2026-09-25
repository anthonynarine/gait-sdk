# Filename: tests/test_settings_django_unconfigured.py
import subprocess
import sys


def test_import_settings_when_django_unconfigured_does_not_raise():
    """
    Django can be installed but not configured (no DJANGO_SETTINGS_MODULE).
    Importing gait_sdk.settings must not raise ImproperlyConfigured.
    """
    # Step 1: Import in a clean interpreter with DJANGO_SETTINGS_MODULE unset
    code = (
        "import os;"
        "os.environ.pop('DJANGO_SETTINGS_MODULE', None);"
        "import gait_sdk.settings;"
        "print('ok')"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)

    assert result.returncode == 0, result.stderr
