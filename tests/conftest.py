# ✅ Filename: tests/conftest.py
"""
Pytest configuration for gait_sdk tests.
Ensures Django-dependent imports (like DRF APIException) do not break
when Django settings are not actually configured.
"""

import os
import sys
import types
import pytest

# Step 1: Ensure gait_sdk is importable
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Step 2: Create a minimal fake Django settings module
# This prevents "AttributeError: module 'fake_django_settings' has no attribute 'configured'"
fake_django_settings = types.SimpleNamespace()
fake_django_settings.configured = True
fake_django_settings.DEBUG = False

sys.modules["fake_django_settings"] = fake_django_settings

# Step 3: Point Django to use this fake settings module
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "fake_django_settings")

# Step 4: Set safe environment vars for gait_sdk.settings
os.environ.setdefault("GAIT_AUTH_URL", "https://dummy-auth.com/api")
os.environ.setdefault("GAIT_TIMEOUT", "5")


@pytest.fixture(autouse=True)
def setup_env(monkeypatch):
    """Inject mock environment for all tests automatically."""
    monkeypatch.setenv("GAIT_AUTH_URL", "https://dummy-auth.com/api")
    monkeypatch.setenv("GAIT_TIMEOUT", "5")
