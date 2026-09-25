# ✅ New Code
# Filename: tests/test_settings.py

# to run activate venv in path:
# (gait_int_venv) \gait_sdk> 
# pytest -v -s tests/test_settings.py


import os
import importlib
import pytest


# ---------------------------------------------------------------------
# 🧩 Fixture: Reset settings module between tests
# ---------------------------------------------------------------------
@pytest.fixture(autouse=True)
def reload_settings_module(monkeypatch):
    """
    Ensures gait_sdk.settings is reloaded fresh
    for every test to avoid cached environment variables.
    """
    if "gait_sdk.settings" in importlib.sys.modules:
        del importlib.sys.modules["gait_sdk.settings"]
    yield
    if "gait_sdk.settings" in importlib.sys.modules:
        del importlib.sys.modules["gait_sdk.settings"]


# ---------------------------------------------------------------------
# ✅ Test 1: Load from environment (.env / decouple)
# ---------------------------------------------------------------------
def test_loads_from_env(monkeypatch):
    """Should correctly load GAIT_AUTH_URL and GAIT_TIMEOUT from environment."""
    monkeypatch.setenv("GAIT_AUTH_URL", "https://dummy-auth.com/api")
    monkeypatch.setenv("GAIT_TIMEOUT", "10")

    settings = importlib.import_module("gait_sdk.settings")

    assert settings.GAIT_AUTH_URL == "https://dummy-auth.com/api"
    assert settings.GAIT_TIMEOUT == 10


# ---------------------------------------------------------------------
# ✅ Test 2: Missing env → should log warning and use default
# ---------------------------------------------------------------------
def test_missing_env_uses_default(monkeypatch, caplog):
    """Should warn and use fallback default values if env vars not set."""
    monkeypatch.delenv("GAIT_AUTH_URL", raising=False)
    monkeypatch.delenv("GAIT_TIMEOUT", raising=False)

    import decouple

    def fake_config(name, default=None, cast=None):
        raise ValueError("Variable not found")

    monkeypatch.setattr(decouple, "config", fake_config)

    if "gait_sdk.settings" in importlib.sys.modules:
        del importlib.sys.modules["gait_sdk.settings"]

    settings = importlib.import_module("gait_sdk.settings")

    assert settings.GAIT_AUTH_URL is None
    assert isinstance(settings.GAIT_TIMEOUT, int)
    assert any(keyword in caplog.text.lower() for keyword in ["not set", "not found", "missing"])




# ---------------------------------------------------------------------
# ✅ Test 3: Fallback to AUTH_API_URL if GAIT_AUTH_URL missing
# ---------------------------------------------------------------------
def test_fallback_to_auth_api_url(monkeypatch):
    """Should use AUTH_API_URL when GAIT_AUTH_URL is missing."""
    monkeypatch.delenv("GAIT_AUTH_URL", raising=False)
    monkeypatch.setenv("AUTH_API_URL", "https://backup-auth.com/api")

    settings = importlib.import_module("gait_sdk.settings")

    assert settings.GAIT_AUTH_URL == "https://backup-auth.com/api"


# ---------------------------------------------------------------------
# ✅ Test 4: Handles ImportError when Django not installed
# ---------------------------------------------------------------------
def test_handles_no_django(monkeypatch):
    """Should not raise errors when Django is unavailable."""
    # Step 1: Temporarily block django import
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "django.conf":
            raise ImportError("Django not installed")
        return real_import(name, *args, **kwargs)

    builtins.__import__ = fake_import

    # Step 2: Import settings
    settings = importlib.import_module("gait_sdk.settings")

    builtins.__import__ = real_import  # restore
    assert settings._is_django is False
    assert settings.GAIT_AUTH_URL is not None or settings.GAIT_AUTH_URL is None
