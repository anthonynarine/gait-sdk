# Filename: gait_sdk/__init__.py
"""
gait_sdk
----------------
Cross-framework authentication integration for Django + FastAPI.

Design rules:
-------------
- Keep package import side-effect free.
- Do NOT import framework-specific modules (Django/DRF/FastAPI) here.
- Downstream services should import adapters from stable entrypoints:
  - DRF:    gait_sdk.authentication.ExternalJWTAuthentication
  - FastAPI: gait_sdk.fastapi.dependencies.verify_token
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version


# ---------------------------------------------------------------------
# 📌 Package Version
# ---------------------------------------------------------------------
# Step 1: Resolve installed version from package metadata (no heavy imports).
try:
    __version__ = version("gait-sdk")
except PackageNotFoundError:
    __version__ = "0.0.0"


__all__ = ["__version__"]
