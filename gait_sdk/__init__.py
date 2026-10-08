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

import logging
from importlib.metadata import PackageNotFoundError, version


# ---------------------------------------------------------------------
# Logging (GAIT-SEC-034)
# ---------------------------------------------------------------------
# A library never sets levels or handlers on its own loggers: the host
# application decides what is emitted and where. The NullHandler only stops
# Python's "last resort" handler from printing gait_sdk records to stderr
# when the host has configured no logging at all.
logging.getLogger("gait_sdk").addHandler(logging.NullHandler())


# ---------------------------------------------------------------------
# 📌 Package Version
# ---------------------------------------------------------------------
# Step 1: Resolve installed version from package metadata (no heavy imports).
try:
    __version__ = version("gait-sdk")
except PackageNotFoundError:
    __version__ = "0.0.0"


__all__ = ["__version__"]
