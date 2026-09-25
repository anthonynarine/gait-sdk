# Filename: gait_sdk/settings.py
"""
gait_sdk.settings — Unified Configuration Loader
========================================================

Purpose:
--------
This module provides a **universal configuration interface** for the
`gait_sdk` package — supporting both Django (via project settings)
and FastAPI (via environment variables using python-decouple).

It ensures that all microservices in the Lumen ecosystem can resolve
authentication settings (e.g., `GAIT_AUTH_URL`, `GAIT_TIMEOUT`) without
framework-specific adapters.

Teaching Notes:
---------------
- Django projects automatically supply settings via `django.conf.settings`.
- FastAPI or standalone services read from `.env` files or environment vars.
- This design keeps configuration consistent across the stack.
"""

from __future__ import annotations

import logging
import os
from typing import Optional
from urllib.parse import urlparse

from decouple import AutoConfig

# A PRIVATE decouple instance, deliberately not `decouple.config`. The global
# `decouple.config` is a process-wide AutoConfig that locates its .env from
# the directory of whoever calls it FIRST and then caches that forever. When
# this package was imported before the host app had read any setting, the
# global instance latched onto this package's install directory (e.g.
# site-packages), found no .env, and the host app's own later
# `config("DATABASE_URL")` then failed. Using our own instance, rooted at the
# process working directory, leaves the host app's decouple state untouched.
config = AutoConfig(search_path=os.getcwd())

# Step X: Backwards-compatible flag for existing tests and callers.


# Attempt to import Django settings (if running inside a Django app).
# IMPORTANT: Django may be installed but not configured (no DJANGO_SETTINGS_MODULE).
try:
    from django.conf import settings as django_settings  # type: ignore

    _has_django = True
except Exception:  # pragma: no cover
    django_settings = None  # type: ignore
    _has_django = False

_is_django = _has_django

# -----------------------------------------------------------------------------
# ⚙️ Logger setup (lightweight internal)
# -----------------------------------------------------------------------------
logger = logging.getLogger("gait_sdk.settings")
logger.setLevel(logging.INFO)

# -----------------------------------------------------------------------------
# 🔧 Helper: Safe environment or Django setting loader
# -----------------------------------------------------------------------------
def _get_setting(name: str, default: Optional[str] = None) -> Optional[str]:
    """
    Attempts to load a configuration variable from:
        1. Django settings (ONLY if configured)
        2. Environment variables (.env via python-decouple)

    Args:
        name (str): Variable name, e.g., "GAIT_AUTH_URL".
        default (Optional[str]): Fallback value if not found.

    Returns:
        Optional[str]: The loaded value or None if unavailable.
    """
    # Step 1: Django settings (only if Django is configured)
    if _has_django and django_settings is not None and getattr(django_settings, "configured", False):
        if hasattr(django_settings, name):
            value = getattr(django_settings, name)
            logger.info("Loaded %s from Django settings.", name)
            return value

    # Step 2: Environment or .env file
    try:
        value = config(name, default=default)
        if value is not None:
            logger.info("Loaded %s from environment (.env).", name)
        return value
    except Exception:
        logger.warning("%s not found in settings or environment.", name)
        return default


# -----------------------------------------------------------------------------
# 🌐 Configuration Variables
# -----------------------------------------------------------------------------
GAIT_AUTH_URL: Optional[str] = _get_setting("GAIT_AUTH_URL") or _get_setting("AUTH_API_URL")
GAIT_TIMEOUT: int = int(_get_setting("GAIT_TIMEOUT", "5"))

# SDK2: the Gait ApplicationCredential (machine/software identity secret —
# see gait_sdk.application). Server-side only; never sent to a
# browser, never given a default/fake value, and never logged — `_get_setting`
# above only ever logs the setting NAME, never its value, for any setting,
# so this is safe by construction. Unlike GAIT_AUTH_URL, no warning is
# logged when this is unset: most consumers of this package only use human
# identity (ClaimsUser/whoami) and never touch application identity at all,
# so an absent credential here is normal, not a misconfiguration to warn
# about at import time — gait_sdk.application.verify_application()
# raises explicitly if it's actually needed and missing at call time.
GAIT_APPLICATION_CREDENTIAL: Optional[str] = _get_setting("GAIT_APPLICATION_CREDENTIAL")

# -----------------------------------------------------------------------------
# 🧠 Sanity Check & Safe Logging
# -----------------------------------------------------------------------------
if not GAIT_AUTH_URL:
    logger.warning(
        "GAIT_AUTH_URL is not set! Token validation will fail until configured.\n"
        "Set GAIT_AUTH_URL in Django settings or your .env file."
    )
else:
    parsed = urlparse(GAIT_AUTH_URL)
    domain = parsed.netloc or GAIT_AUTH_URL
    logger.info("GAIT_AUTH_URL loaded successfully (domain only shown): %s", domain)
