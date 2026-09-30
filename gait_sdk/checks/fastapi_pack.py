"""The FastAPI check pack (v1.0.0).

    gait-check --pack fastapi --app mypackage.main:app

The pack imports the module and reads the app object's attributes. It never
starts the app: no lifespan, no startup/shutdown handlers, no TestClient,
no request, no call to `app()` and no `middleware_stack` build. So it can't
connect to your database or any other service. (Importing the module runs
its top-level code, as any import does.)

What it reads: `app.debug`, `app.docs_url`, `app.redoc_url`,
`app.openapi_url` and `app.user_middleware` (the middleware you added, with
the keyword arguments you passed). Facts are booleans only; no URL, origin
or host name is ever sent.
"""

from __future__ import annotations

import importlib
import os
import sys
from typing import Any, Callable, Mapping, Optional

from gait_sdk.checks.engine import PackContext, UsageError

PACK = "fastapi"
PACK_VERSION = "1.0.0"

Outcome = tuple[str, dict[str, Any]]

CORS_CATCH_ALL = frozenset({".*", "^.*$", ".+", "^.+$", "^https?://.*$"})

CORS_MIDDLEWARE = "CORSMiddleware"
TRUSTED_HOST_MIDDLEWARE = "TrustedHostMiddleware"
HTTPS_REDIRECT_MIDDLEWARE = "HTTPSRedirectMiddleware"


# -----------------------------------------------------------------------------
# Loading the app (import + attribute only)
# -----------------------------------------------------------------------------
def load_app(path: Optional[str]) -> Any:
    """Import `pkg.module:attr` and return the attribute. Nothing is started.

    Raises UsageError for a malformed path, a missing module or attribute,
    or an object that isn't a Starlette/FastAPI application.
    """
    if not path or ":" not in path:
        raise UsageError("--app must look like package.module:app (required for --pack fastapi).")
    module_name, _, attr_path = path.partition(":")
    if not module_name or not attr_path:
        raise UsageError("--app must look like package.module:app.")
    cwd = os.getcwd()
    if cwd not in sys.path:
        sys.path.insert(0, cwd)
    try:
        module = importlib.import_module(module_name)
    except ImportError:
        raise UsageError(f"--app: can't import module {module_name!r}.") from None
    except Exception as exc:
        raise UsageError(f"--app: importing {module_name!r} failed ({type(exc).__name__}).") from None
    obj: Any = module
    for part in attr_path.split("."):
        if not hasattr(obj, part):
            raise UsageError(f"--app: {module_name!r} has no attribute {attr_path!r}.")
        obj = getattr(obj, part)
    try:
        from starlette.applications import Starlette
    except ImportError:
        raise UsageError("The fastapi pack needs FastAPI: pip install 'gait-sdk[fastapi]'.") from None
    if not isinstance(obj, Starlette):
        raise UsageError(f"--app: {path!r} is not a FastAPI or Starlette application.")
    return obj


# -----------------------------------------------------------------------------
# Reading middleware without building the stack
# -----------------------------------------------------------------------------
def _middleware_entries(app: Any) -> list[tuple[str, Mapping[str, Any]]]:
    """(class name, keyword arguments) for each middleware added to the app.

    Starlette's Middleware keeps the keyword arguments as `.kwargs` (0.35+)
    or `.options` (older releases). Reading `user_middleware` never builds
    the middleware stack.
    """
    entries = []
    for entry in list(getattr(app, "user_middleware", None) or []):
        cls = getattr(entry, "cls", None)
        name = getattr(cls, "__name__", "") if cls is not None else ""
        options = getattr(entry, "kwargs", None)
        if not isinstance(options, Mapping):
            options = getattr(entry, "options", None)
        if not isinstance(options, Mapping):
            options = {}
        entries.append((name, options))
    return entries


def _find(app: Any, name: str) -> Optional[Mapping[str, Any]]:
    for cls_name, options in _middleware_entries(app):
        if cls_name == name:
            return options
    return None


def _as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    try:
        return list(value)
    except TypeError:
        return []


# -----------------------------------------------------------------------------
# Checks
# -----------------------------------------------------------------------------
def check_debug_off(app: Any, ctx: PackContext) -> Outcome:
    debug = bool(getattr(app, "debug", False))
    return ("fail" if debug else "ok"), {"debug": debug}


def check_docs_hidden(app: Any, ctx: PackContext) -> Outcome:
    # Only a production concern: docs on a staging or CI app are expected.
    if ctx.environment != "production":
        return "not_applicable", {}
    facts = {
        "docs_url_set": getattr(app, "docs_url", None) is not None,
        "redoc_url_set": getattr(app, "redoc_url", None) is not None,
        "openapi_url_set": getattr(app, "openapi_url", None) is not None,
    }
    if not any(facts.values()):
        return "ok", facts
    return ("fail" if ctx.strict else "weak"), facts


def check_cors_not_wildcard(app: Any, ctx: PackContext) -> Outcome:
    options = _find(app, CORS_MIDDLEWARE)
    installed = options is not None
    options = options or {}
    allow_all = "*" in _as_list(options.get("allow_origins"))
    regex = options.get("allow_origin_regex")
    catch_all = str(getattr(regex, "pattern", regex)) in CORS_CATCH_ALL if regex is not None else False
    credentials = bool(options.get("allow_credentials", False))
    facts = {
        "cors_installed": installed,
        "allow_all": allow_all,
        "catch_all_regex": catch_all,
        "allow_credentials": credentials,
    }
    if not installed:
        return "not_applicable", facts
    if allow_all or catch_all:
        return ("fail" if credentials else "weak"), facts
    return "ok", facts


def check_trusted_host(app: Any, ctx: PackContext) -> Outcome:
    options = _find(app, TRUSTED_HOST_MIDDLEWARE)
    installed = options is not None
    # TrustedHostMiddleware defaults allowed_hosts to ["*"].
    raw_hosts = (options or {}).get("allowed_hosts") if installed else []
    hosts = ["*"] if raw_hosts is None else _as_list(raw_hosts)
    wildcard = "*" in hosts
    outcome = "ok" if installed and not wildcard else "weak"
    return outcome, {"trusted_host_installed": installed, "wildcard": wildcard}


def check_https_redirect(app: Any, ctx: PackContext) -> Outcome:
    installed = _find(app, HTTPS_REDIRECT_MIDDLEWARE) is not None
    return ("ok" if installed else "weak"), {"https_redirect_installed": installed}


CHECKS: dict[str, Callable[[Any, PackContext], Outcome]] = {
    "CHK.FASTAPI.DEBUG_OFF": check_debug_off,
    "CHK.FASTAPI.DOCS_HIDDEN": check_docs_hidden,
    "CHK.FASTAPI.CORS_NOT_WILDCARD": check_cors_not_wildcard,
    "CHK.FASTAPI.TRUSTED_HOST": check_trusted_host,
    "CHK.FASTAPI.HTTPS_REDIRECT": check_https_redirect,
}


def prepare(ctx: PackContext) -> None:
    """Load the app once per run (usage error if --app is missing or bad)."""
    if ctx.app is None:
        ctx.app = load_app(ctx.app_path)


def run_check(check_id: str, ctx: PackContext) -> Outcome:
    return CHECKS[check_id](ctx.app, ctx)
