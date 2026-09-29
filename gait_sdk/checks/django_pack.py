"""The Django check pack (v1.0.0).

One function per check id in checks_v1.json. Each reads only the named
Django settings (plus INSTALLED_APPS and the URL resolver where a check needs
them) and returns `(outcome, facts)`. Facts are typed configuration facts:
booleans, bounded integers and enums. A setting's value is never returned,
and the SECRET_KEY in particular is only measured (length, distinct
characters, prefix, placeholder), never copied, logged or sent.

`deploy_check_ids()` runs Django's own deployment checks and maps the
security.W0xx/E0xx ids they return onto these checks, where they are
attached as the supporting "django_ids" fact. The pack's own rules decide
every outcome; Django's ids never do.
"""

from __future__ import annotations

from typing import Any, Callable, Iterable, Optional

PACK = "django"
PACK_VERSION = "1.0.0"

Outcome = tuple[str, dict[str, Any]]

# -----------------------------------------------------------------------------
# Django deployment-check ids -> check ids
# -----------------------------------------------------------------------------
# Derived from django/core/checks/security/{base,csrf,sessions}.py for Django
# 4.2 through 5.2. W007 and W017 were retired before 4.2 and map to nothing.
# E101/E102 (CSRF_FAILURE_VIEW can't be imported / has the wrong signature)
# have no matching check and are reported as unmapped.
DJANGO_ID_MAP = {
    "security.W001": "CHK.DJANGO.SECURITY_MIDDLEWARE",
    "security.W002": "CHK.DJANGO.CLICKJACKING",
    "security.W003": "CHK.DJANGO.CSRF_MIDDLEWARE",
    "security.W004": "CHK.DJANGO.HSTS",
    "security.W005": "CHK.DJANGO.HSTS",
    "security.W006": "CHK.DJANGO.NOSNIFF",
    "security.W008": "CHK.DJANGO.SSL_REDIRECT",
    "security.W009": "CHK.DJANGO.SIGNING_KEY_STRENGTH",
    "security.W010": "CHK.DJANGO.SESSION_COOKIE_FLAGS",
    "security.W011": "CHK.DJANGO.SESSION_COOKIE_FLAGS",
    "security.W012": "CHK.DJANGO.SESSION_COOKIE_FLAGS",
    "security.W013": "CHK.DJANGO.SESSION_COOKIE_FLAGS",
    "security.W014": "CHK.DJANGO.SESSION_COOKIE_FLAGS",
    "security.W015": "CHK.DJANGO.SESSION_COOKIE_FLAGS",
    "security.W016": "CHK.DJANGO.CSRF_COOKIE_SECURE",
    "security.W018": "CHK.DJANGO.DEBUG_OFF",
    "security.W019": "CHK.DJANGO.CLICKJACKING",
    "security.W020": "CHK.DJANGO.ALLOWED_HOSTS",
    "security.W021": "CHK.DJANGO.HSTS",
    "security.W022": "CHK.DJANGO.REFERRER_POLICY",
    "security.E023": "CHK.DJANGO.REFERRER_POLICY",
    "security.E024": "CHK.DJANGO.COOP",
    "security.W025": "CHK.DJANGO.SIGNING_KEY_FALLBACKS",
}

SECURITY_MIDDLEWARE = "django.middleware.security.SecurityMiddleware"
CSRF_MIDDLEWARE = "django.middleware.csrf.CsrfViewMiddleware"
XFRAME_MIDDLEWARE = "django.middleware.clickjacking.XFrameOptionsMiddleware"

KEY_MIN_LENGTH = 50
KEY_MIN_UNIQUE = 5
KEY_INSECURE_PREFIX = "django-insecure-"
KEY_PLACEHOLDERS = frozenset(
    {"changeme", "change-me", "secret", "secretkey", "secret_key", "dev", "development", "test", "insecure", "replace-me"}
)
HSTS_ONE_YEAR = 31536000
LOOPBACK_HOSTS = frozenset({"", "localhost", "127.0.0.1", "::1"})
PG_TLS_MODES = frozenset({"require", "verify-ca", "verify-full"})
REFERRER_GOOD = frozenset(
    {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin", "origin", "origin-when-cross-origin"}
)
REFERRER_WEAK = frozenset({"unsafe-url", "no-referrer-when-downgrade"})
COOP_GOOD = frozenset({"same-origin", "same-origin-allow-popups"})
CORS_CATCH_ALL = frozenset({".*", "^.*$", ".+", "^.+$", "^https?://.*$"})
DRF_ALLOW_ANY = "rest_framework.permissions.AllowAny"


def _settings():
    from django.conf import settings

    return settings


def _setting(name: str, default: Any = None) -> Any:
    return getattr(_settings(), name, default)


def _middleware() -> list[str]:
    return list(_setting("MIDDLEWARE", None) or [])


def _installed_apps() -> list[str]:
    return list(_setting("INSTALLED_APPS", None) or [])


def _is_installed(app: str) -> bool:
    return any(entry == app or entry.startswith(app + ".") for entry in _installed_apps())


# -----------------------------------------------------------------------------
# Signing keys
# -----------------------------------------------------------------------------
def _as_text(key: Any) -> str:
    if key is None:
        return ""
    if isinstance(key, bytes):
        return key.decode("utf-8", "replace")
    return str(key)


def _key_facts(key: Any) -> dict[str, Any]:
    """Measure a signing key. Never returns any part of it."""
    text = _as_text(key)
    return {
        "length": len(text),
        "unique_chars": len(set(text)),
        "insecure_prefix": text.startswith(KEY_INSECURE_PREFIX),
        "placeholder": text.lower() in KEY_PLACEHOLDERS,
    }


def _key_is_strong(facts: dict[str, Any]) -> bool:
    return (
        facts["length"] >= KEY_MIN_LENGTH
        and facts["unique_chars"] >= KEY_MIN_UNIQUE
        and not facts["insecure_prefix"]
        and not facts["placeholder"]
    )


def _read_secret_key() -> Any:
    from django.core.exceptions import ImproperlyConfigured

    try:
        return _settings().SECRET_KEY
    except (ImproperlyConfigured, AttributeError):
        return ""


# -----------------------------------------------------------------------------
# Databases
# -----------------------------------------------------------------------------
def _network_databases() -> list[dict[str, Any]]:
    """DATABASES entries that talk to a server over the network."""
    found = []
    for config in (_setting("DATABASES", None) or {}).values():
        engine = str(config.get("ENGINE") or "")
        host = str(config.get("HOST") or "").strip()
        if "sqlite" in engine:
            continue
        if host in LOOPBACK_HOSTS or host.startswith("/"):
            continue
        found.append(config)
    return found


def _is_postgres(config: dict[str, Any]) -> bool:
    engine = str(config.get("ENGINE") or "")
    return "postgresql" in engine or "postgis" in engine


# -----------------------------------------------------------------------------
# Checks
# -----------------------------------------------------------------------------
def check_debug_off() -> Outcome:
    debug = bool(_setting("DEBUG", False))
    return ("fail" if debug else "ok"), {"debug": debug}


def check_allowed_hosts() -> Outcome:
    hosts = list(_setting("ALLOWED_HOSTS", None) or [])
    wildcard = "*" in hosts
    outcome = "fail" if (not hosts or wildcard) else "ok"
    return outcome, {"host_count": len(hosts), "wildcard": wildcard}


def check_signing_key_strength() -> Outcome:
    facts = _key_facts(_read_secret_key())
    return ("ok" if _key_is_strong(facts) else "fail"), facts


def check_signing_key_fallbacks() -> Outcome:
    fallbacks = list(_setting("SECRET_KEY_FALLBACKS", None) or [])
    weak = sum(1 for key in fallbacks if not _key_is_strong(_key_facts(key)))
    count = len(fallbacks)
    if weak:
        outcome = "fail"
    elif count > 2:
        outcome = "weak"
    else:
        outcome = "ok"
    return outcome, {"fallback_count": count, "weak_fallbacks": weak}


def check_db_credentials_set() -> Outcome:
    network = _network_databases()
    missing = sum(1 for c in network if not c.get("USER") or not c.get("PASSWORD"))
    facts = {"network_databases": len(network), "missing_credentials": missing}
    if not network:
        return "not_applicable", facts
    return ("fail" if missing else "ok"), facts


def check_security_middleware() -> Outcome:
    present = SECURITY_MIDDLEWARE in _middleware()
    return ("ok" if present else "fail"), {"present": present}


def check_csrf_middleware() -> Outcome:
    present = CSRF_MIDDLEWARE in _middleware()
    return ("ok" if present else "fail"), {"present": present}


def _frame_option() -> str:
    raw = _setting("X_FRAME_OPTIONS", "DENY")
    if raw is None or str(raw).strip() == "":
        return "unset"
    value = str(raw).strip().upper()
    return value if value in {"DENY", "SAMEORIGIN"} else "other"


def check_clickjacking() -> Outcome:
    present = XFRAME_MIDDLEWARE in _middleware()
    option = _frame_option()
    if not present:
        outcome = "fail"
    elif option == "DENY":
        outcome = "ok"
    else:
        outcome = "weak"
    return outcome, {"middleware_present": present, "frame_option": option}


def check_ssl_redirect() -> Outcome:
    redirect = bool(_setting("SECURE_SSL_REDIRECT", False))
    proxy = _setting("SECURE_PROXY_SSL_HEADER", None) is not None
    return ("ok" if redirect else "fail"), {"ssl_redirect": redirect, "proxy_header_set": proxy}


def check_hsts() -> Outcome:
    try:
        seconds = int(_setting("SECURE_HSTS_SECONDS", 0) or 0)
    except (TypeError, ValueError):
        seconds = 0
    seconds = max(seconds, 0)
    if seconds >= HSTS_ONE_YEAR:
        outcome = "ok"
    elif seconds > 0:
        outcome = "weak"
    else:
        outcome = "fail"
    return outcome, {
        "hsts_seconds": seconds,
        "include_subdomains": bool(_setting("SECURE_HSTS_INCLUDE_SUBDOMAINS", False)),
        "preload": bool(_setting("SECURE_HSTS_PRELOAD", False)),
    }


def check_nosniff() -> Outcome:
    nosniff = bool(_setting("SECURE_CONTENT_TYPE_NOSNIFF", True))
    return ("ok" if nosniff else "fail"), {"nosniff": nosniff}


def check_session_cookie_flags() -> Outcome:
    secure = bool(_setting("SESSION_COOKIE_SECURE", False))
    httponly = bool(_setting("SESSION_COOKIE_HTTPONLY", True))
    return ("ok" if secure and httponly else "fail"), {"session_secure": secure, "session_httponly": httponly}


def check_csrf_cookie_secure() -> Outcome:
    secure = bool(_setting("CSRF_COOKIE_SECURE", False))
    return ("ok" if secure else "fail"), {"csrf_secure": secure}


def _referrer_policy() -> str:
    raw = _setting("SECURE_REFERRER_POLICY", None)
    if raw is None:
        return "unset"
    if isinstance(raw, str):
        first = raw.split(",")[0].strip()
    else:
        items = list(raw)
        first = str(items[0]).strip() if items else ""
    if not first:
        return "unset"
    if first in REFERRER_GOOD or first in REFERRER_WEAK:
        return first
    return "other"


def check_referrer_policy() -> Outcome:
    policy = _referrer_policy()
    return ("ok" if policy in REFERRER_GOOD else "weak"), {"policy": policy}


def _coop_policy() -> str:
    raw = _setting("SECURE_CROSS_ORIGIN_OPENER_POLICY", None)
    if raw is None or str(raw).strip() == "":
        return "unset"
    value = str(raw).strip()
    return value if value in COOP_GOOD or value == "unsafe-none" else "other"


def check_coop() -> Outcome:
    policy = _coop_policy()
    return ("ok" if policy in COOP_GOOD else "weak"), {"policy": policy}


def _regex_text(pattern: Any) -> str:
    return str(getattr(pattern, "pattern", pattern))


def check_cors_not_wildcard() -> Outcome:
    installed = _is_installed("corsheaders")
    allow_all = bool(_setting("CORS_ALLOW_ALL_ORIGINS", False) or _setting("CORS_ORIGIN_ALLOW_ALL", False))
    regexes = list(_setting("CORS_ALLOWED_ORIGIN_REGEXES", None) or [])
    catch_all = any(_regex_text(p) in CORS_CATCH_ALL for p in regexes)
    credentials = bool(_setting("CORS_ALLOW_CREDENTIALS", False))
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


def _admin_at_default_path() -> bool:
    from django.urls import Resolver404, resolve

    try:
        match = resolve("/admin/")
    except Resolver404:
        return False
    return "admin" in (match.app_names or []) or "admin" in (match.namespaces or [])


def check_admin_url() -> Outcome:
    installed = _is_installed("django.contrib.admin")
    if not installed:
        return "not_applicable", {"admin_installed": False, "default_path": False}
    default_path = _admin_at_default_path()
    return ("weak" if default_path else "ok"), {"admin_installed": True, "default_path": default_path}


def _class_path(entry: Any) -> str:
    if isinstance(entry, str):
        return entry
    return f"{getattr(entry, '__module__', '')}.{getattr(entry, '__qualname__', '')}"


def check_drf_default_deny() -> Outcome:
    installed = _is_installed("rest_framework")
    if not installed:
        return "not_applicable", {"drf_installed": False, "classes_set": False, "default_allow_any": False}
    config = _setting("REST_FRAMEWORK", None) or {}
    classes_set = "DEFAULT_PERMISSION_CLASSES" in config
    classes = [_class_path(c) for c in (config.get("DEFAULT_PERMISSION_CLASSES") or [])]
    # An explicitly empty list makes DRF allow every request, same as AllowAny.
    allow_any = (not classes_set) or (not classes) or DRF_ALLOW_ANY in classes
    facts = {"drf_installed": True, "classes_set": classes_set, "default_allow_any": allow_any}
    return ("fail" if allow_any else "ok"), facts


def _validator_name(entry: Any) -> str:
    if isinstance(entry, dict):
        return str(entry.get("NAME") or "")
    return ""


def check_password_policy() -> Outcome:
    validators = list(_setting("AUTH_PASSWORD_VALIDATORS", None) or [])
    min_length = 0
    common = numeric = similarity = False
    for entry in validators:
        name = _validator_name(entry)
        if name.endswith("MinimumLengthValidator"):
            options = entry.get("OPTIONS") or {}
            try:
                length = int(options.get("min_length", 8))
            except (TypeError, ValueError):
                length = 0
            min_length = max(min_length, length)
        elif name.endswith("CommonPasswordValidator"):
            common = True
        elif name.endswith("NumericPasswordValidator"):
            numeric = True
        elif name.endswith("UserAttributeSimilarityValidator"):
            similarity = True
    if min_length >= 12 and common:
        outcome = "ok"
    elif 8 <= min_length <= 11 and common:
        outcome = "weak"
    else:
        outcome = "fail"
    return outcome, {
        "validator_count": len(validators),
        "min_length": max(min_length, 0),
        "common_list_check": common,
        "numeric_check": numeric,
        "similarity_check": similarity,
    }


def check_db_tls() -> Outcome:
    postgres = [c for c in _network_databases() if _is_postgres(c)]
    tls = sum(1 for c in postgres if str((c.get("OPTIONS") or {}).get("sslmode") or "") in PG_TLS_MODES)
    facts = {"network_databases": len(postgres), "tls_required": tls}
    if not postgres:
        return "not_applicable", facts
    return ("ok" if tls == len(postgres) else "fail"), facts


def check_email_tls() -> Outcome:
    backend = str(_setting("EMAIL_BACKEND", "django.core.mail.backends.smtp.EmailBackend") or "")
    smtp = backend.endswith("smtp.EmailBackend")
    tls = bool(_setting("EMAIL_USE_TLS", False) or _setting("EMAIL_USE_SSL", False))
    facts = {"smtp_backend": smtp, "tls": tls}
    if not smtp:
        return "not_applicable", facts
    return ("ok" if tls else "fail"), facts


CHECKS: dict[str, Callable[[], Outcome]] = {
    "CHK.DJANGO.DEBUG_OFF": check_debug_off,
    "CHK.DJANGO.ALLOWED_HOSTS": check_allowed_hosts,
    "CHK.DJANGO.SIGNING_KEY_STRENGTH": check_signing_key_strength,
    "CHK.DJANGO.SIGNING_KEY_FALLBACKS": check_signing_key_fallbacks,
    "CHK.DJANGO.DB_CREDENTIALS_SET": check_db_credentials_set,
    "CHK.DJANGO.SECURITY_MIDDLEWARE": check_security_middleware,
    "CHK.DJANGO.CSRF_MIDDLEWARE": check_csrf_middleware,
    "CHK.DJANGO.CLICKJACKING": check_clickjacking,
    "CHK.DJANGO.SSL_REDIRECT": check_ssl_redirect,
    "CHK.DJANGO.HSTS": check_hsts,
    "CHK.DJANGO.NOSNIFF": check_nosniff,
    "CHK.DJANGO.SESSION_COOKIE_FLAGS": check_session_cookie_flags,
    "CHK.DJANGO.CSRF_COOKIE_SECURE": check_csrf_cookie_secure,
    "CHK.DJANGO.REFERRER_POLICY": check_referrer_policy,
    "CHK.DJANGO.COOP": check_coop,
    "CHK.DJANGO.CORS_NOT_WILDCARD": check_cors_not_wildcard,
    "CHK.DJANGO.ADMIN_URL": check_admin_url,
    "CHK.DJANGO.DRF_DEFAULT_DENY": check_drf_default_deny,
    "CHK.DJANGO.PASSWORD_POLICY": check_password_policy,
    "CHK.DJANGO.DB_TLS": check_db_tls,
    "CHK.DJANGO.EMAIL_TLS": check_email_tls,
}


# -----------------------------------------------------------------------------
# Django's own deployment checks
# -----------------------------------------------------------------------------
def _run_django_security_checks() -> Iterable[Any]:
    from django.core.checks import run_checks

    return run_checks(include_deployment_checks=True, tags=["security"])


def deploy_check_ids() -> tuple[dict[str, list[str]], list[str], Optional[str]]:
    """Run Django's security deployment checks.

    Returns (ids per check id, unmapped ids, error). Unmapped ids are only
    shown locally, never sent. Message text is never kept: only the id.
    """
    mapped: dict[str, list[str]] = {}
    unmapped: list[str] = []
    try:
        messages = list(_run_django_security_checks())
    except Exception as exc:  # a broken third-party check must not stop the pack
        return {}, [], type(exc).__name__
    for message in messages:
        msg_id = getattr(message, "id", None)
        if not msg_id:
            continue
        check_id = DJANGO_ID_MAP.get(msg_id)
        if check_id is None:
            if msg_id not in unmapped:
                unmapped.append(msg_id)
            continue
        ids = mapped.setdefault(check_id, [])
        if msg_id not in ids:
            ids.append(msg_id)
    return {k: sorted(v) for k, v in mapped.items()}, sorted(unmapped), None
