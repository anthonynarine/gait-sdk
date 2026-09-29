"""CHK2a: the Django pack's rules, check by check, plus env gating and
Django deployment-id mapping. Django is configured from
tests/checks_settings.py (every check passes there); each test changes one
thing."""

import pytest

from tests._checks_support import django_settings  # noqa: F401  (configures Django)

from gait_sdk.checks import django_pack, engine, registry

pytestmark = pytest.mark.filterwarnings("ignore:Overriding setting DATABASES")

STRONG_FALLBACK ="Fb-9xQ2mZr7Lw4Xb8Nc1Vd6Hy3Tp5Js0Kq-gA7uE2oI9wR4tY6pL1zXcV8b"


def outcome(check_id, **overrides):
    with django_settings(**overrides):
        return django_pack.CHECKS[check_id]()


def test_every_spec_check_has_a_function_and_no_extras():
    assert set(django_pack.CHECKS) == set(registry.check_ids("django"))


def test_base_settings_pass_every_applicable_check():
    with django_settings():
        results, _ = engine.run_checks(["django"], "production")
    by_id = {r.check_id: r.outcome for r in results}
    assert {k for k, v in by_id.items() if v != "ok"} == {
        "CHK.DJANGO.DB_CREDENTIALS_SET",  # sqlite only
        "CHK.DJANGO.CORS_NOT_WILDCARD",  # corsheaders not installed
        "CHK.DJANGO.DB_TLS",  # sqlite only
    }


# --- DEBUG_OFF / ALLOWED_HOSTS ----------------------------------------------
def test_debug_off():
    assert outcome("CHK.DJANGO.DEBUG_OFF") == ("ok", {"debug": False})
    assert outcome("CHK.DJANGO.DEBUG_OFF", DEBUG=True) == ("fail", {"debug": True})


@pytest.mark.parametrize(
    "hosts,expected",
    [
        (["a.example.com", "b.example.com"], ("ok", {"host_count": 2, "wildcard": False})),
        ([], ("fail", {"host_count": 0, "wildcard": False})),
        (["*"], ("fail", {"host_count": 1, "wildcard": True})),
        (["a.example.com", "*"], ("fail", {"host_count": 2, "wildcard": True})),
    ],
)
def test_allowed_hosts(hosts, expected):
    assert outcome("CHK.DJANGO.ALLOWED_HOSTS", ALLOWED_HOSTS=hosts) == expected


# --- Signing keys -------------------------------------------------------------
def test_signing_key_strong():
    result, facts = outcome("CHK.DJANGO.SIGNING_KEY_STRENGTH")
    assert result == "ok"
    assert facts == {"length": 64, "unique_chars": facts["unique_chars"], "insecure_prefix": False, "placeholder": False}
    assert facts["unique_chars"] >= 5


@pytest.mark.parametrize(
    "key,fact,value",
    [
        ("short-but-random-Q9x", "length", 20),
        ("a" * 60, "unique_chars", 1),
        ("django-insecure-" + "Xq8Lr2Zm9Wn4Tb7Yc1Vd6Hy3Kp5Js0Gg-A7uE2oI9wR4", "insecure_prefix", True),
        ("changeme", "placeholder", True),
        ("Secret_Key", "placeholder", True),
    ],
)
def test_signing_key_weak_variants_fail(key, fact, value):
    result, facts = outcome("CHK.DJANGO.SIGNING_KEY_STRENGTH", SECRET_KEY=key)
    assert result == "fail"
    assert facts[fact] == value
    assert set(facts) == {"length", "unique_chars", "insecure_prefix", "placeholder"}


def test_signing_key_fallbacks():
    fn = "CHK.DJANGO.SIGNING_KEY_FALLBACKS"
    assert outcome(fn) == ("ok", {"fallback_count": 0, "weak_fallbacks": 0})
    assert outcome(fn, SECRET_KEY_FALLBACKS=[STRONG_FALLBACK, STRONG_FALLBACK + "2"]) == (
        "ok", {"fallback_count": 2, "weak_fallbacks": 0})
    assert outcome(fn, SECRET_KEY_FALLBACKS=[STRONG_FALLBACK + str(i) for i in range(3)]) == (
        "weak", {"fallback_count": 3, "weak_fallbacks": 0})
    assert outcome(fn, SECRET_KEY_FALLBACKS=[STRONG_FALLBACK, "dev"]) == (
        "fail", {"fallback_count": 2, "weak_fallbacks": 1})


# --- Databases ----------------------------------------------------------------
PG = "django.db.backends.postgresql"


def db(host, user="app", password="pw", sslmode=None, engine=PG):
    config = {"ENGINE": engine, "NAME": "app", "HOST": host, "USER": user, "PASSWORD": password}
    if sslmode:
        config["OPTIONS"] = {"sslmode": sslmode}
    return config


@pytest.mark.parametrize(
    "databases,expected",
    [
        ({"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}},
         ("not_applicable", {"network_databases": 0, "missing_credentials": 0})),
        ({"default": db("localhost", user="", password=""), "b": db("127.0.0.1"), "c": db("::1"),
          "d": db("/var/run/postgresql"), "e": db("")},
         ("not_applicable", {"network_databases": 0, "missing_credentials": 0})),
        ({"default": db("db.internal")}, ("ok", {"network_databases": 1, "missing_credentials": 0})),
        ({"default": db("db.internal"), "replica": db("replica.internal", password="")},
         ("fail", {"network_databases": 2, "missing_credentials": 1})),
        ({"default": db("db.internal", user="")}, ("fail", {"network_databases": 1, "missing_credentials": 1})),
    ],
)
def test_db_credentials_set(databases, expected):
    assert outcome("CHK.DJANGO.DB_CREDENTIALS_SET", DATABASES=databases) == expected


@pytest.mark.parametrize(
    "databases,expected",
    [
        ({"default": db("localhost")}, ("not_applicable", {"network_databases": 0, "tls_required": 0})),
        ({"default": db("mysql.internal", engine="django.db.backends.mysql")},
         ("not_applicable", {"network_databases": 0, "tls_required": 0})),
        ({"default": db("db.internal", sslmode="require")}, ("ok", {"network_databases": 1, "tls_required": 1})),
        ({"default": db("db.internal", sslmode="verify-full"),
          "gis": db("gis.internal", sslmode="verify-ca", engine="django.contrib.gis.db.backends.postgis")},
         ("ok", {"network_databases": 2, "tls_required": 2})),
        ({"default": db("db.internal", sslmode="prefer")}, ("fail", {"network_databases": 1, "tls_required": 0})),
        ({"default": db("db.internal", sslmode="require"), "b": db("b.internal")},
         ("fail", {"network_databases": 2, "tls_required": 1})),
    ],
)
def test_db_tls(databases, expected):
    assert outcome("CHK.DJANGO.DB_TLS", DATABASES=databases) == expected


# --- Middleware ----------------------------------------------------------------
def without(name):
    return [m for m in django_settings_base("MIDDLEWARE") if m != name]


def django_settings_base(name):
    from tests._checks_support import BASE_SETTINGS

    return BASE_SETTINGS[name]


def test_security_and_csrf_middleware():
    assert outcome("CHK.DJANGO.SECURITY_MIDDLEWARE") == ("ok", {"present": True})
    assert outcome("CHK.DJANGO.SECURITY_MIDDLEWARE", MIDDLEWARE=without(django_pack.SECURITY_MIDDLEWARE)) == (
        "fail", {"present": False})
    assert outcome("CHK.DJANGO.CSRF_MIDDLEWARE") == ("ok", {"present": True})
    assert outcome("CHK.DJANGO.CSRF_MIDDLEWARE", MIDDLEWARE=without(django_pack.CSRF_MIDDLEWARE)) == (
        "fail", {"present": False})


@pytest.mark.parametrize(
    "overrides,expected",
    [
        ({}, ("ok", {"middleware_present": True, "frame_option": "DENY"})),
        ({"X_FRAME_OPTIONS": "deny"}, ("ok", {"middleware_present": True, "frame_option": "DENY"})),
        ({"X_FRAME_OPTIONS": "SAMEORIGIN"}, ("weak", {"middleware_present": True, "frame_option": "SAMEORIGIN"})),
        ({"X_FRAME_OPTIONS": "ALLOW-FROM x"}, ("weak", {"middleware_present": True, "frame_option": "other"})),
        ({"MIDDLEWARE": "no-xframe"}, ("fail", {"middleware_present": False, "frame_option": "DENY"})),
    ],
)
def test_clickjacking(overrides, expected):
    if overrides.get("MIDDLEWARE") == "no-xframe":
        overrides = {"MIDDLEWARE": without(django_pack.XFRAME_MIDDLEWARE)}
    assert outcome("CHK.DJANGO.CLICKJACKING", **overrides) == expected


def test_clickjacking_django_default_counts_as_deny():
    from django.conf import global_settings

    assert outcome("CHK.DJANGO.CLICKJACKING", X_FRAME_OPTIONS=global_settings.X_FRAME_OPTIONS)[0] == "ok"


# --- Transport and headers -------------------------------------------------------
def test_ssl_redirect():
    assert outcome("CHK.DJANGO.SSL_REDIRECT") == ("ok", {"ssl_redirect": True, "proxy_header_set": True})
    assert outcome("CHK.DJANGO.SSL_REDIRECT", SECURE_SSL_REDIRECT=False, SECURE_PROXY_SSL_HEADER=None) == (
        "fail", {"ssl_redirect": False, "proxy_header_set": False})


@pytest.mark.parametrize(
    "seconds,subdomains,preload,expected",
    [
        (31536000, True, True, "ok"),
        (63072000, False, False, "ok"),
        (86400, True, False, "weak"),
        (0, False, False, "fail"),
    ],
)
def test_hsts(seconds, subdomains, preload, expected):
    result, facts = outcome(
        "CHK.DJANGO.HSTS",
        SECURE_HSTS_SECONDS=seconds, SECURE_HSTS_INCLUDE_SUBDOMAINS=subdomains, SECURE_HSTS_PRELOAD=preload,
    )
    assert result == expected
    assert facts == {"hsts_seconds": seconds, "include_subdomains": subdomains, "preload": preload}


def test_nosniff():
    assert outcome("CHK.DJANGO.NOSNIFF") == ("ok", {"nosniff": True})
    assert outcome("CHK.DJANGO.NOSNIFF", SECURE_CONTENT_TYPE_NOSNIFF=False) == ("fail", {"nosniff": False})


def test_session_cookie_flags():
    fn = "CHK.DJANGO.SESSION_COOKIE_FLAGS"
    assert outcome(fn) == ("ok", {"session_secure": True, "session_httponly": True})
    assert outcome(fn, SESSION_COOKIE_SECURE=False)[0] == "fail"
    assert outcome(fn, SESSION_COOKIE_HTTPONLY=False) == ("fail", {"session_secure": True, "session_httponly": False})


def test_csrf_cookie_secure():
    assert outcome("CHK.DJANGO.CSRF_COOKIE_SECURE") == ("ok", {"csrf_secure": True})
    assert outcome("CHK.DJANGO.CSRF_COOKIE_SECURE", CSRF_COOKIE_SECURE=False) == ("fail", {"csrf_secure": False})


@pytest.mark.parametrize(
    "value,expected",
    [
        ("same-origin", ("ok", "same-origin")),
        ("strict-origin-when-cross-origin", ("ok", "strict-origin-when-cross-origin")),
        ("no-referrer, strict-origin", ("ok", "no-referrer")),
        (["origin", "unsafe-url"], ("ok", "origin")),
        (None, ("weak", "unset")),
        ("", ("weak", "unset")),
        ("unsafe-url", ("weak", "unsafe-url")),
        ("no-referrer-when-downgrade", ("weak", "no-referrer-when-downgrade")),
        ("made-up-policy", ("weak", "other")),
    ],
)
def test_referrer_policy(value, expected):
    result, facts = outcome("CHK.DJANGO.REFERRER_POLICY", SECURE_REFERRER_POLICY=value)
    assert (result, facts["policy"]) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("same-origin", ("ok", "same-origin")),
        ("same-origin-allow-popups", ("ok", "same-origin-allow-popups")),
        ("unsafe-none", ("weak", "unsafe-none")),
        (None, ("weak", "unset")),
        ("bogus", ("weak", "other")),
    ],
)
def test_coop(value, expected):
    result, facts = outcome("CHK.DJANGO.COOP", SECURE_CROSS_ORIGIN_OPENER_POLICY=value)
    assert (result, facts["policy"]) == expected


# --- CORS / admin / DRF ---------------------------------------------------------
@pytest.fixture
def cors_installed(monkeypatch):
    real = django_pack._installed_apps
    monkeypatch.setattr(django_pack, "_installed_apps", lambda: real() + ["corsheaders"])


def test_cors_not_installed_is_not_applicable():
    result, facts = outcome("CHK.DJANGO.CORS_NOT_WILDCARD", CORS_ALLOW_ALL_ORIGINS=True)
    assert result == "not_applicable"
    assert facts["cors_installed"] is False


@pytest.mark.parametrize(
    "overrides,expected",
    [
        ({"CORS_ALLOWED_ORIGINS": ["https://app.example.com"]}, "ok"),
        ({"CORS_ALLOW_ALL_ORIGINS": True, "CORS_ALLOW_CREDENTIALS": True}, "fail"),
        ({"CORS_ORIGIN_ALLOW_ALL": True, "CORS_ALLOW_CREDENTIALS": True}, "fail"),
        ({"CORS_ALLOW_ALL_ORIGINS": True}, "weak"),
        ({"CORS_ALLOWED_ORIGIN_REGEXES": [r"^https?://.*$"], "CORS_ALLOW_CREDENTIALS": True}, "fail"),
        ({"CORS_ALLOWED_ORIGIN_REGEXES": [".*"]}, "weak"),
        ({"CORS_ALLOWED_ORIGIN_REGEXES": [r"^https://\w+\.example\.com$"], "CORS_ALLOW_CREDENTIALS": True}, "ok"),
    ],
)
def test_cors(cors_installed, overrides, expected):
    result, facts = outcome("CHK.DJANGO.CORS_NOT_WILDCARD", **overrides)
    assert result == expected
    assert facts["cors_installed"] is True


def test_admin_url():
    assert outcome("CHK.DJANGO.ADMIN_URL") == ("ok", {"admin_installed": True, "default_path": False})
    assert outcome("CHK.DJANGO.ADMIN_URL", ROOT_URLCONF="tests.checks_urls_default_admin") == (
        "weak", {"admin_installed": True, "default_path": True})


def test_admin_not_installed(monkeypatch):
    monkeypatch.setattr(django_pack, "_installed_apps", lambda: ["django.contrib.auth"])
    assert outcome("CHK.DJANGO.ADMIN_URL", ROOT_URLCONF="tests.checks_urls_default_admin")[0] == "not_applicable"


@pytest.mark.parametrize(
    "rest_framework,expected",
    [
        ({"DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"]},
         ("ok", {"drf_installed": True, "classes_set": True, "default_allow_any": False})),
        ({}, ("fail", {"drf_installed": True, "classes_set": False, "default_allow_any": True})),
        ({"DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.AllowAny"]},
         ("fail", {"drf_installed": True, "classes_set": True, "default_allow_any": True})),
        ({"DEFAULT_PERMISSION_CLASSES": []},
         ("fail", {"drf_installed": True, "classes_set": True, "default_allow_any": True})),
    ],
)
def test_drf_default_deny(rest_framework, expected):
    assert outcome("CHK.DJANGO.DRF_DEFAULT_DENY", REST_FRAMEWORK=rest_framework) == expected


def test_drf_class_objects_are_understood():
    from rest_framework.permissions import AllowAny, IsAdminUser

    assert outcome("CHK.DJANGO.DRF_DEFAULT_DENY", REST_FRAMEWORK={"DEFAULT_PERMISSION_CLASSES": [IsAdminUser]})[0] == "ok"
    assert outcome("CHK.DJANGO.DRF_DEFAULT_DENY", REST_FRAMEWORK={"DEFAULT_PERMISSION_CLASSES": [AllowAny]})[0] == "fail"


def test_drf_not_installed(monkeypatch):
    monkeypatch.setattr(django_pack, "_installed_apps", lambda: ["django.contrib.auth"])
    assert outcome("CHK.DJANGO.DRF_DEFAULT_DENY")[0] == "not_applicable"


# --- Passwords / email -----------------------------------------------------------
V = "django.contrib.auth.password_validation."


@pytest.mark.parametrize(
    "validators,expected,min_length",
    [
        ([{"NAME": V + "MinimumLengthValidator", "OPTIONS": {"min_length": 14}}, {"NAME": V + "CommonPasswordValidator"}],
         "ok", 14),
        ([{"NAME": V + "MinimumLengthValidator"}, {"NAME": V + "CommonPasswordValidator"}], "weak", 8),
        ([{"NAME": V + "MinimumLengthValidator", "OPTIONS": {"min_length": 11}},
          {"NAME": V + "CommonPasswordValidator"}], "weak", 11),
        ([{"NAME": V + "MinimumLengthValidator", "OPTIONS": {"min_length": 16}}], "fail", 16),
        ([{"NAME": V + "MinimumLengthValidator", "OPTIONS": {"min_length": 6}}, {"NAME": V + "CommonPasswordValidator"}],
         "fail", 6),
        ([{"NAME": V + "CommonPasswordValidator"}], "fail", 0),
        ([], "fail", 0),
    ],
)
def test_password_policy(validators, expected, min_length):
    result, facts = outcome("CHK.DJANGO.PASSWORD_POLICY", AUTH_PASSWORD_VALIDATORS=validators)
    assert result == expected
    assert facts["min_length"] == min_length
    assert facts["validator_count"] == len(validators)


def test_password_policy_flags():
    _, facts = outcome("CHK.DJANGO.PASSWORD_POLICY")
    assert facts == {"validator_count": 4, "min_length": 12, "common_list_check": True,
                     "numeric_check": True, "similarity_check": True}


@pytest.mark.parametrize(
    "overrides,expected",
    [
        ({}, ("ok", {"smtp_backend": True, "tls": True})),
        ({"EMAIL_USE_TLS": False, "EMAIL_USE_SSL": True}, ("ok", {"smtp_backend": True, "tls": True})),
        ({"EMAIL_USE_TLS": False}, ("fail", {"smtp_backend": True, "tls": False})),
        ({"EMAIL_BACKEND": "django.core.mail.backends.console.EmailBackend", "EMAIL_USE_TLS": False},
         ("not_applicable", {"smtp_backend": False, "tls": False})),
    ],
)
def test_email_tls(overrides, expected):
    assert outcome("CHK.DJANGO.EMAIL_TLS", **overrides) == expected


# --- Env gating ------------------------------------------------------------------------
@pytest.mark.parametrize("environment", ["local", "test"])
def test_env_gated_checks_are_not_applicable_locally(environment):
    with django_settings(DEBUG=True, ALLOWED_HOSTS=["*"]):
        results, _ = engine.run_checks(["django"], environment)
    for item in results:
        definition = registry.get_check(item.check_id)
        if definition.env_gated:
            assert (item.outcome, item.facts, item.result) == ("not_applicable", {}, "INFORMATIONAL")
        else:
            assert item.outcome != "not_applicable" or item.facts


@pytest.mark.parametrize("environment", ["ci", "staging", "production"])
def test_env_gated_checks_run_in_real_environments(environment):
    with django_settings(DEBUG=True):
        results, _ = engine.run_checks(["django"], environment, only=["CHK.DJANGO.DEBUG_OFF"])
    assert results[0].outcome == "fail"


def test_ungated_checks_still_run_locally():
    with django_settings(SECRET_KEY="dev"):
        results, _ = engine.run_checks(["django"], "local", only=["CHK.DJANGO.SIGNING_KEY_STRENGTH"])
    assert results[0].outcome == "fail"


# --- Errors ----------------------------------------------------------------------------
def test_one_check_raising_becomes_error_and_others_continue(monkeypatch):
    def boom():
        raise RuntimeError("would quote a setting here")

    monkeypatch.setitem(django_pack.CHECKS, "CHK.DJANGO.HSTS", boom)
    with django_settings():
        results, _ = engine.run_checks(["django"], "production")
    by_id = {r.check_id: r for r in results}
    assert (by_id["CHK.DJANGO.HSTS"].outcome, by_id["CHK.DJANGO.HSTS"].facts) == ("error", {})
    assert by_id["CHK.DJANGO.HSTS"].result == "INFORMATIONAL"
    assert by_id["CHK.DJANGO.HSTS"].valid
    assert len(results) == len(registry.check_ids("django"))
    assert by_id["CHK.DJANGO.NOSNIFF"].outcome == "ok"


def test_int_facts_are_clamped_to_spec_bounds():
    with django_settings(ALLOWED_HOSTS=[f"h{i}.example.com" for i in range(1500)]):
        results, _ = engine.run_checks(["django"], "production", only=["CHK.DJANGO.ALLOWED_HOSTS"])
    assert results[0].facts["host_count"] == 1000
    assert results[0].valid


# --- Django deployment ids ------------------------------------------------------------
def test_django_ids_are_attached_to_their_check_as_supporting_facts():
    with django_settings(DEBUG=True, SECURE_HSTS_SECONDS=86400, SECURE_HSTS_INCLUDE_SUBDOMAINS=False,
                         SECURE_HSTS_PRELOAD=False, SESSION_COOKIE_SECURE=False):
        results, unmapped = engine.run_checks(["django"], "production")
    by_id = {r.check_id: r for r in results}
    assert by_id["CHK.DJANGO.DEBUG_OFF"].facts["django_ids"] == ["security.W018"]
    assert by_id["CHK.DJANGO.HSTS"].facts["django_ids"] == ["security.W005", "security.W021"]
    assert by_id["CHK.DJANGO.HSTS"].outcome == "weak"  # the pack's rule decides
    assert "security.W012" in by_id["CHK.DJANGO.SESSION_COOKIE_FLAGS"].facts["django_ids"]
    assert "django_ids" not in by_id["CHK.DJANGO.NOSNIFF"].facts
    assert unmapped == []
    assert all(r.valid for r in results)


def test_clean_config_attaches_no_django_ids():
    with django_settings():
        results, unmapped = engine.run_checks(["django"], "production")
    assert not any("django_ids" in r.facts for r in results)
    assert unmapped == []


def test_unmapped_django_ids_are_reported_not_attached(monkeypatch):
    class Msg:
        def __init__(self, msg_id):
            self.id = msg_id

    monkeypatch.setattr(
        django_pack, "_run_django_security_checks",
        lambda: [Msg("security.E101"), Msg("thirdparty.W001"), Msg("security.W018"), Msg(None)],
    )
    with django_settings():
        results, unmapped = engine.run_checks(["django"], "production")
    assert unmapped == ["security.E101", "thirdparty.W001"]
    for item in results:
        for value in item.facts.get("django_ids", []):
            assert value in django_pack.DJANGO_ID_MAP


def test_django_checks_crashing_doesnt_stop_the_pack(monkeypatch):
    def boom():
        raise RuntimeError("broken third-party check")

    monkeypatch.setattr(django_pack, "_run_django_security_checks", boom)
    with django_settings():
        results, unmapped = engine.run_checks(["django"], "production")
    assert len(results) == len(registry.check_ids("django"))
    assert unmapped == []


def test_id_map_matches_installed_django_security_checks():
    """Every security.* id Django defines for 4.2-5.x maps somewhere, except E101/E102."""
    import re
    from pathlib import Path

    import django.core.checks.security as security_checks

    defined = set()
    for source in Path(security_checks.__file__).parent.glob("*.py"):
        defined |= set(re.findall(r'id="(security\.[EW]\d{3})"', source.read_text(encoding="utf-8")))
    assert defined, "couldn't read Django's security check sources"
    unmapped = defined - set(django_pack.DJANGO_ID_MAP)
    assert unmapped <= {"security.E101", "security.E102"}
    for check_id in django_pack.DJANGO_ID_MAP.values():
        assert check_id in registry.check_ids("django")
    pattern = re.compile(registry.common_facts()["django_ids"]["pattern"])
    for django_id in django_pack.DJANGO_ID_MAP:
        assert pattern.fullmatch(django_id)
