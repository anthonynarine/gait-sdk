"""CHK2b: the FastAPI pack. Real FastAPI apps, built here and in
tests/checks_fastapi_apps.py. The pack must only import and read the app:
never lifespan, startup/shutdown handlers, requests or the middleware stack."""

import io
import json
import types

import pytest
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from tests import checks_fastapi_apps as apps
from tests._checks_support import FakeGait, SleepRecorder, install_fake_gait

from gait_sdk.checks import cli, engine, fastapi_pack, registry

FASTAPI_IDS = registry.check_ids("fastapi")


def run(app, environment="production", strict=False, **kwargs):
    ctx = engine.PackContext(environment=environment, strict=strict, app=app)
    results, _ = engine.run_checks(["fastapi"], environment, context=ctx, **kwargs)
    return {r.check_id: r for r in results}


def outcome(check_id, app, environment="production", strict=False):
    item = run(app, environment, strict)[check_id]
    return item.outcome, item.facts


def app_with(*middleware, **kwargs):
    app = FastAPI(**kwargs)
    for cls, options in middleware:
        app.add_middleware(cls, **options)
    return app


def test_every_spec_check_has_a_function():
    assert set(fastapi_pack.CHECKS) == set(FASTAPI_IDS)


def test_hardened_app_passes_everything():
    results = run(apps.secure)
    assert {k: v.outcome for k, v in results.items()} == {k: "ok" for k in FASTAPI_IDS}
    for item in results.values():
        assert item.valid
        registry.validate_payload(item.check_id, item.payload, result=item.result)


# --- DEBUG_OFF -------------------------------------------------------------------------
def test_debug_off():
    assert outcome("CHK.FASTAPI.DEBUG_OFF", FastAPI()) == ("ok", {"debug": False})
    assert outcome("CHK.FASTAPI.DEBUG_OFF", FastAPI(debug=True)) == ("fail", {"debug": True})


# --- DOCS_HIDDEN -------------------------------------------------------------------------
def test_docs_hidden_ok_when_all_three_are_off():
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    assert outcome("CHK.FASTAPI.DOCS_HIDDEN", app) == (
        "ok", {"docs_url_set": False, "redoc_url_set": False, "openapi_url_set": False})


def test_docs_exposed_in_production_is_weak_or_fail_with_strict():
    facts = {"docs_url_set": True, "redoc_url_set": True, "openapi_url_set": True}
    assert outcome("CHK.FASTAPI.DOCS_HIDDEN", FastAPI()) == ("weak", facts)
    assert outcome("CHK.FASTAPI.DOCS_HIDDEN", FastAPI(), strict=True) == ("fail", facts)
    only_openapi = FastAPI(docs_url=None, redoc_url=None)
    assert outcome("CHK.FASTAPI.DOCS_HIDDEN", only_openapi)[0] == "weak"


@pytest.mark.parametrize("environment", ["ci", "staging"])
def test_docs_hidden_only_evaluated_in_production(environment):
    assert outcome("CHK.FASTAPI.DOCS_HIDDEN", FastAPI(), environment, strict=True) == ("not_applicable", {})


# --- CORS ----------------------------------------------------------------------------------
def test_cors_not_installed():
    result, facts = outcome("CHK.FASTAPI.CORS_NOT_WILDCARD", FastAPI())
    assert result == "not_applicable" and facts["cors_installed"] is False


@pytest.mark.parametrize(
    "options,expected",
    [
        ({"allow_origins": ["https://app.example.com"], "allow_credentials": True}, "ok"),
        ({"allow_origins": ["*"], "allow_credentials": True}, "fail"),
        ({"allow_origins": ["*"]}, "weak"),
        ({"allow_origin_regex": r"^https?://.*$", "allow_credentials": True}, "fail"),
        ({"allow_origin_regex": ".*"}, "weak"),
        ({"allow_origin_regex": r"^https://\w+\.example\.com$", "allow_credentials": True}, "ok"),
    ],
)
def test_cors(options, expected):
    result, facts = outcome("CHK.FASTAPI.CORS_NOT_WILDCARD", app_with((CORSMiddleware, options)))
    assert result == expected
    assert facts["cors_installed"] is True


def test_cors_reads_the_older_options_attribute():
    """Older Starlette kept middleware kwargs as `.options` instead of `.kwargs`."""
    app = FastAPI()
    app.user_middleware.append(
        types.SimpleNamespace(cls=CORSMiddleware, options={"allow_origins": ["*"], "allow_credentials": True})
    )
    assert outcome("CHK.FASTAPI.CORS_NOT_WILDCARD", app)[0] == "fail"
    app2 = FastAPI()
    app2.user_middleware.append(types.SimpleNamespace(cls=TrustedHostMiddleware, options={"allowed_hosts": ["a.com"]}))
    assert outcome("CHK.FASTAPI.TRUSTED_HOST", app2)[0] == "ok"


# --- TRUSTED_HOST / HTTPS_REDIRECT -------------------------------------------------------
@pytest.mark.parametrize(
    "middleware,expected,facts",
    [
        ([(TrustedHostMiddleware, {"allowed_hosts": ["api.example.com"]})], "ok",
         {"trusted_host_installed": True, "wildcard": False}),
        ([(TrustedHostMiddleware, {"allowed_hosts": ["*"]})], "weak",
         {"trusted_host_installed": True, "wildcard": True}),
        ([(TrustedHostMiddleware, {})], "weak", {"trusted_host_installed": True, "wildcard": True}),
        ([], "weak", {"trusted_host_installed": False, "wildcard": False}),
    ],
)
def test_trusted_host(middleware, expected, facts):
    assert outcome("CHK.FASTAPI.TRUSTED_HOST", app_with(*middleware)) == (expected, facts)


def test_https_redirect():
    assert outcome("CHK.FASTAPI.HTTPS_REDIRECT", app_with((HTTPSRedirectMiddleware, {}))) == (
        "ok", {"https_redirect_installed": True})
    assert outcome("CHK.FASTAPI.HTTPS_REDIRECT", FastAPI()) == ("weak", {"https_redirect_installed": False})


# --- Env gating ------------------------------------------------------------------------------
@pytest.mark.parametrize("environment", ["local", "test"])
def test_env_gated_checks_are_not_applicable_locally(environment):
    results = run(FastAPI(debug=True), environment)
    for check_id, item in results.items():
        if registry.get_check(check_id).env_gated:
            assert (item.outcome, item.facts) == ("not_applicable", {})
    # CORS isn't gated
    assert results["CHK.FASTAPI.CORS_NOT_WILDCARD"].facts["cors_installed"] is False


def test_debug_is_checked_in_real_environments():
    assert run(FastAPI(debug=True), "staging")["CHK.FASTAPI.DEBUG_OFF"].outcome == "fail"


# --- The app is never started ------------------------------------------------------------------
def test_app_is_never_started_or_called(monkeypatch):
    apps.SENTINEL.clear()
    fake = install_fake_gait(monkeypatch, FakeGait())
    out, err = io.StringIO(), io.StringIO()
    for app_name in ("secure", "with_handlers", "default"):
        app = getattr(apps, app_name)
        stack_before = app.middleware_stack
        code = cli.main(
            ["--pack", "fastapi", "--app", f"tests.checks_fastapi_apps:{app_name}", "--json", "--strict"],
            out=out, err=err, sleep=SleepRecorder(),
        )
        assert code in (0, 1), err.getvalue()
        assert app.middleware_stack is stack_before  # the stack was never built
    assert apps.SENTINEL == []
    assert fake.sent  # it did run and send


def test_dry_run_never_starts_the_app():
    apps.SENTINEL.clear()
    out = io.StringIO()
    code = cli.main(["--pack", "fastapi", "--app", "tests.checks_fastapi_apps:with_handlers", "--dry-run", "--json"],
                    out=out, err=io.StringIO())
    assert code in (0, 1)
    assert apps.SENTINEL == []
    assert len(json.loads(out.getvalue())["requests"]) == len(FASTAPI_IDS)


# --- --app handling ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "argv",
    [
        ["--pack", "fastapi"],  # --app missing
        ["--pack", "fastapi", "--app", "tests.checks_fastapi_apps"],  # no attribute part
        ["--pack", "fastapi", "--app", "tests.no_such_module:app"],
        ["--pack", "fastapi", "--app", "tests.checks_fastapi_apps:missing"],
        ["--pack", "fastapi", "--app", "tests.checks_fastapi_apps:not_an_app"],
    ],
)
def test_bad_app_is_a_usage_error(monkeypatch, argv):
    fake = install_fake_gait(monkeypatch, FakeGait())
    err = io.StringIO()
    assert cli.main(argv + ["--dry-run"], out=io.StringIO(), err=err) == 3
    assert fake.verify_calls == 0 and fake.sent == []


def test_bad_app_fails_before_contacting_gait(monkeypatch):
    fake = install_fake_gait(monkeypatch, FakeGait())
    assert cli.main(["--pack", "fastapi", "--app", "tests.checks_fastapi_apps:missing"],
                    out=io.StringIO(), err=io.StringIO()) == 3
    assert fake.verify_calls == 0


def test_load_app_returns_the_object_without_starting_it():
    apps.SENTINEL.clear()
    assert fastapi_pack.load_app("tests.checks_fastapi_apps:secure") is apps.secure
    assert apps.SENTINEL == []


def test_fastapi_and_deps_packs_together_without_django(monkeypatch):
    from tests._checks_support import fake_deps

    fake_deps(monkeypatch)
    install_fake_gait(monkeypatch, FakeGait())
    out = io.StringIO()
    code = cli.main(["--pack", "fastapi", "--pack", "deps", "--app", "tests.checks_fastapi_apps:secure", "--json"],
                    out=out, err=io.StringIO(), sleep=SleepRecorder())
    ids = [r["id"] for r in json.loads(out.getvalue())["results"]]
    assert ids == list(FASTAPI_IDS) + ["CHK.DEPS.KNOWN_VULNS"]
    assert code == 0


def test_strict_flag_reaches_the_engine(monkeypatch):
    install_fake_gait(monkeypatch, FakeGait())
    base = ["--pack", "fastapi", "--app", "tests.checks_fastapi_apps:default", "--no-send", "--fail-on", "fail"]
    assert cli.main(base, out=io.StringIO(), err=io.StringIO()) == 0  # docs exposed: WARNING
    assert cli.main(base + ["--strict"], out=io.StringIO(), err=io.StringIO()) == 1  # FAIL
