"""0.5.0 security hardening -- regression tests for the 0.4.1 audit findings.

Each test reproduces the problem it guards against, so it FAILS on the code
before the fix (verified by mutation when the fix was written):

  M1  JWKS lock was held during network I/O -> one slow/attacker-triggered
      fetch stalled every verification, even for already-cached keys.
  L6  JWKS responses had no size / key-count bound.
"""

import threading
import time

import httpx
import pytest

from gait_sdk.exceptions import InvalidTokenError
from gait_sdk.verification import JwksVerifier, _JwksFetchFailed, parse_jwks

from tests._jwks_support import AUDIENCE, ISSUER, JWKS_URL, KEY_A, KEY_B, FakeClock, jwk, jwks, sign


class _BlockingEndpoint:
    """A fake Gait JWKS endpoint we can freeze mid-request."""

    def __init__(self, document):
        self.document = document
        self.release = threading.Event()
        self.block = False
        self.calls = 0
        self.entered = threading.Event()

    def __call__(self, url, timeout):
        self.calls += 1
        if self.block:
            self.entered.set()
            self.release.wait(timeout=10)
        return self.document


def _verifier(endpoint, clock=None):
    return JwksVerifier(
        jwks_url=JWKS_URL, issuer=ISSUER, audience=AUDIENCE, fetch=endpoint, clock=clock or FakeClock()
    )


# --- M1: no lock held during network I/O ---------------------------------------
def test_cached_key_verifies_while_another_thread_is_stuck_fetching():
    endpoint = _BlockingEndpoint(jwks(jwk(KEY_A, "kid-a")))
    verifier = _verifier(endpoint)
    verifier.verify(sign())  # warm cache with kid-a

    # Thread A: an unknown kid forces a refresh, and Gait "hangs".
    endpoint.block = True
    stuck = threading.Thread(target=lambda: pytest.raises(InvalidTokenError, verifier.verify, sign(kid="kid-x")))
    stuck.start()
    assert endpoint.entered.wait(timeout=5), "forced refresh never started"

    # Thread B (main): a token whose key is ALREADY cached must not wait for A.
    started = time.monotonic()
    assert verifier.verify(sign()).subject == "123"
    elapsed = time.monotonic() - started

    endpoint.release.set()
    stuck.join(timeout=10)
    assert elapsed < 1.0, f"cached-key verification blocked for {elapsed:.2f}s behind a network fetch"


def test_concurrent_misses_share_one_fetch():
    endpoint = _BlockingEndpoint(jwks(jwk(KEY_A, "kid-a"), jwk(KEY_B, "kid-b")))
    verifier = _verifier(endpoint)
    endpoint.block = True
    results = []

    def worker():
        results.append(verifier.verify(sign()).subject)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    assert endpoint.entered.wait(timeout=5)
    time.sleep(0.2)  # let the other nine pile up behind the leader
    endpoint.release.set()
    for t in threads:
        t.join(timeout=10)

    assert results == ["123"] * 10
    assert endpoint.calls == 1  # single-flight: one download for ten cold misses


def test_leader_failure_releases_waiters_and_fails_closed():
    class _FailingSlow(_BlockingEndpoint):
        def __call__(self, url, timeout):
            super().__call__(url, timeout)
            raise httpx.ConnectError("gait down")

    endpoint = _FailingSlow(None)
    endpoint.block = True
    verifier = _verifier(endpoint)
    errors = []

    def worker():
        try:
            verifier.verify(sign())
        except Exception as exc:  # noqa: BLE001 - recording the outcome
            errors.append(type(exc).__name__)

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    assert endpoint.entered.wait(timeout=5)
    endpoint.release.set()
    for t in threads:
        t.join(timeout=10)

    assert errors == ["AuthServiceUnavailable"] * 5  # nobody hangs, nobody fails open
    assert endpoint.calls == 1


# --- L6: bounded JWKS ------------------------------------------------------------
def test_too_many_keys_rejected():
    document = jwks(*[jwk(KEY_A, f"kid-{i}") for i in range(21)])
    with pytest.raises(_JwksFetchFailed):
        parse_jwks(document)


def test_oversized_response_rejected(monkeypatch):
    from gait_sdk import verification

    class _Resp:
        status_code = 200

        def iter_bytes(self):
            for _ in range(100):
                yield b"x" * 1024  # 100 KB

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(verification.httpx, "stream", lambda *a, **k: _Resp())
    with pytest.raises(_JwksFetchFailed, match="too large"):
        verification._http_fetch_json(JWKS_URL, 5)


def test_normal_sized_response_parses(monkeypatch):
    import json

    from gait_sdk import verification

    payload = json.dumps(jwks(jwk(KEY_A, "kid-a"))).encode()

    class _Resp:
        status_code = 200

        def iter_bytes(self):
            yield payload

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(verification.httpx, "stream", lambda *a, **k: _Resp())
    assert "keys" in verification._http_fetch_json(JWKS_URL, 5)


# --- L1 / L2: URLs that carry credentials must be https (exact localhost exception) ---
@pytest.mark.parametrize(
    "url",
    [
        "https://auth.example.com/api",
        "http://localhost:8000/api",
        "http://127.0.0.1:8010/api",
        "http://[::1]:8000/api",
    ],
)
def test_secure_urls_accepted(url):
    from gait_sdk.verification import is_secure_gait_url

    assert is_secure_gait_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://auth.example.com/api",  # plaintext to a real host
        "http://localhost.evil.com/api",  # prefix trick (the old startswith check passed this)
        "http://localhost@evil.com/api",  # userinfo trick
        "http://127.0.0.1.nip.io/api",  # DNS-rebinding style prefix trick
        "https://user:pass@auth.example.com/api",  # embedded credentials
        "ftp://auth.example.com/",
        "not a url",
        "",
    ],
)
def test_insecure_urls_rejected(url):
    from gait_sdk.verification import is_secure_gait_url

    assert not is_secure_gait_url(url)


def test_startup_rejects_plaintext_gait_auth_url(monkeypatch):
    from gait_sdk.exceptions import AuthConfigurationError
    from gait_sdk.verification import load_verifier_config

    monkeypatch.setenv("GAIT_AUTH_URL", "http://auth.example.com/api")
    with pytest.raises(AuthConfigurationError):
        load_verifier_config()


def test_startup_rejects_prefix_trick_jwks_url(monkeypatch):
    from gait_sdk.exceptions import AuthConfigurationError
    from gait_sdk.verification import load_verifier_config

    monkeypatch.setenv("GAIT_TOKEN_VERIFIER", "jwks")
    monkeypatch.setenv("GAIT_JWKS_URL", "http://localhost.evil.com/.well-known/jwks.json")
    monkeypatch.setenv("GAIT_ISSUER", ISSUER)
    monkeypatch.setenv("GAIT_AUDIENCE", AUDIENCE)
    with pytest.raises(AuthConfigurationError):
        load_verifier_config()


def test_live_session_check_refuses_plaintext_url(monkeypatch):
    from gait_sdk.exceptions import AuthServiceUnavailable
    from gait_sdk.session import check_session_live

    monkeypatch.setenv("GAIT_AUTH_URL", "http://auth.example.com/api")
    monkeypatch.setattr(httpx, "get", lambda *a, **k: pytest.fail("must not send the token over plaintext"))
    with pytest.raises(AuthServiceUnavailable):
        check_session_live("tok")


# --- L5: FastAPI legacy path validates Gait's answer --------------------------------
def test_fastapi_introspection_malformed_whoami_fails_closed(monkeypatch):
    from fastapi import Depends, FastAPI
    from fastapi.testclient import TestClient

    from gait_sdk.fastapi.dependencies import verify_token
    from gait_sdk.verification import set_token_verifier

    set_token_verifier(None)

    async def fake_validate(token):
        return {"email": "x@y.com"}  # 200 but no id

    monkeypatch.setattr("gait_sdk.fastapi.dependencies.validate_token", fake_validate)
    app = FastAPI()

    @app.get("/x")
    async def route(claims: dict = Depends(verify_token)):
        return claims

    response = TestClient(app).get("/x", headers={"Authorization": "Bearer t"})
    assert response.status_code == 401  # never an anonymous/empty identity


# --- Info: log the host only, never embedded credentials --------------------------
def test_settings_log_never_contains_userinfo(monkeypatch, caplog):
    import importlib
    import logging

    monkeypatch.setenv("GAIT_AUTH_URL", "https://svc:s3cret@auth.example.com/api")
    with caplog.at_level(logging.INFO, logger="gait_sdk.settings"):
        importlib.reload(importlib.import_module("gait_sdk.settings"))
    assert "s3cret" not in caplog.text
    monkeypatch.setenv("GAIT_AUTH_URL", "https://dummy-auth.com/api")
    importlib.reload(importlib.import_module("gait_sdk.settings"))
