"""0.4.0 JwksVerifier: local RS256 verification of Gait access tokens."""

import threading
from datetime import datetime, timedelta, timezone

import httpx
import jwt
import pytest

from gait_sdk.exceptions import AuthConfigurationError, AuthServiceUnavailable, InvalidTokenError
from gait_sdk.verification import JwksVerifier, VerifiedIdentity, parse_jwks, _JwksFetchFailed

from tests._jwks_support import (
    AUDIENCE, ISSUER, JWKS_URL, KEY_A, KEY_B, KEY_WEAK, FakeClock, jwk, jwks, make_verifier, sign,
)


# --- happy path + identity contract ------------------------------------------
def test_valid_token_verifies_to_identity():
    verifier, endpoint = make_verifier()
    token = sign(sub="123", sid="s-1", jti="j-1")
    identity = verifier.verify(token)
    assert identity == VerifiedIdentity(
        subject="123", email="tech@example.com", session_id="s-1", token_id="j-1", issuer=ISSUER
    )
    assert endpoint.calls == 1


def test_identity_carries_no_authorization_data():
    verifier, _ = make_verifier()
    identity = verifier.verify(sign())
    assert identity.legacy_whoami is None
    claims = identity.as_claims()
    assert claims["role"] == "" and claims["first_name"] == "" and claims["last_name"] == ""
    for forbidden in ("org_id", "org_slug", "org_role", "organization", "facility_id", "permissions"):
        assert forbidden not in claims


def test_role_claim_in_token_is_ignored():
    # Even if a token somehow carried a role, it never reaches the identity.
    verifier, _ = make_verifier()
    assert verifier.verify(sign(role="physician")).as_claims()["role"] == ""


def test_subject_is_opaque_string():
    verifier, _ = make_verifier()
    assert verifier.verify(sign(sub="user_2abc")).subject == "user_2abc"


def test_fresh_cache_needs_no_network():
    verifier, endpoint = make_verifier()
    for _ in range(5):
        verifier.verify(sign())
    assert endpoint.calls == 1


async def test_async_verify_same_result():
    verifier, _ = make_verifier()
    identity = await verifier.averify(sign(sub="9"))
    assert identity.subject == "9"


# --- claim validation ---------------------------------------------------------
@pytest.mark.parametrize("claim", ["sub", "iss", "aud", "jti", "exp", "iat", "sid", "token_use"])
def test_missing_required_claim_rejected(claim):
    verifier, _ = make_verifier()
    with pytest.raises(InvalidTokenError):
        verifier.verify(sign(**{claim: None}))


@pytest.mark.parametrize("value", ["refresh", "id", "2FA_temporary", "", "ACCESS"])
def test_wrong_token_use_rejected(value):
    verifier, _ = make_verifier()
    with pytest.raises(InvalidTokenError):
        verifier.verify(sign(token_use=value))


@pytest.mark.parametrize("claim", ["sub", "sid", "jti"])
def test_empty_identity_claim_rejected(claim):
    verifier, _ = make_verifier()
    with pytest.raises(InvalidTokenError):
        verifier.verify(sign(**{claim: ""}))


def test_wrong_issuer_rejected():
    verifier, _ = make_verifier()
    with pytest.raises(InvalidTokenError):
        verifier.verify(sign(iss="https://evil.test"))


def test_wrong_audience_rejected():
    verifier, _ = make_verifier()
    with pytest.raises(InvalidTokenError):
        verifier.verify(sign(aud="urn:gait:other"))


def test_expired_rejected():
    verifier, _ = make_verifier()
    past = datetime.now(timezone.utc) - timedelta(minutes=20)
    with pytest.raises(InvalidTokenError):
        verifier.verify(sign(iat=past, exp=past + timedelta(minutes=15)))


def test_clock_skew_within_leeway_accepted():
    verifier, _ = make_verifier()
    just_expired = datetime.now(timezone.utc) - timedelta(seconds=10)
    assert verifier.verify(sign(exp=just_expired)).subject == "123"


def test_clock_skew_beyond_leeway_rejected():
    verifier, _ = make_verifier()
    expired = datetime.now(timezone.utc) - timedelta(seconds=45)
    with pytest.raises(InvalidTokenError):
        verifier.verify(sign(exp=expired))


def test_invalid_signature_rejected():
    verifier, _ = make_verifier()
    header, payload, sig = sign().split(".")
    tampered = sig[:-2] + ("AA" if not sig.endswith("AA") else "BB")
    with pytest.raises(InvalidTokenError):
        verifier.verify(f"{header}.{payload}.{tampered}")


def test_signed_by_wrong_key_under_published_kid_rejected():
    verifier, _ = make_verifier()
    with pytest.raises(InvalidTokenError):
        verifier.verify(sign(key=KEY_B, kid="kid-a"))


@pytest.mark.parametrize("token", ["", "not-a-jwt", "a.b", "a.b.c", "....."])
def test_malformed_token_rejected(token):
    verifier, _ = make_verifier()
    with pytest.raises(InvalidTokenError):
        verifier.verify(token)


def test_alg_none_rejected():
    verifier, _ = make_verifier()
    token = jwt.encode({"sub": "123"}, None, algorithm="none", headers={"kid": "kid-a"})
    with pytest.raises(InvalidTokenError):
        verifier.verify(token)


def test_hs256_rejected_even_with_public_key_as_secret():
    verifier, _ = make_verifier()
    import base64, hashlib, hmac, json
    from cryptography.hazmat.primitives import serialization

    pem = KEY_A.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    enc = lambda o: base64.urlsafe_b64encode(json.dumps(o, default=str).encode()).rstrip(b"=").decode()
    head, body = enc({"alg": "HS256", "typ": "JWT", "kid": "kid-a"}), enc({"sub": "123"})
    sig = base64.urlsafe_b64encode(hmac.new(pem, f"{head}.{body}".encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    with pytest.raises(InvalidTokenError):
        verifier.verify(f"{head}.{body}.{sig}")


def test_other_rsa_algorithm_rejected():
    verifier, _ = make_verifier()
    with pytest.raises(InvalidTokenError):
        verifier.verify(sign(alg="PS256"))


def test_missing_kid_rejected():
    verifier, _ = make_verifier()
    token = jwt.encode({"sub": "1"}, KEY_A, algorithm="RS256")
    with pytest.raises(InvalidTokenError):
        verifier.verify(token)


# --- rotation + unknown kid ---------------------------------------------------
def test_rotation_new_kid_picked_up_by_forced_refresh():
    verifier, endpoint = make_verifier()
    verifier.verify(sign())
    endpoint.document = jwks(jwk(KEY_A, "kid-a"), jwk(KEY_B, "kid-b"))
    assert verifier.verify(sign(key=KEY_B, kid="kid-b")).subject == "123"
    assert endpoint.calls == 2


def test_unknown_kid_triggers_exactly_one_forced_refresh():
    verifier, endpoint = make_verifier()
    verifier.verify(sign())
    with pytest.raises(InvalidTokenError):
        verifier.verify(sign(kid="kid-unknown"))
    assert endpoint.calls == 2


def test_unknown_kid_during_cooldown_fails_without_network():
    clock = FakeClock()
    verifier, endpoint = make_verifier(clock=clock)
    verifier.verify(sign())
    with pytest.raises(InvalidTokenError):
        verifier.verify(sign(kid="kid-x1"))
    calls_after_first = endpoint.calls
    for i in range(50):  # kid flood
        with pytest.raises(InvalidTokenError):
            verifier.verify(sign(kid=f"kid-flood-{i}"))
    assert endpoint.calls == calls_after_first  # Gait not hammered
    clock.advance(31)
    with pytest.raises(InvalidTokenError):
        verifier.verify(sign(kid="kid-after-cooldown"))
    assert endpoint.calls == calls_after_first + 1


def test_new_kid_published_during_cooldown_waits_for_cooldown():
    clock = FakeClock()
    verifier, endpoint = make_verifier(clock=clock)
    verifier.verify(sign())
    with pytest.raises(InvalidTokenError):
        verifier.verify(sign(kid="kid-b"))  # consumes the forced refresh
    endpoint.document = jwks(jwk(KEY_A, "kid-a"), jwk(KEY_B, "kid-b"))
    with pytest.raises(InvalidTokenError):
        verifier.verify(sign(key=KEY_B, kid="kid-b"))
    clock.advance(31)
    assert verifier.verify(sign(key=KEY_B, kid="kid-b")).subject == "123"


def test_successful_refresh_removing_kid_invalidates_it_immediately():
    clock = FakeClock()
    verifier, endpoint = make_verifier(jwks(jwk(KEY_A, "kid-a"), jwk(KEY_B, "kid-b")), clock=clock)
    token_a = sign()
    verifier.verify(token_a)
    endpoint.document = jwks(jwk(KEY_B, "kid-b"))  # kid-a emergency-removed
    clock.advance(301)  # cache expires -> normal refresh succeeds
    with pytest.raises(InvalidTokenError):
        verifier.verify(token_a)


def test_forced_refresh_removing_kid_invalidates_it_immediately():
    verifier, endpoint = make_verifier(jwks(jwk(KEY_A, "kid-a"), jwk(KEY_B, "kid-b")))
    token_a = sign()
    verifier.verify(token_a)
    endpoint.document = jwks(jwk(KEY_B, "kid-b"), jwk(KEY_A, "kid-c"))
    with pytest.raises(InvalidTokenError):
        verifier.verify(sign(key=KEY_A, kid="kid-zzz"))  # forces a successful refresh
    with pytest.raises(InvalidTokenError):
        verifier.verify(token_a)  # kid-a gone from the fresh set


def test_single_flight_under_concurrency():
    verifier, endpoint = make_verifier()
    results = []

    def worker():
        try:
            results.append(verifier.verify(sign()).subject)
        except Exception as exc:  # pragma: no cover
            results.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results == ["123"] * 20
    assert endpoint.calls == 1


# --- stale cache / Gait unavailable -------------------------------------------
def test_known_key_verifies_stale_within_window_on_network_failure():
    clock = FakeClock()
    verifier, endpoint = make_verifier(clock=clock)
    verifier.verify(sign())
    endpoint.fail = httpx.ConnectError("down")
    clock.advance(301)
    assert verifier.verify(sign()).subject == "123"


def test_known_key_rejected_beyond_stale_window():
    clock = FakeClock()
    verifier, endpoint = make_verifier(clock=clock)
    verifier.verify(sign())
    endpoint.fail = httpx.ConnectError("down")
    clock.advance(3601)
    with pytest.raises(AuthServiceUnavailable):
        verifier.verify(sign())


def test_unknown_kid_with_gait_unavailable_fails_closed():
    verifier, endpoint = make_verifier()
    verifier.verify(sign())
    endpoint.fail = httpx.ConnectError("down")
    with pytest.raises(AuthServiceUnavailable):
        verifier.verify(sign(kid="kid-new"))


def test_never_fetched_and_gait_unavailable_fails_closed():
    verifier, endpoint = make_verifier()
    endpoint.fail = httpx.ReadTimeout("slow")
    with pytest.raises(AuthServiceUnavailable):
        verifier.verify(sign())


def test_outage_backoff_does_not_refetch_every_request():
    clock = FakeClock()
    verifier, endpoint = make_verifier(clock=clock)
    verifier.verify(sign())
    endpoint.fail = httpx.ConnectError("down")
    clock.advance(301)
    for _ in range(20):
        verifier.verify(sign())  # stale known key
    assert endpoint.calls == 2  # one failed attempt, then backoff
    clock.advance(31)
    verifier.verify(sign())
    assert endpoint.calls == 3


def test_malformed_refresh_keeps_previous_keys_and_counts_as_failure():
    clock = FakeClock()
    verifier, endpoint = make_verifier(clock=clock)
    verifier.verify(sign())
    endpoint.document = {"not": "a jwks"}
    clock.advance(301)
    assert verifier.verify(sign()).subject == "123"  # stale-within-window


def test_verification_failure_never_calls_whoami(monkeypatch):
    def boom(*args, **kwargs):  # pragma: no cover - must never run
        raise AssertionError("JWKS verifier must never downgrade to /whoami/")

    monkeypatch.setattr("gait_sdk.client.validate_token", boom)
    monkeypatch.setattr(httpx.AsyncClient, "get", boom)
    verifier, endpoint = make_verifier()
    endpoint.fail = httpx.ConnectError("down")
    with pytest.raises(AuthServiceUnavailable):
        verifier.verify(sign())
    with pytest.raises(InvalidTokenError):
        verifier.verify("garbage")


# --- JWKS parsing ---------------------------------------------------------------
def test_parse_skips_non_rsa_and_non_signing_keys():
    keys = parse_jwks(jwks(
        {"kty": "EC", "kid": "ec", "crv": "P-256", "x": "x", "y": "y"},
        jwk(KEY_A, "enc", use="enc"),
        jwk(KEY_A, "ps", alg="PS256"),
        jwk(KEY_A, "good"),
    ))
    assert set(keys) == {"good"}


def test_parse_skips_weak_and_malformed_rsa_keys():
    keys = parse_jwks(jwks(jwk(KEY_WEAK, "weak"), {"kty": "RSA", "kid": "broken", "n": "!!", "e": "AQAB"}, jwk(KEY_A, "good")))
    assert set(keys) == {"good"}


@pytest.mark.parametrize("document", [None, [], "keys", {"keys": "nope"}, {"other": []}])
def test_parse_rejects_malformed_document(document):
    with pytest.raises(_JwksFetchFailed):
        parse_jwks(document)


def test_parse_rejects_duplicate_kid():
    with pytest.raises(_JwksFetchFailed):
        parse_jwks(jwks(jwk(KEY_A, "dup"), jwk(KEY_B, "dup")))


def test_duplicate_kid_document_fails_safely():
    verifier, _ = make_verifier(jwks(jwk(KEY_A, "kid-a"), jwk(KEY_B, "kid-a")))
    with pytest.raises(AuthServiceUnavailable):
        verifier.verify(sign())


def test_constructor_requires_configuration():
    with pytest.raises(AuthConfigurationError):
        JwksVerifier(jwks_url="", issuer=ISSUER, audience=AUDIENCE)
