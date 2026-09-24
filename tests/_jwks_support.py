"""Shared helpers for 0.4.0 JWKS-verifier tests.

Tokens mirror Gait's stage-1a RS256 access-token contract exactly:
    sub, email, sid, jti, iss, aud, token_use="access", iat, exp  (no role)
"""

import time
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from auth_integration.verification import JwksVerifier

ISSUER = "https://auth.gait.test"
AUDIENCE = "urn:gait:lumen"
JWKS_URL = "https://auth.gait.test/.well-known/jwks.json"


def new_key(bits=2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


KEY_A = new_key()
KEY_B = new_key()
KEY_WEAK = new_key(1024)


def jwk(key, kid, **extra):
    entry = RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    entry.update({"kid": kid, "use": "sig", "alg": "RS256"})
    entry.update(extra)
    return entry


def jwks(*entries):
    return {"keys": list(entries)}


def claims(**changes):
    now = datetime.now(timezone.utc)
    body = {
        "sub": "123",
        "email": "tech@example.com",
        "sid": str(uuid.uuid4()),
        "jti": str(uuid.uuid4()),
        "iss": ISSUER,
        "aud": AUDIENCE,
        "token_use": "access",
        "iat": now,
        "exp": now + timedelta(minutes=15),
    }
    for name, value in changes.items():
        if value is None:
            body.pop(name, None)
        else:
            body[name] = value
    return body


def sign(key=KEY_A, kid="kid-a", alg="RS256", headers=None, **changes):
    hdrs = {"kid": kid}
    hdrs.update(headers or {})
    return jwt.encode(claims(**changes), key, algorithm=alg, headers=hdrs)


class FakeClock:
    def __init__(self, start=1000.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class FakeJwksEndpoint:
    """Stands in for Gait's /.well-known/jwks.json. Records every fetch."""

    def __init__(self, document):
        self.document = document
        self.fail = None  # an Exception instance to raise instead of answering
        self.calls = 0

    def __call__(self, url, timeout):
        self.calls += 1
        if self.fail is not None:
            raise self.fail
        return self.document


def make_verifier(document=None, *, clock=None, **kwargs):
    endpoint = FakeJwksEndpoint(document if document is not None else jwks(jwk(KEY_A, "kid-a")))
    verifier = JwksVerifier(
        jwks_url=JWKS_URL,
        issuer=ISSUER,
        audience=AUDIENCE,
        fetch=endpoint,
        clock=clock or FakeClock(),
        **kwargs,
    )
    return verifier, endpoint
