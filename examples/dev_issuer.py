"""A stand-in for Gait, for trying gait-sdk locally. NOT for production.

Real Gait signs access tokens with its private key and publishes the public
key at /.well-known/jwks.json. This script does the same thing on your machine
so you can run the examples without a Gait account:

    python dev_issuer.py serve          # serves http://localhost:9000/.well-known/jwks.json
    python dev_issuer.py token alice    # prints a signed access token for subject "alice"

The key is generated once into ./.dev_issuer_key.pem (gitignored). Tokens use
exactly Gait's RS256 access-token format: sub, email, sid, jti, iss, aud,
token_use="access", iat, exp -- and no roles.
"""

import http.server
import json
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

PORT = 9000
ISSUER = "http://localhost:9000"
AUDIENCE = "urn:gait:example"
KID = "dev-key-1"
KEY_FILE = Path(__file__).with_name(".dev_issuer_key.pem")


def _private_key():
    if KEY_FILE.exists():
        return serialization.load_pem_private_key(KEY_FILE.read_bytes(), password=None)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    KEY_FILE.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    return key


def jwks() -> dict:
    jwk = RSAAlgorithm.to_jwk(_private_key().public_key(), as_dict=True)
    jwk.update({"kid": KID, "use": "sig", "alg": "RS256"})
    return {"keys": [jwk]}


def token(subject: str, email: str | None = None, minutes: int = 15) -> str:
    now = datetime.now(timezone.utc)
    claims = {
        "sub": subject,
        "email": email or f"{subject}@example.com",
        "sid": str(uuid.uuid4()),
        "jti": str(uuid.uuid4()),
        "iss": ISSUER,
        "aud": AUDIENCE,
        "token_use": "access",
        "iat": now,
        "exp": now + timedelta(minutes=minutes),
    }
    return jwt.encode(claims, _private_key(), algorithm="RS256", headers={"kid": KID})


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - http.server naming
        if self.path != "/.well-known/jwks.json":
            self.send_error(404)
            return
        body = json.dumps(jwks()).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else "help"
    if command == "serve":
        print(f"Dev issuer: JWKS at {ISSUER}/.well-known/jwks.json  (Ctrl+C to stop)")
        http.server.HTTPServer(("127.0.0.1", PORT), _Handler).serve_forever()
    elif command == "token":
        print(token(sys.argv[2] if len(sys.argv) > 2 else "alice"))
    else:
        print(__doc__)
