# gait-sdk

[![PyPI](https://img.shields.io/pypi/v/gait-sdk.svg)](https://pypi.org/project/gait-sdk/)
[![Python](https://img.shields.io/pypi/pyversions/gait-sdk.svg)](https://pypi.org/project/gait-sdk/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/anthonynarine/gait-sdk/blob/main/LICENSE)

The official Python SDK for **Gait**, an identity and security platform. Drop it into a **Django REST Framework** or **FastAPI** service to verify who is calling you, using identities Gait issues. It never issues tokens, stores passwords, or makes authorization decisions.

```
Gait                authenticates   — who are you? (login, 2FA, sessions, signed tokens)
gait-sdk            verifies        — is this token genuine, and whose is it?
your application    authorizes      — what may this person do here?
```

![How gait-sdk works: the browser logs in to Gait, sends a Bearer token to your app, gait-sdk verifies it locally with Gait's cached public keys, your code authorizes, and sensitive actions get a live session check](https://raw.githubusercontent.com/anthonynarine/gait-sdk/main/docs/assets/how-it-works.svg)

That boundary is the core design rule. The SDK hands your code a verified **identity** (`subject`, `email`, session, token id, issuer). Roles, organizations and permissions belong to your application. See [Architecture](https://github.com/anthonynarine/gait-sdk/blob/main/docs/ARCHITECTURE.md).

### What is Gait?

**Gait** is an identity and security service. It handles everything about *who someone is*:
- sign-up and login;
- two-factor authentication;
- sessions, logout and "log out everywhere";
- short-lived signed access tokens, and publishing the public keys that let other services check them.

Alongside that, it watches its own security posture (a security observatory with automated investigation).

Apps don't build login themselves. They send people to Gait, and gait-sdk lets their backend trust the result.

> **Availability:** Gait currently serves its own first-party applications (starting with **Lumen**, a vascular-ultrasound reporting platform). Self-service onboarding for outside applications isn't open yet. You can still try gait-sdk end to end today with the local stand-in issuer in [`examples/`](https://github.com/anthonynarine/gait-sdk/tree/main/examples).

### New here? Start here

1. **[Concepts](https://github.com/anthonynarine/gait-sdk/blob/main/docs/CONCEPTS.md)**: tokens, signatures, JWKS, revocation, 401 vs 403, in plain language.
2. **[Examples](https://github.com/anthonynarine/gait-sdk/tree/main/examples)**: a FastAPI and a Django app you can run in five minutes, no account needed.
3. **[Integration guide](https://github.com/anthonynarine/gait-sdk/blob/main/docs/INTEGRATION_GUIDE.md)**: wiring it into your own app.
4. Something wrong? **[Troubleshooting](https://github.com/anthonynarine/gait-sdk/blob/main/docs/TROUBLESHOOTING.md)** lists the exact error messages.

---

## Install

```bash
pip install "gait-sdk[django]"     # Django REST Framework services
pip install "gait-sdk[fastapi]"    # FastAPI services
pip install gait-sdk               # core only (verification, sessions, app identity)
```

Requires Python 3.10+. Pin exact versions in production (`gait-sdk==0.5.0`). See [Supply chain](https://github.com/anthonynarine/gait-sdk/blob/main/docs/PUBLISHING.md#consuming-safely).

---

## Quick start: Django REST Framework

```python
# settings.py
INSTALLED_APPS = [..., "gait_sdk"]          # validates configuration at startup

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["gait_sdk.authentication.ExternalJWTAuthentication"],
}

GAIT_TOKEN_VERIFIER = "jwks"                 # verify locally (recommended)
GAIT_JWKS_URL = "https://auth.example.com/.well-known/jwks.json"
GAIT_ISSUER = "https://auth.example.com"
GAIT_AUDIENCE = "urn:gait:your-app"
GAIT_AUTH_URL = "https://auth.example.com/api"   # used for live session checks
```

```python
# views.py
from gait_sdk.django.authentication import require_live_session

class FinalizeReport(APIView):
    def post(self, request, pk):
        identity = request.verified_identity    # subject, email, session_id, token_id, issuer
        ...                                     # YOUR authorization check first
        require_live_session(request)           # sensitive action: confirm the session live
        ...                                     # then mutate
```

## Quick start: FastAPI

```python
from fastapi import Depends, FastAPI
from gait_sdk.fastapi.dependencies import require_live_session, validate_configuration, verify_token

app = FastAPI()
validate_configuration()   # fail at startup, not on the first request

@app.get("/me")
async def me(claims: dict = Depends(verify_token)):
    return {"subject": claims["id"], "email": claims["email"]}   # "id" works in both verifier modes

@app.post("/danger")
async def danger(claims: dict = Depends(require_live_session)):
    ...
```

---

## Configuration

| Setting | Default | Purpose |
|---|---|---|
| `GAIT_TOKEN_VERIFIER` | `introspection` | `jwks` = verify tokens locally against Gait's published keys (recommended). `introspection` = ask Gait `/whoami/` on every request (legacy). Chosen explicitly, with **no automatic fallback**. |
| `GAIT_JWKS_URL` | — | Required for `jwks`. Must be `https` (plain `http` only for `localhost`). |
| `GAIT_ISSUER` | — | Required for `jwks`. Must equal Gait's `JWT_ISSUER` exactly. |
| `GAIT_AUDIENCE` | — | Required for `jwks`. Must equal Gait's `JWT_AUDIENCE`. |
| `GAIT_AUTH_URL` | — | Gait's API base (`…/api`), used by live session checks, introspection, application identity and signals. `https` required (http only for `localhost`). |
| `GAIT_TIMEOUT` | `5` | Seconds for calls to Gait. |
| `GAIT_APPLICATION_CREDENTIAL` | — | Only for application identity / security signals. A secret: keep it in the environment. |
| `GAIT_ALLOW_COOKIE_AUTH` | `False` | Deprecated legacy cookie mode (introspection only). Leave off. See [Security](https://github.com/anthonynarine/gait-sdk/blob/main/docs/SECURITY.md). |

Settings come from Django settings first, then environment variables / `.env`. An invalid or incomplete configuration **stops the service at startup**.

---

## What you get

| Module | For |
|---|---|
| `gait_sdk.verification` | Token verification (`JwksVerifier`, `IntrospectionVerifier`) → `VerifiedIdentity` |
| `gait_sdk.session` | `check_session_live()`: live revocation check for sensitive actions |
| `gait_sdk.authentication` / `gait_sdk.django` | DRF authentication class, `require_live_session(request)` |
| `gait_sdk.fastapi.dependencies` | `verify_token`, `require_live_session`, `validate_configuration` |
| `gait_sdk.application` | Verify your *service's* own Gait credential (machine identity) |
| `gait_sdk.context` | `SecurityContext`: human identity + application identity together |
| `gait_sdk.security` | Send tenant security signals to Gait |

## Security, in one screen

- **RS256 only.** `alg=none`, HS256 key-confusion and unknown algorithms are rejected. `iss`, `aud`, `exp`, `iat`, `sub`, `sid`, `jti` and `token_use="access"` are all required.
- **The SDK holds no secrets for verification.** It only ever has Gait's *public* keys, so it cannot mint tokens even if compromised.
- **Fails closed:** an invalid token → **401**; Gait unreachable → **503**. It never falls back to a weaker check.
- **Real 401s** (not DRF's silent 403), so clients' refresh-on-401 logic works.
- **Revocation:** local verification sees a revoked session only when its token expires (≤15 min). Protect sensitive actions with `require_live_session`.
- **No token, cookie or credential value is ever logged.**

Full threat model, guarantees, limits and audit history: [docs/SECURITY.md](https://github.com/anthonynarine/gait-sdk/blob/main/docs/SECURITY.md). To report a vulnerability, see the same file.

---

## Upgrading from `auth_integration`

The package was renamed in **0.5.0**. The old import name still works as a deprecated alias until 0.6.0, returning the *same* modules, so nothing breaks while you migrate:

1. `pip install gait-sdk` (replacing the old git URL pin).
2. Replace `auth_integration` with `gait_sdk` in imports, `INSTALLED_APPS`, and DRF settings strings.

Details: [Integration guide](https://github.com/anthonynarine/gait-sdk/blob/main/docs/INTEGRATION_GUIDE.md#upgrading-from-auth_integration).

## Documentation

| | |
|---|---|
| [Concepts](https://github.com/anthonynarine/gait-sdk/blob/main/docs/CONCEPTS.md) | Tokens, signatures, JWKS, revocation, 401/403/503, explained for newcomers |
| [Examples](https://github.com/anthonynarine/gait-sdk/tree/main/examples) | Runnable FastAPI + Django apps with a local stand-in issuer |
| [Architecture](https://github.com/anthonynarine/gait-sdk/blob/main/docs/ARCHITECTURE.md) | The boundary, components, verification & caching, trust model |
| [Integration guide](https://github.com/anthonynarine/gait-sdk/blob/main/docs/INTEGRATION_GUIDE.md) | Wiring into Django/FastAPI, JWKS cut-over runbook, sensitive actions, testing |
| [Security](https://github.com/anthonynarine/gait-sdk/blob/main/docs/SECURITY.md) | Threat model, guarantees, known limits, hardening checklist, audit log, reporting |
| [Troubleshooting](https://github.com/anthonynarine/gait-sdk/blob/main/docs/TROUBLESHOOTING.md) | Exact error messages, what they mean, and how to fix them |
| [Publishing](https://github.com/anthonynarine/gait-sdk/blob/main/docs/PUBLISHING.md) | How releases reach PyPI (a step-by-step tutorial), and consuming safely |
| [Changelog](https://github.com/anthonynarine/gait-sdk/blob/main/docs/CHANGELOG.md) | Version history |
| Module references | [`gait_sdk/docs/`](https://github.com/anthonynarine/gait-sdk/tree/main/gait_sdk/docs) |

## License

MIT, © Anthony Narine.
