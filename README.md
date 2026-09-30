# gait-sdk

[![PyPI](https://img.shields.io/pypi/v/gait-sdk.svg)](https://pypi.org/project/gait-sdk/)
[![Python](https://img.shields.io/pypi/pyversions/gait-sdk.svg)](https://pypi.org/project/gait-sdk/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/anthonynarine/gait-sdk/blob/main/LICENSE)

The official Python SDK for **Gait**, for **Django REST Framework** and **FastAPI** services. It does two jobs:

1. **Report security checks.** Your application checks itself (for example "debug mode is off") and sends PASS or FAIL to your Gait workspace, using its connection key.
2. **Verify users** *(early access)*. When your product's users sign in with Gait, the SDK tells your API who each caller is. It never issues tokens, stores passwords, or makes authorization decisions.

```
Gait                authenticates   — who are you? (login, 2FA, sessions, signed tokens)
gait-sdk            verifies        — is this token genuine, and whose is it?
your application    authorizes      — what may this person do here?
```

![How gait-sdk works: the browser logs in to Gait, sends a Bearer token to your app, gait-sdk verifies it locally with Gait's cached public keys, your code authorizes, and sensitive actions get a live session check](https://raw.githubusercontent.com/anthonynarine/gait-sdk/main/docs/assets/how-it-works.svg)

*The diagram shows local (`jwks`) verification. See [Choosing a verifier](#choosing-a-verifier) for which mode to use today.*

That boundary is the core design rule. The SDK hands your code a verified **identity** (`subject`, `email`, and more). Roles, organizations and permissions belong to your application. See [Architecture](https://github.com/anthonynarine/gait-sdk/blob/main/docs/ARCHITECTURE.md).

### What is Gait?

**Gait** is an identity and security service at [gaitobservatory.com](https://gaitobservatory.com). Your team gets a private **workspace**: it registers each piece of software, per environment, as an **application** with its own connection key, and sees the findings those applications' security checks produce.

For sign-in, Gait handles everything about *who someone is*:
- sign-up and login;
- two-factor authentication;
- sessions, logout and "log out everywhere";
- short-lived signed access tokens.

How it fits together: [How it works](https://gaitobservatory.com/docs/how-it-works) and [People and applications](https://gaitobservatory.com/docs/people-and-applications).

> **Availability:** reporting security checks is self-service: create a workspace at [gaitobservatory.com](https://gaitobservatory.com), add an application and issue its connection key ([Quickstart](https://gaitobservatory.com/docs/quickstart)). Verifying your own product's users is in **early access**: [request it here](https://gaitobservatory.com/early-access). You can try verification end to end today with the local stand-in issuer in [`examples/`](https://github.com/anthonynarine/gait-sdk/tree/main/examples).

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
pip install gait-sdk               # core only (security checks, verification, sessions, app identity)
```

Pin exact versions in production (for example `gait-sdk==0.5.1`). See [Supply chain](https://github.com/anthonynarine/gait-sdk/blob/main/docs/PUBLISHING.md#consuming-safely).

### Compatibility

| | Supported |
|---|---|
| Python | 3.10 or later (tested on 3.10, 3.11 and 3.12) |
| Django REST Framework | Django 4.2 or later, djangorestframework 3.14 or later (the `[django]` extra) |
| FastAPI | FastAPI 0.100 or later, Starlette 0.27 or later (the `[fastapi]` extra) |
| Core | httpx 0.25 or later, python-decouple 3.6 or later |

---

## Quick start: report a security check

Any Python service. You need an application and its connection key from your Gait workspace ([Getting started](https://gaitobservatory.com/docs/getting-started)).

```bash
# Environment (the connection key is a secret: keep it out of source code)
GAIT_AUTH_URL=https://api.gaitobservatory.com/api
GAIT_APPLICATION_CREDENTIAL=<your connection key>
```

```python
import asyncio
from gait_sdk.security import APPLICATION_SELF_CHECK, send_security_signal

asyncio.run(send_security_signal(
    signal_type=APPLICATION_SELF_CHECK,
    result="FAIL",                                       # or "PASS"
    source_reference="self-check:2026-09-25T20:00Z:1",   # unique per run
    payload={"checks": {"debug_disabled": "FAIL", "hsts_enabled": "PASS"}},
))
```

The key alone decides which application, workspace and environment the result belongs to. A FAIL opens a finding; a later PASS closes it. Details: [Connecting your software](https://gaitobservatory.com/docs/connecting-your-software) and the [signal contract](https://github.com/anthonynarine/gait-sdk/blob/main/gait_sdk/docs/security_signals.md).

## Built-in checks *(0.6.0, unreleased)*

gait-sdk ships ready-made checks, so you don't have to write your own. There are three packs, 27 checks in all:

- **django** (21 checks) against your settings: DEBUG, ALLOWED_HOSTS, SECRET_KEY strength, HTTPS redirect, HSTS, secure cookies, CSRF, clickjacking, CORS, DRF default permissions, password rules, database and email TLS, and more.
- **fastapi** (5 checks) against your app object: debug, public API docs, CORS, trusted hosts, HTTPS redirect. The app is imported and read only, never started: no lifespan or startup code runs, so nothing connects to your database.
- **deps** (1 check): known-vulnerable Python packages, using pip-audit (`pip install 'gait-sdk[deps]'`) or osv-scanner.

Each check reports to Gait as its own control, so a failing check opens its own finding and a later pass closes exactly that one.

```bash
# Inside a Django project ("gait_sdk" in INSTALLED_APPS): runs the django and deps packs
python manage.py gait_check --dry-run      # see exactly what would be sent; needs no key
python manage.py gait_check                # run and report to Gait

# Or without manage.py
gait-check --pack django --settings mysite.settings --run-id "ci:$GIT_SHA:$JOB_ID"
gait-check --pack fastapi --app mypackage.main:app --pack deps
```

- **What's sent:** per check, an outcome and a few typed facts (booleans, bounded numbers, fixed choices). Never a setting value, never the SECRET_KEY, never request or database data. `--dry-run` prints every payload before you send anything.
- **Dependencies:** pip-audit / osv-scanner send your package names and versions to PyPI / OSV to look them up; Gait receives only the vulnerable packages, versions and advisory ids.
- **Environment:** comes from the connection key's application. `--environment` only asserts it (exit 3 on a mismatch). DEBUG, HTTPS and cookie checks report "not applicable" for `local` and `test` applications.
- **Delivery:** results go in batches when your Gait server supports it (one request per check otherwise, or with `--no-batch`).
- **Exit codes:** 0 clean, 1 a result at or above `--fail-on` (default `fail`), 2 delivery failed, 3 usage or configuration error. Use `--no-send` to gate CI without contacting Gait.

Every check, its rules and how to fix it: [docs/CHECKS.md](https://github.com/anthonynarine/gait-sdk/blob/main/docs/CHECKS.md).

## Quick start: verify users *(early access)*

### Django REST Framework

```python
# settings.py
INSTALLED_APPS = [..., "gait_sdk"]          # validates configuration at startup

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["gait_sdk.authentication.ExternalJWTAuthentication"],
}

GAIT_AUTH_URL = "https://api.gaitobservatory.com/api"
```

```python
# views.py
from gait_sdk.django.authentication import require_live_session

class FinalizeReport(APIView):
    def post(self, request, pk):
        identity = request.verified_identity    # subject, email (see VerifiedIdentity)
        ...                                     # YOUR authorization check first
        require_live_session(request)           # sensitive action: confirm the session is live
        ...                                     # then mutate
```

### FastAPI

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

With `GAIT_AUTH_URL` set in the environment (or `.env`).

### Choosing a verifier

Both quick starts use the default verifier, **`introspection`**: the SDK asks Gait (`/whoami/`) about the token on every request. It needs only `GAIT_AUTH_URL`, and it works with Gait today.

**`jwks`** verifies tokens locally against Gait's published signing keys, with no call to Gait per request. It needs Gait's key set (`/.well-known/jwks.json`) to list at least one key. **Check that before switching:** if the key set is empty, every token will be rejected. Then:

```python
GAIT_TOKEN_VERIFIER = "jwks"
GAIT_JWKS_URL = "https://<your Gait>/.well-known/jwks.json"
GAIT_ISSUER = "<exactly your Gait issuer>"       # Gait's JWT_ISSUER
GAIT_AUDIENCE = "<the audience Gait gives you>"  # Gait's JWT_AUDIENCE
GAIT_AUTH_URL = "https://<your Gait>/api"        # still used for live session checks
```

The mode is chosen explicitly, with **no automatic fallback** from one to the other. The cut-over runbook is in the [Integration guide](https://github.com/anthonynarine/gait-sdk/blob/main/docs/INTEGRATION_GUIDE.md).

---

## Configuration

| Setting | Default | Purpose |
|---|---|---|
| `GAIT_AUTH_URL` | — | Gait's API base (`…/api`). Used by introspection, live session checks, application identity and security checks. `https` required (plain `http` only for `localhost`). |
| `GAIT_TOKEN_VERIFIER` | `introspection` | `introspection` = ask Gait `/whoami/` on every request. `jwks` = verify locally against Gait's published keys (needs a non-empty key set; see [Choosing a verifier](#choosing-a-verifier)). |
| `GAIT_JWKS_URL` | — | Required for `jwks`. Must be `https` (plain `http` only for `localhost`). |
| `GAIT_ISSUER` | — | Required for `jwks`. Must equal Gait's `JWT_ISSUER` exactly. |
| `GAIT_AUDIENCE` | — | Required for `jwks`. Must equal Gait's `JWT_AUDIENCE`. |
| `GAIT_TIMEOUT` | `5` | Seconds for calls to Gait. |
| `GAIT_APPLICATION_CREDENTIAL` | — | Your application's connection key, for security checks and application identity. A secret: keep it in the environment. |
| `GAIT_ALLOW_COOKIE_AUTH` | `False` | Deprecated legacy cookie mode (introspection only). Leave off. See [Security](https://github.com/anthonynarine/gait-sdk/blob/main/docs/SECURITY.md). |

Settings come from Django settings first, then environment variables / `.env`. An invalid or incomplete configuration **stops the service at startup** (`AuthConfigurationError`).

---

## Reference

The public API. Everything else is internal and may change. Module-level detail: [`gait_sdk/docs/`](https://github.com/anthonynarine/gait-sdk/tree/main/gait_sdk/docs).

### Security checks: `gait_sdk.security`

```python
async def send_security_signal(*, signal_type: str, result: str, source_reference: str,
                               payload: Optional[dict] = None, credential: Optional[str] = None) -> SecuritySignalResult: ...
```

Sends one security check result to Gait (`POST {GAIT_AUTH_URL}/security/tenant-signals/`), authenticated with the connection key in the `Gait-Application-Credential` header.

- `signal_type`: an approved signal type. `APPLICATION_SELF_CHECK` is exported for the one known today.
- `result`: `"PASS"`, `"FAIL"`, `"WARNING"` or `"INFORMATIONAL"` (`KNOWN_RESULTS`). Gait makes the final check.
- `source_reference`: unique per run. Resending the same one is safe: Gait treats it as the same report.
- `payload`: optional details, such as each check's result.
- `credential`: defaults to `GAIT_APPLICATION_CREDENTIAL`.
- **Returns** `SecuritySignalResult(signal_id, control_key, evidence_id, received_at)`, frozen.
- **Raises** `SecuritySignalRejected` (400, bad content), `InvalidApplicationCredentialError` (401, missing or rejected key), `AuthServiceUnavailable` (503).

### Verifying users: DRF, `gait_sdk.authentication`

- **`ExternalJWTAuthentication`**: the DRF authentication class. It reads the `Authorization: Bearer` token, verifies it with the configured verifier, sets `request.user` to a `ClaimsUser` and `request.verified_identity` to a `VerifiedIdentity`. Failures are real **401**s with `WWW-Authenticate: Bearer`, so clients' refresh-on-401 works. It returns 503 if Gait can't be reached.
- **`ClaimsUser(id, email, role, first_name, last_name)`**: a lightweight, frozen user. `is_authenticated` is True. Under `jwks`, `role`, `first_name` and `last_name` are `""`: Gait's tokens carry identity only.
- **`gait_sdk.django.authentication.require_live_session(request) -> None`**: confirms with Gait that the caller's session is still live. Use it before sensitive actions. It raises 401 if revoked, and 503 if Gait can't confirm.

### Verifying users: FastAPI, `gait_sdk.fastapi.dependencies`

- **`verify_token`** (dependency) `-> dict`: verified claims, with `"id"` and `"email"` in both modes. 401 on a bad token, 503 if Gait is unreachable.
- **`require_live_session`** (dependency) `-> dict`: `verify_token` plus a live session check.
- **`validate_configuration() -> None`**: call at startup. It raises `AuthConfigurationError` on bad settings.
- **`get_current_user(request) -> dict`**: the claims `verify_token` attached to `request.state.user`.

### Verification core: `gait_sdk.verification` and `gait_sdk.session`

- **`VerifiedIdentity`**, frozen: `subject`, `email`, `session_id`, `token_id`, `issuer`, `source` (`"jwks"` or `"introspection"`). Under introspection, `session_id`, `token_id` and `issuer` are `None`.
- **`get_token_verifier() -> TokenVerifier`**: the configured verifier (`JwksVerifier` or `IntrospectionVerifier`). **`set_token_verifier(verifier)`** replaces it, for tests.
- **`check_session_live(token, *, expected_subject=None) -> None`** and **`async acheck_session_live(...)`**: the framework-free live session check. They raise `InvalidTokenError` (401) if revoked or expired, and `AuthServiceUnavailable` (503) if Gait can't confirm. There is no fail-open path.

### Application identity: `gait_sdk.application`

- **`async verify_application(credential: Optional[str] = None) -> ApplicationPrincipal`**: asks Gait which application a connection key belongs to (defaults to `GAIT_APPLICATION_CREDENTIAL`).
- **`ApplicationPrincipal(application_id, application_slug, organization_id, organization_slug, environment)`**, frozen. `organization_*` is your Gait workspace.
- **Raises** `InvalidApplicationCredentialError` (401), `AuthServiceUnavailable` (503).

### Combining identities: `gait_sdk.context`

- **`SecurityContext(user=None, application=None)`**, frozen: an already-verified human identity and/or `ApplicationPrincipal`. It makes no network call. It needs at least one of the two (otherwise `ValueError`). Use `has_user` and `has_application` to check which is present.

### Exceptions: `gait_sdk.exceptions`

| Exception | Status | When |
|---|---|---|
| `InvalidTokenError` | 401 | The token is invalid or expired, or the session was revoked. |
| `InvalidApplicationCredentialError` | 401 | The connection key is missing or rejected. |
| `SecuritySignalRejected` | 400 | A security check's content is malformed or unapproved. |
| `AuthServiceUnavailable` | 503 | Gait is unreachable, times out, or answers unexpectedly. |
| `AuthConfigurationError` | — | Bad or incomplete settings, raised at startup. |

When Django REST Framework is installed, the ones with a status are DRF `APIException`s, so DRF views return that status directly. Without DRF, they're plain exceptions that carry the same `status_code`.

### Deprecated

- `HasRole`, `HasAnyRole`, `require_role`, and `gait_sdk.utils.get_user_role` / `is_admin` / `is_physician` / `is_technologist`: authorization belongs to your application. Under `jwks` the role is always `""`, so they always deny.
- The `auth_integration` import name: see [Upgrading](#upgrading-from-auth_integration).

## Security, in one screen

- **The SDK holds no secrets for verification.** In `jwks` mode it only ever has Gait's *public* keys, so it can't mint tokens even if compromised.
- **`jwks` mode is strict.** RS256 only: `alg=none`, HS256 key confusion and unknown algorithms are rejected. `iss`, `aud`, `exp`, `iat`, `sub`, `sid`, `jti` and `token_use="access"` are all required.
- **Fails closed.** An invalid token gets **401**. If Gait is needed and can't be reached, **503**. It never falls back to a weaker check.
- **Real 401s** (not DRF's silent 403), so clients' refresh-on-401 logic works.
- **Revocation.** `introspection` asks Gait on every request. `jwks` sees a revoked session only when its token expires (≤15 min), so protect sensitive actions with `require_live_session`.
- **No token, cookie or credential value is ever logged.**

Full threat model, guarantees, limits and audit history: [docs/SECURITY.md](https://github.com/anthonynarine/gait-sdk/blob/main/docs/SECURITY.md). To report a vulnerability, see the same file.

---

## Upgrading from `auth_integration`

The package was renamed in **0.5.0**. The old import name still works as a deprecated alias (it will be removed in a future release), returning the *same* modules, so nothing breaks while you migrate:

1. `pip install gait-sdk` (replacing the old git URL pin).
2. Replace `auth_integration` with `gait_sdk` in imports, `INSTALLED_APPS`, and DRF settings strings.

Details: [Integration guide](https://github.com/anthonynarine/gait-sdk/blob/main/docs/INTEGRATION_GUIDE.md#upgrading-from-auth_integration).

## Documentation

| | |
|---|---|
| [Gait docs](https://gaitobservatory.com/docs) | Gait itself: workspaces, applications and connection keys, security checks and findings, [gait-sdk](https://gaitobservatory.com/docs/gait-sdk) |
| [Built-in checks](https://github.com/anthonynarine/gait-sdk/blob/main/docs/CHECKS.md) | Every check in the django, fastapi and deps packs: what it checks, pass/fail rules, how to fix it, what's sent, CI and scheduling |
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
