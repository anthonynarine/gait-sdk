# Security

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through GitHub's *Security → Report a vulnerability* on this repository, or contact the maintainer (Anthony Narine) via GitHub. Include the affected version, reproduction steps and impact. Reports are acknowledged within 72 hours.

## Supported versions

| Version | Supported |
|---|---|
| 0.5.x | ✅ Security fixes |
| 0.4.x | ⚠️ Upgrade. Contains the issues fixed in 0.5.0 (see the audit log below). |
| < 0.4 | ❌ |

---

## What gait-sdk protects against

| Threat | Defense |
|---|---|
| Forged tokens | RS256 signature checked against Gait's published public keys. The SDK never holds a signing secret, so it can't forge tokens either. |
| Algorithm confusion (`alg=none`, HS256 signed with the public key) | The algorithm is hard-pinned to RS256. The header's `alg` is compared, never used to choose the algorithm. |
| Wrong issuer / audience / expired token | `iss` and `aud` are exact-matched; `exp` and `iat` are required, with 30 s leeway |
| Using a refresh token (or any non-access token) as an access token | `token_use` must equal `"access"` |
| Replaying a token after logout | Session-bound tokens (`sid`). `require_live_session` asks Gait live on sensitive actions. |
| Key rotation / emergency key removal | A successful key refresh *replaces* the set, so a removed `kid` is rejected immediately |
| Random-`kid` flooding to hammer Gait or stall the service | Max one forced refresh per 30 s; single-flight fetching; cached keys never wait on the network |
| Hostile or broken key endpoint | 64 KB response cap, ≤20 keys, 2 s connect timeout, no redirects; malformed or duplicate-`kid` documents rejected; non-RSA or <2048-bit keys ignored |
| Downgrade to a weaker check | None exists. JWKS failures never fall back to introspection; the verifier is chosen explicitly. |
| Credentials sent in plaintext | `GAIT_AUTH_URL` and `GAIT_JWKS_URL` must be `https` (plain `http` only for exactly `localhost`, `127.0.0.1` or `::1`). URLs with embedded credentials are rejected. Checked at startup and again before every live session call. |
| CSRF via cookies | JWKS mode is **Bearer-only**. Legacy cookie mode is off by default. |
| Misconfiguration discovered in production | Invalid or incomplete settings stop the service at **startup** (Django `AppConfig`, FastAPI `validate_configuration()`) |
| Leaking secrets in logs | No token, cookie, or credential value is logged; only the Gait *hostname* is |
| 401 silently becoming 403 (breaks client refresh) | `authenticate_header()` returns `Bearer`, so DRF sends real 401s |

## Known limits (by design)

- **Revocation window.** Local (JWKS) verification sees a revoked session only when its access token expires (≤15 min, set by Gait). Use `require_live_session` on sensitive actions. The legacy introspection path also caches results for 45 s.
- **Stale keys during a Gait outage.** A known key keeps verifying for up to 1 hour after the last successful refresh, so users aren't all logged out when Gait blips. An unknown key fails closed.
- **The SDK does not authorize.** Anything about roles, organizations or object access is your application's responsibility. The deprecated `HasRole`, `HasAnyRole` and `require_role` helpers exist only for the legacy path, and always deny under JWKS.
- **Trust in configuration.** Whoever controls your service's environment controls which Gait you trust. Protect deployment config like any other secret-bearing setting.

## Hardening checklist for consuming services

- [ ] `GAIT_TOKEN_VERIFIER=jwks`, with `GAIT_JWKS_URL`, `GAIT_ISSUER` and `GAIT_AUDIENCE` all set, and `https` URLs only
- [ ] `require_live_session` on every action you'd consider sensitive, called **after** your own authorization check
- [ ] `GAIT_ALLOW_COOKIE_AUTH` unset (off)
- [ ] `GAIT_APPLICATION_CREDENTIAL` only in environment variables, never in code or logs
- [ ] `gait-sdk` pinned to an exact version (optionally `--require-hashes`)
- [ ] Clients send `Authorization: Bearer <access token>` and keep the token in memory, not `localStorage`

---

## Audit log

### 2026-09-25: review of 0.4.1 → fixed in 0.5.0

A read-only review of all modules found **no critical or high issues**. The verification core (algorithm pinning, claim enforcement, no downgrade, fail-closed live checks) was confirmed sound. Every finding below is fixed in 0.5.0, with a regression test that reproduces the original problem (`tests/test_security_hardening_050.py`, `tests/test_django_authentication.py`).

| ID | Severity | Finding | Fix |
|---|---|---|---|
| M1 | Medium | The JWKS cache lock was held during the network fetch. A junk token with a random `kid` could force a refresh and stall **all** verifications, including cached keys, for the fetch duration. | Single-flight: the network I/O runs with no lock held; cached keys never wait. The regression test measured a 10.8 s stall on 0.4.1. |
| M2 | Medium | Cookie-based authentication had no CSRF protection | JWKS mode is Bearer-only; legacy cookie mode is off by default (`GAIT_ALLOW_COOKIE_AUTH`) |
| L1 | Low | The `http://localhost` exception was a string-prefix check (`http://localhost.evil.com` passed) | URL parsed and the exact hostname compared; embedded credentials rejected |
| L2 | Low | `GAIT_AUTH_URL` had no TLS requirement, so tokens and the app credential could travel in plaintext | `https` required (localhost excepted), at startup and on each live check |
| L3 | Low | Legacy cookie mode forwarded the 7-day refresh token (and the 2FA temp token) to `/whoami/` | Only the access token is forwarded |
| L4 | Low | The legacy bearer cache wasn't thread-safe | Guarded by a lock |
| L5 | Low | The FastAPI introspection path trusted the shape of Gait's response | Validated; a malformed response fails closed |
| L6 | Low | JWKS response size and key count were unbounded | 64 KB and 20-key caps, 2 s connect timeout |
| Info | — | The Gait URL could be logged with embedded credentials; the original Django scaffold (with a `django-insecure` dev `SECRET_KEY`) was still in the repo | Only the hostname is logged; scaffold removed (it was never packaged or used) |

**Repository hygiene (same date):** the entire git history was scanned for secrets. Apart from that scaffold dev key, no API keys, tokens, private keys, `.env` files or credentials were ever committed. Runtime dependencies had no known vulnerabilities at the versions resolved (pip-audit).

### Earlier fixes worth knowing

- **0.4.1:** the SDK no longer initializes python-decouple's global config at import time. Previously that could stop the host app from reading its own `.env`.
- **0.3.12:** `authenticate_header()` added. Before it, every invalid token came back as 403, which silently disabled client token refresh everywhere.
