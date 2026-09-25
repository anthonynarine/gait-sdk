# Testing guide for gait-sdk

## Overview
This guide describes the testing strategy used for the `gait-sdk` package.
The suite ensures correct behavior for authentication validation, exception handling,
permissions, utility helpers, and environment configuration.

---

## Test Environment Setup

The `tests/conftest.py` file initializes environment variables and mock settings so that
tests can run independently of Django. It defines safe defaults for `GAIT_AUTH_URL` and
`GAIT_TIMEOUT` and avoids `ImproperlyConfigured` errors.

All tests are executed using **pytest** with **pytest‑asyncio** enabled.

---

## Test Modules

| File | Purpose |
|------|---------|
| `test_jwks_verifier.py` | JWKS verification: token contract, algorithm pinning, key caching, rotation, cooldown, stale-key window, outage behavior |
| `test_jwks_adapters.py` | Django + FastAPI adapters under JWKS; verifier selection and startup config validation; role-helper deprecations |
| `test_session_check.py` | Live session check: active / revoked / unreachable / subject mismatch; never cached |
| `test_security_hardening_050.py` | 0.5.0 audit fixes: no lock during I/O (M1), https + exact-localhost URLs (L1/L2), FastAPI shape validation (L5), bounded JWKS (L6), host-only logging |
| `test_rename_compat_shim.py` | `auth_integration` alias returns the same `gait_sdk` modules, and warns |
| `test_django_authentication.py` | DRF adapter: introspection path, bearer cache, legacy cookie mode (opt-in, access token only), `authenticate_header()` (401 vs 403) |
| `test_dependencies.py`, `test_role_dependency_status_codes.py` | FastAPI `verify_token` and status codes |
| `test_client.py` | The async `/whoami/` client |
| `test_application.py` | Application (machine) identity |
| `test_context.py` | `SecurityContext` |
| `test_security_signal.py` | Tenant security signals |
| `test_settings.py`, `test_settings_django_unconfigured.py`, `test_settings_decouple_isolation.py` | Configuration loading; the SDK never touches decouple's global config |
| `test_permissions.py`, `test_permissions_fastapi_fallback.py`, `test_utils.py` | Deprecated role helpers (still fail closed) |
| `test_exceptions.py`, `test_integration_auth.py` | Exception codes; cross-module checks |

`_jwks_support.py` has shared helpers: test RSA keys, a fake JWKS endpoint, a fake clock, and `sign()` for building tokens in Gait's exact access-token format.

## Running Tests

```bash
pytest -v -s
```

Pytest configuration is included in `pyproject.toml`:

```toml
[tool.pytest.ini_options]
asyncio_mode = "auto"
```

---

## Coverage Goals

- 100% function coverage across all core modules.
- No external API calls — all network operations are mocked.
- Reusable test patterns for any service integrating with Gait.

---

Maintained by **Anthony Narine**, 2025
