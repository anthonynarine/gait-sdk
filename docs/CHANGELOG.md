# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and adheres to [Semantic Versioning](https://semver.org/).

> Note: entries below `0.3.9` were never backfilled here — see `git log` for the full history if you need it. The `[2.0.0]` entry that used to sit at the top of this file was from a legacy versioning scheme (the package was briefly renamed `gait_integration` and back) and didn't correspond to any real tag; removed for accuracy.

## [Unreleased] — SDK1: Foundation Hardening

Not yet tagged/released — see the SDK1 report for full context. No version
bump, no JWT/claims-shape/backward-compatibility change for existing Lumen
callers.

### Fixed
- `pyproject.toml` declared dependencies now match actual runtime imports: `httpx` added as a core dependency (was used but undeclared); new `[django]`/`[fastapi]`/`[test]` optional-dependency extras declare `djangorestframework`/`asgiref` and `fastapi`/`starlette` explicitly (previously undeclared, working only because consumers happened to install them separately). `requests`/`PyJWT` deliberately left in place pending a separately-reviewed removal — see the SDK1 report.
- `auth_integration.fastapi.dependencies.get_current_user()` previously always returned `{}` because nothing set `request.state.user` — `verify_token()` now attaches the verified claims to `request.state.user` so the two stay consistent.
- `auth_integration.fastapi.dependencies.verify_token()` now returns `WWW-Authenticate: Bearer` on every 401, matching the Django adapter's contract.
- `auth_integration.permissions`' FastAPI/DRF-less fallback (`require_role`, `HasRole`, `HasAnyRole`) previously granted access unconditionally (`return True` / no-op passthrough) whenever DRF wasn't installed. Now fails closed in every case — missing claims, non-dict claims, or a role mismatch all deny.
- `auth_integration/utils.py` no longer hard-imports `django.http.HttpRequest` at runtime — it's now a `TYPE_CHECKING`-only import, so this module (and the package's generic surface) can be imported in a Django-less environment.

### Changed
- `role` is now typed/validated as a generic non-empty string rather than `Literal["admin", "physician", "technologist"]` — this package no longer bakes Lumen's specific role vocabulary into its identity contract. Lumen's existing role values continue to work unchanged; `is_admin`/`is_physician`/`is_technologist` in `utils.py` remain as documented backward-compatibility helpers, not the SDK's role model.
- `django/authentication.py::_validate_claims_shape` now also rejects non-string/empty values for `id`, `email`, `first_name`, `last_name` (previously only checked key presence) — malformed-but-present claim data now fails closed instead of silently passing through.
- CI (`python-tests.yml`) installs via the package's own declared extras (`pip install -e ".[django,fastapi,test]"`) instead of a hand-picked package list, and adds a separate clean-install verification job proving `auth_integration`, `auth_integration[django]`, and `auth_integration[fastapi]` each install and import correctly on their own.

### Added
- Regression tests for `authenticate_header() == "Bearer"`, malformed/wrong-typed claims, `httpx.TimeoutException` handling (Bearer and cookie mode), and the Bearer-mode TTL cache (hit/miss/expiry/non-raw-token cache key).
- A real automated test suite for the FastAPI adapter (`tests/test_dependencies.py`, previously empty) and for the permissions fallback branch (`tests/test_permissions_fastapi_fallback.py`, new).

## [0.3.12] - 2026-07-26

### Fixed
- **`ExternalJWTAuthentication` silently returned 403 instead of 401 for auth failures.** DRF rewrites `AuthenticationFailed`/`NotAuthenticated` from 401 to 403 whenever no authenticator advertises a `WWW-Authenticate` header. Added `authenticate_header()` returning `"Bearer"`, so DRF stops downgrading the status. This had been silently disabling every consuming service's token-refresh-on-401 logic — see the root `README.md`'s "Correctness guarantee" section for the full story.

## [0.3.11] - 2026-01-05

### Fixed
- Settings loader when Django is unconfigured; kept `_is_django` alias for backward compatibility.

## [0.3.10] - 2026-01-05

### Changed
- Made package imports framework-agnostic — no FastAPI import path triggered when running under Django.

## [0.3.9] - 2026-01-05

### Added
- DRF auth adapter test coverage (`test_django_authentication.py`).
