# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and adheres to [Semantic Versioning](https://semver.org/).

> Note: entries below `0.3.9` were never backfilled here — see `git log` for the full history if you need it. The `[2.0.0]` entry that used to sit at the top of this file was from a legacy versioning scheme (the package was briefly renamed `gait_integration` and back) and didn't correspond to any real tag; removed for accuracy.

## [Unreleased] — SDK4: Tenant Security Signal Client

Not yet tagged/released. Additive only — no change to `ClaimsUser`,
`ApplicationPrincipal`, `verify_application`, `SecurityContext`, or any
existing public import path.

### Added
- `auth_integration.security.send_security_signal(*, signal_type, result, source_reference, payload=None, credential=None) -> SecuritySignalResult` — submits a customer-originated tenant security signal to Gait's `POST {GAIT_AUTH_URL}/security/tenant-signals/`, authenticated as an application via the same `Gait-Application-Credential` header and `GAIT_APPLICATION_CREDENTIAL` setting SDK2 established. No second credential concept was introduced.
- `auth_integration.security.SecuritySignalResult` — immutable receipt (`signal_id`, `control_key`, `evidence_id`, `received_at`) mirroring exactly what Gait's response contains; no invented "duplicate"/"idempotent" field, since Gait's own response doesn't distinguish a fresh signal from an idempotent replay.
- New `auth_integration.exceptions.SecuritySignalRejected` (400) — a single exception for every signal-content rejection reason (local malformed input or Gait's own 400), mirroring the backend's own deliberately-singular `TenantSignalRejected`.
- `signal_type`/`result` stay plain `str` parameters, not an SDK-side enum — Gait's own `tenant_signal_registry.py` is an explicitly growable, code-reviewed backend structure; hardcoding its contents into the SDK would create version drift for no safety benefit, since unapproved values are already rejected server-side. One convenience constant, `APPLICATION_SELF_CHECK`, is exported for the one currently-known approved value (documented as non-exhaustive).
- `auth_integration/docs/AuthIntegration_TenantSecuritySignals.md` — full contract in founder/developer-readable language: what a signal is/isn't, `CUSTOMER_REPORTED` trust semantics, idempotency via `source_reference`, allowed vs. forbidden fields, and failure behavior.
- `tests/test_security_signal.py` (44 tests): exact endpoint/header, valid/invalid/missing credential, unknown signal type, local input validation, timeout/network/malformed-response failure paths, credential/payload absence from logs and errors, a structural authority-injection proof (via `inspect.signature`) that none of Gait's own forbidden field names — `organization`, `scope`, `trust`, `control_key`, and 15 others, mirroring the backend's own strict-contract test matrix almost exactly — exist as parameters, idempotent-retry behavior (SDK never deduplicates locally, always forwards to Gait), and human-identity independence in both directions.

### Notes
- No Django/FastAPI wiring, no `SecurityContext` integration, no Observatory/findings client, and no automatic instrumentation were added — all deliberately out of scope for this milestone.
- The frozen backend contract for this milestone (`security/tenant_ingestion.py`, `tenant_signal_registry.py`, `models.py::TenantSecuritySignal`, `serializers.py`, `views.py`, and both `test_tenant_ingestion*.py` files) was inspected read-only in the Gait backend's `b-tenant1/tenant-boundary` line (tip `08a06b6`, the same commit the original SDK discovery brief named as the frozen tenancy baseline) — not guessed from this milestone's own prompt, which used slightly different terminology (`SELF_REPORTED` vs. the actual `CUSTOMER_REPORTED`) corrected here to match the real backend.

## [Unreleased] — SDK3: SecurityContext

Not yet tagged/released. Additive only — no change to `ClaimsUser`,
`ApplicationPrincipal`, `verify_token`, `verify_application`, or any
existing public import path.

### Added
- `auth_integration.context.SecurityContext` — an immutable, framework-neutral composition of an already-verified human identity (`user`) and/or application identity (`application`). Performs no verification and no Gait network call; only accepts identities already verified elsewhere.
- `SecurityContext.user` accepts either a real `ClaimsUser` instance (Django) or a raw claims dict (FastAPI's `verify_token()` never constructs a `ClaimsUser`) — checked structurally, never via `isinstance(user, ClaimsUser)`, because `ClaimsUser` currently lives in a module (`auth_integration.django.authentication`) that unconditionally imports Django/DRF; importing it for a runtime check would make `SecurityContext` require Django to import. `SecurityContext.application` is strictly `isinstance`-checked against `ApplicationPrincipal`, which has no such coupling.
- `has_user` / `has_application` presence properties — identity-presence only, deliberately not named/shaped like an authorization check.
- `auth_integration/docs/AuthIntegration_SecurityContext.md` — full contract, including the neither-identity rejection decision and why no Django/FastAPI request-integration helper was added this milestone.
- `tests/test_context.py` (20 tests): user-only/application-only/both/neither states, immutability, exact-identity preservation, absence of cross-derived fields, no-network-on-construction, credential absence from repr, and type validation for malformed local input.

### Design decisions (documented, not implemented as code changes)
- `SecurityContext()` with neither `user` nor `application` raises `ValueError` — assessed against real usage and declined as a "meaningless context object" per this milestone's own stated default.
- No Django (`request.security_context`) or FastAPI (`Depends(get_security_context)`) integration helper was added: neither framework currently has an established per-request source of `ApplicationPrincipal` (SDK2 didn't wire it in), so such a helper today could only build a human-only context automatically — not enough value over calling `SecurityContext(user=...)` directly, and it would risk implying request-lifecycle integration that doesn't exist yet.
- No `.to_dict()`/serialization was added — no current consumer need identified.

## [Unreleased] — SDK2: Application Identity

Not yet tagged/released. Additive only — no change to `ClaimsUser`, human
JWT/claims behavior, or any existing public import path.

### Added
- `auth_integration.application.ApplicationPrincipal` — an immutable, framework-neutral value object representing a Gait-verified machine/software identity (`application_id`, `application_slug`, `organization_id`, `organization_slug`, `environment`). No credential field, no human role, no Lumen-domain fields.
- `auth_integration.application.verify_application(credential=None)` — verifies a Gait `ApplicationCredential` against the frozen Gait backend endpoint `POST {GAIT_AUTH_URL}/applications/verify/`, sent via the dedicated `Gait-Application-Credential` header (never `Authorization: Bearer`). Falls back to the new `GAIT_APPLICATION_CREDENTIAL` setting when no credential is passed explicitly; raises immediately (no network call) if neither is present.
- New `auth_integration.exceptions.InvalidApplicationCredentialError` (401) — kept deliberately separate from `InvalidTokenError` (human identity failures) and deliberately a single exception (Gait's own verification response doesn't distinguish missing/unknown/revoked/expired/suspended-application reasons either).
- New `GAIT_APPLICATION_CREDENTIAL` setting, read through the existing `auth_integration.settings` loader (Django settings, then environment/`.env`) — server-side only, no default, never logged.
- `auth_integration/docs/AuthIntegration_Application_Identity.md` — full contract: `ClaimsUser` vs `ApplicationPrincipal`, credential configuration, wire format, and why organization/environment authority belongs to Gait alone (no caller override exists).
- `tests/test_application.py` (34 tests): valid/invalid/missing credential, network failure, timeout, malformed JSON, structurally-invalid responses (missing/empty/wrong-typed fields, unknown environment), `ApplicationPrincipal` construction/immutability, raw-credential absence from repr/logs/exception messages, organization/environment authority, no caller-side tenant-override parameter, and human/application identity independence in both directions.

### Fixed / Changed (SDK1 follow-ups, same milestone)
- `pyproject.toml`'s `[django]` extra now declares `Django >=4.2` explicitly instead of relying on `djangorestframework`'s own transitive dependency — `auth_integration/settings.py` directly imports `django.conf.settings`, so this is a real, direct runtime dependency of this package, not only DRF's.
- Added an end-to-end regression test (`tests/test_role_dependency_status_codes.py`) proving the FastAPI role-check flow keeps a real authentication failure (missing/invalid token → 401, `WWW-Authenticate: Bearer`) distinct from an authorization failure (authenticated but wrong role → 403) — confirmed the existing `require_role`/`verify_token` composition already behaved correctly; no production code change was needed, only the missing test.

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
