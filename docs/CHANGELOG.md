# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and adheres to [Semantic Versioning](https://semver.org/).

> Note: entries below `0.3.9` were never backfilled here — see `git log` for the full history if you need it. The `[2.0.0]` entry that used to sit at the top of this file was from a legacy versioning scheme (the package was briefly renamed `gait_integration` and back) and didn't correspond to any real tag; removed for accuracy.

## [Unreleased]

## [0.5.4] - 2026-10-07

Hygiene release: CI supply chain, dependencies, logging and two docs fixes.
No change to verification behaviour.

### Removed
- **GAIT-SEC-033 (info): `requests` is no longer a runtime dependency.** It
  was declared in `pyproject.toml` but never imported by the package (the
  HTTP client is `httpx`). **If your project used `requests` without
  declaring it, because it arrived transitively with gait-sdk, add it to your
  own dependencies before upgrading.** Covered by `tests/test_hygiene_054.py`
  (no source file imports it; every module imports with it unavailable) and a
  CI check that a core install does not contain it.

### Changed
- **GAIT-SEC-034 (low): library loggers no longer force a level.** Five
  modules (`client`, `security`, `application`, `settings`,
  `fastapi.dependencies`) called `setLevel(INFO)` on their loggers, which
  overrode the host application's logging configuration. They now leave the
  level `NOTSET`, so your configuration decides what is emitted. The
  `gait_sdk` package logger gets a `NullHandler`, the standard library
  practice. If you relied on gait-sdk INFO records appearing without
  configuring logging, set the level yourself, for example
  `logging.getLogger("gait_sdk").setLevel(logging.INFO)`.

### Security
- **GAIT-SEC-032 (medium): CI and release workflows pin actions by commit.**
  Every third-party action in `.github/workflows/` is pinned to a full
  40-character commit SHA (the release tag is in a trailing comment),
  including the PyPI publish action, which was referenced by a moving branch.
  Workflows default to `contents: read`; `id-token: write` is granted only to
  the publish job. `.github/dependabot.yml` proposes weekly updates for
  GitHub Actions and pip. A test fails if any `uses:` is not SHA-pinned.
- **GAIT-SEC-080 (low): the workflow hygiene test now checks permissions
  structurally.** `tests/test_hygiene_054.py` missed job-level permission
  escalation (it matched lines of text). It now parses `.github/workflows/`
  as YAML, flow-style mappings included, and requires every job's effective
  permissions to be at most `contents: read`, except the `publish` job, which
  must be exactly `id-token: write` (optionally plus `contents: read`).
  `read-all`, `write-all`, any other write scope, and the
  `pull_request_target` / `workflow_run` triggers fail the test. Each rule is
  also tested against mutated copies of the workflows. PyYAML joins the
  `[test]` extra.
- **GAIT-SEC-081 (info): CI checkouts no longer keep the job token.** Every
  `actions/checkout` step sets `persist-credentials: false`; the test
  requires it.
- **GAIT-SEC-082 (info): release build tools are hash-pinned.** The publish
  and test build jobs installed `build` and `twine` unpinned. They now install
  `.github/requirements/release.txt` (exact versions with SHA-256 hashes,
  including the `setuptools` build backend) with `pip install
  --require-hashes`, and build with `python -m build --no-isolation`, so the
  build fetches nothing unpinned. Dependabot watches that file weekly; the
  test requires all of it.
- **GAIT-SEC-083 (info): `gait_sdk/django/authentication.py` module docstring
  corrected (docs only).** It described cookie forwarding as the production
  mode. Cookie mode is legacy: introspection-only, deprecated, off by default
  (`GAIT_ALLOW_COOKIE_AUTH`), and it forwards only the `access_token` cookie;
  JWKS mode reads the Bearer header only.
- **GAIT-SEC-031 (low): `gait_sdk/docs/verification.md` corrected (docs only).**
  It said JWKS mode in Django reads the `access_token` cookie as a fallback.
  It does not: JWKS mode reads the `Authorization: Bearer` header only. Legacy
  cookie mode exists only on the introspection path, is deprecated and
  off by default (`GAIT_ALLOW_COOKIE_AUTH`).

## [0.5.3] - 2026-10-07

Security fixes in the deprecated role helpers (`gait_sdk.permissions`,
`gait_sdk.utils`). Read "Changed" before upgrading if you use them.

### Security
- **GAIT-SEC-029 (high): `require_role` no longer passes through when DRF is installed.**
  It used to return the route function unchanged whenever `rest_framework` was
  importable, so a FastAPI or plain route in an environment that also had DRF
  installed was never role-checked. `require_role` now has one implementation
  that always enforces against the route's `claims` keyword argument (403 on
  mismatch), for both `async def` and `def` routes. When it cannot enforce it
  raises at decoration time instead of passing through: `RuntimeError` if
  FastAPI is not installed, `TypeError` if it decorates a non-function.
  The deprecation warning is unchanged.
- **GAIT-SEC-056 (low): role helpers deny an empty or missing role.**
  `HasRole`, `HasAnyRole`, `require_role` and `gait_sdk.utils.is_admin` /
  `is_physician` / `is_technologist` deny when the user's role is missing,
  not a string, or empty/blank. `get_user_role` returns `None` for such a role,
  and `get_user_claims` returns `{}` when `user_claims` is not a dict.
  Construction now rejects bad arguments:
  - `HasRole(...)` / `require_role(...)`: an empty or blank role raises `ValueError`, a non-string raises `TypeError`.
  - `HasAnyRole(...)`: a bare string (which made the check a substring test) or a non-collection raises `TypeError`; an empty collection or an empty/blank entry raises `ValueError`; a non-string entry raises `TypeError`.
  - Covered by `tests/test_role_helpers_fail_closed.py`, which runs with DRF and FastAPI installed together.
- **GAIT-SEC-071 (low): the documented DRF usage is corrected (docs only).**
  The docs showed an instance in `permission_classes`
  (`permission_classes = [HasRole(...)]`), which fails the request: DRF
  instantiates each entry with no arguments. Use the class form, which works
  on 0.5.2 and 0.5.3 alike:
  ```python
  class PhysicianRole(HasRole):
      def __init__(self):
          super().__init__("physician")

  permission_classes = [PhysicianRole]
  ```
  These classes, and any subclass, are for DRF `permission_classes` only;
  never use them with FastAPI's `Depends()` (GAIT-SEC-074, GAIT-SEC-075).
  Covered by `tests/test_permissions_documented_usage.py`: a real DRF view
  using this form allows the right role and answers 403 (never 500) for a
  wrong, empty, blank, padded or missing role and for missing claims.
- **GAIT-SEC-074 (medium): `HasRole`/`HasAnyRole` must never become FastAPI
  dependencies.** An unreleased change in this cycle (DRF-shaped classes in
  `gait_sdk/permissions.py`, missing authorization check) let FastAPI accept
  them in `Depends()` without a role check. It was reverted before release,
  so FastAPI refuses such a route at registration. A regression test, run with DRF and FastAPI installed
  together, fails if `Depends(HasRole(...))` or `Depends(HasAnyRole([...]))`
  ever answers 200. Never pass these classes to `Depends()`; use an
  application-owned dependency.
- **GAIT-SEC-075 (low): `HasRole`/`HasAnyRole` classes and subclasses are
  refused as FastAPI dependencies.** Older than this release
  (`gait_sdk/permissions.py`, missing authorization check): FastAPI's
  `Depends()` accepted the classes themselves and any subclass, including
  the documented no-argument DRF subclass, and constructed them without a
  role check. Both classes now carry a signature FastAPI cannot satisfy, so
  it refuses such a route at registration (with or without DRF installed);
  DRF `permission_classes` is unaffected. Neither the classes nor any
  subclass may be used with `Depends()`: they are for DRF only. FastAPI apps
  use an application-owned dependency or `require_role` in the documented
  order. The regression test covers instances, the classes and subclasses,
  in route `dependencies=` and as a parameter default.
- **GAIT-SEC-070 (low): `require_role` decorator order documented.** It must
  sit below the FastAPI route decorator (`@app.get(...)` on top); placed
  above it, the route FastAPI registers is not role-checked. Not a
  regression. The docs now recommend an application-owned `Depends()` role
  check, which has no ordering pitfall. The documented order and the
  `Depends()` pattern are pinned by tests.

### Changed (behaviour apps must know about)
- **`@require_role(...)` on a DRF view, or anywhere outside FastAPI, no longer
  silently allows.** Code that used it on a DRF view relied on it being a no-op.
  It now enforces (403 unless the route's `claims` keyword argument carries the
  role), and raises `RuntimeError` at import/decoration time if FastAPI is not
  installed. For DRF views, list a `HasRole` subclass in `permission_classes`
  (the class form shown under GAIT-SEC-071 above).
- **`HasAnyRole("admin")` (a string instead of a list) now raises `TypeError`**
  instead of silently doing a substring match; pass `["admin"]`.
- A user with an empty or missing role is denied by every role helper.

### Documentation
- `gait_sdk/docs/permissions.md`: working DRF (class form) and FastAPI
  patterns; never use `HasRole`/`HasAnyRole` or any subclass with `Depends()`
  (GAIT-SEC-074, GAIT-SEC-075);
  the required `require_role` order (GAIT-SEC-070); `HasRole`/`HasAnyRole` take
  their DRF shape whenever DRF is importable, even in FastAPI code
  (GAIT-SEC-072); `require_role` trusts the route's `claims` argument, which
  must come from `Depends(verify_token)` (GAIT-SEC-073).

## [0.5.2] - 2026-10-06

Bug fix: the DRF introspection path now accepts Gait's real `/whoami/` response and its token contract.
This release also carries the documentation changes listed under "Changed".

### Fixed
- **Every request failed with 401 "Invalid authentication response." against real Gait.**
  `_validate_claims_shape` (`gait_sdk.django.authentication`) required every
  field to be a non-empty string, but Gait's `/whoami/` sends `id` as a JSON
  number (its integer primary key) and allows empty profile names.
  - `id` now accepts a non-empty string or an int (never a `bool`) and is
    normalized to `str(id)`, so consumers and the JWKS path's `sub` see the
    same string.
  - `email` remains fail-closed (missing, empty or wrong type is rejected).
  - `role`, `first_name` and `last_name` are optional: a missing field becomes
    `""`, and a present one must be a string (empty allowed). This follows
    Gait's token contract, where `sub` is the only identity key and `role` is
    being removed from `/whoami/`. `ClaimsUser` now has the same shape whether
    the verifier is `introspection` or `jwks`.
  - The validated claims are a copy; the input dict is not mutated.
  - The FastAPI adapter and the JWKS path were not affected.
  - Covered by `tests/test_claims_shape_gait_whoami.py`, including an
    end-to-end `ExternalJWTAuthentication` test with a Gait-shaped body.

### Changed
- **README:** covers both jobs. Reporting security checks now has its own quick start, and verifying users is marked early access.
  - The user quick starts use the default `introspection` verifier. A new "Choosing a verifier" section explains that `jwks` needs Gait's key set to list at least one key.
  - New: a compatibility table and a full reference of the public API (signatures, returns, exceptions).
  - Links to Gait's docs at gaitobservatory.com.
  - The availability note is current: reporting security checks is self-service, and verifying users is early access.
  - The pinning example is now `0.5.1`.
- **Security guide:** `GAIT_TOKEN_VERIFIER=jwks` moved out of the hardening checklist into a note: switch once Gait's key set lists at least one key. An https `GAIT_AUTH_URL` item takes its place.
- **Changelog:** the 0.4.0 entry no longer says its parts are unreleased (they shipped in 0.4.0). Added compare links, and fixed a pointer to a README section that no longer exists.

## [0.5.1] - 2026-09-25

Documentation release. No code changes: behavior is identical to 0.5.0.

### Added
- **"How gait-sdk works" diagram** (`docs/assets/how-it-works.svg`) at the top of the README (now also on PyPI), plus sequence diagrams for a normal request, a sensitive action and key rotation in `docs/ARCHITECTURE.md`.
- **`docs/CONCEPTS.md`**: tokens, signatures and JWKS, local vs live verification, revocation, access vs refresh tokens, 401/403/503, issuer/audience/subject, in plain language.
- **`examples/`**: runnable FastAPI and single-file Django apps, plus `dev_issuer.py` (a local stand-in for Gait that signs tokens in Gait's exact format and serves a JWKS). Verified against `gait-sdk` installed from PyPI.
- **`docs/TROUBLESHOOTING.md`**: the SDK's exact error messages, their causes and fixes.
- README: "What is Gait?", an availability note, and a "New here? Start here" path.

## [0.5.0] - 2026-09-25

First release on PyPI, under a new name. **Upgrade guide:** `docs/INTEGRATION_GUIDE.md#upgrading-from-auth_integration`.

### Changed
- **Renamed:** package `auth_integration` → **`gait_sdk`**, distribution → **`gait-sdk`** (`pip install gait-sdk`). The repository is now `anthonynarine/gait-sdk`. Logger names are `gait_sdk.*`, and the Django app is `"gait_sdk"` (`GaitSdkConfig`, no models).
- **Published to PyPI** via GitHub Actions Trusted Publishing (`.github/workflows/publish.yml`), tag-triggered, with a manual approval gate. No stored upload credentials.
- `requires-python` is now `>=3.10`, matching the CI matrix (3.10–3.12).
- **JWKS mode is Bearer-only:** cookies are never read.
- **Legacy cookie mode is off by default:** enable it with `GAIT_ALLOW_COOKIE_AUTH=True` (deprecated). It now forwards only `access_token` to Gait.
- `GAIT_AUTH_URL` and `GAIT_JWKS_URL` must be `https` (plain http only for exactly `localhost` / `127.0.0.1` / `::1`); URLs with embedded credentials are rejected. Validated at startup.

### Deprecated
- `import auth_integration` (and every `auth_integration.*` path, DRF setting string and `INSTALLED_APPS` entry) still works through a compatibility alias that returns the **same** module objects, and emits `DeprecationWarning`. **Removed in 0.6.0.**

### Security
Fixes for every finding of the 0.4.1 review (see `docs/SECURITY.md` → Audit log): M1 JWKS lock held during network I/O (single-flight fetching; cached keys never block); M2 cookie auth without CSRF protection; L1 localhost prefix bypass; L2 no TLS requirement on `GAIT_AUTH_URL`; L3 refresh token forwarded in cookie mode; L4 unsynchronized bearer cache; L5 unvalidated FastAPI introspection body; L6 unbounded JWKS response (64 KB / 20 keys). The Gait URL is now logged as a hostname only. Removed the original Django scaffold (`core/`, `manage.py`).

### Removed
- Obsolete repo files: `rename_package.sh`, `bump_version.sh` (releases now go through the publish workflow), the root `requirements.txt` dev snapshot, and `Flow-Diagram.md` (a Lumen workflow diagram that belongs in Lumen).

## [0.4.1] - 2026-09-24

### Fixed
- The SDK no longer initializes python-decouple's **global** `config` at import time. It uses a private `AutoConfig` rooted at the working directory. Previously, importing the SDK before the host app read its own settings could make the host's `config("DATABASE_URL")` fail.

## [0.4.0] - 2026-09-24

Module paths in this entry use the package's name at the time, `auth_integration`. Since 0.5.0 it's `gait_sdk`.

### Added
- **Local token verification:** `gait_sdk.verification` (then `auth_integration.verification`), with a `TokenVerifier` protocol, `JwksVerifier` (RS256 against Gait's JWKS: pinned algorithm, required `iss`/`aud`/`exp`/`iat`/`sub`/`sid`/`jti`/`token_use`, 30 s leeway, key caching with forced-refresh cooldown and a bounded stale window) and `IntrospectionVerifier` (the legacy `/whoami/` path, still the default). Both return **`VerifiedIdentity`**. Selected explicitly via `GAIT_TOKEN_VERIFIER`, never falling back from one to the other.
- **Live session check** (hybrid revocation): `check_session_live` / `acheck_session_live`, Django `require_live_session(request)`, FastAPI `require_live_session` dependency.
- Startup configuration validation (Django `AppConfig`, FastAPI `validate_configuration()`).

### Changed
- Under JWKS, `ClaimsUser.role/first_name/last_name` are `""`: Gait's RS256 tokens carry identity only.

### Deprecated
- `HasRole`, `HasAnyRole`, `require_role`, `utils.get_user_role/is_admin/is_physician/is_technologist`. Authorization belongs to the consuming app.

### Included in 0.4.0 — SDK4: Tenant Security Signal Client

Additive only — no change to `ClaimsUser`,
`ApplicationPrincipal`, `verify_application`, `SecurityContext`, or any
existing public import path.

### Added
- `auth_integration.security.send_security_signal(*, signal_type, result, source_reference, payload=None, credential=None) -> SecuritySignalResult` — submits a customer-originated tenant security signal to Gait's `POST {GAIT_AUTH_URL}/security/tenant-signals/`, authenticated as an application via the same `Gait-Application-Credential` header and `GAIT_APPLICATION_CREDENTIAL` setting SDK2 established. No second credential concept was introduced.
- `auth_integration.security.SecuritySignalResult` — immutable receipt (`signal_id`, `control_key`, `evidence_id`, `received_at`) mirroring exactly what Gait's response contains; no invented "duplicate"/"idempotent" field, since Gait's own response doesn't distinguish a fresh signal from an idempotent replay.
- New `auth_integration.exceptions.SecuritySignalRejected` (400) — a single exception for every signal-content rejection reason (local malformed input or Gait's own 400), mirroring the backend's own deliberately-singular `TenantSignalRejected`.
- `signal_type`/`result` stay plain `str` parameters, not an SDK-side enum — Gait's own `tenant_signal_registry.py` is an explicitly growable, code-reviewed backend structure; hardcoding its contents into the SDK would create version drift for no safety benefit, since unapproved values are already rejected server-side. One convenience constant, `APPLICATION_SELF_CHECK`, is exported for the one currently-known approved value (documented as non-exhaustive).
- `auth_integration/docs/security_signals.md` — full contract in founder/developer-readable language: what a signal is/isn't, `CUSTOMER_REPORTED` trust semantics, idempotency via `source_reference`, allowed vs. forbidden fields, and failure behavior.
- `tests/test_security_signal.py` (44 tests): exact endpoint/header, valid/invalid/missing credential, unknown signal type, local input validation, timeout/network/malformed-response failure paths, credential/payload absence from logs and errors, a structural authority-injection proof (via `inspect.signature`) that none of Gait's own forbidden field names — `organization`, `scope`, `trust`, `control_key`, and 15 others, mirroring the backend's own strict-contract test matrix almost exactly — exist as parameters, idempotent-retry behavior (SDK never deduplicates locally, always forwards to Gait), and human-identity independence in both directions.

### Notes
- No Django/FastAPI wiring, no `SecurityContext` integration, no Observatory/findings client, and no automatic instrumentation were added — all deliberately out of scope for this milestone.
- The frozen backend contract for this milestone (`security/tenant_ingestion.py`, `tenant_signal_registry.py`, `models.py::TenantSecuritySignal`, `serializers.py`, `views.py`, and both `test_tenant_ingestion*.py` files) was inspected read-only in the Gait backend's `b-tenant1/tenant-boundary` line (tip `08a06b6`, the same commit the original SDK discovery brief named as the frozen tenancy baseline) — not guessed from this milestone's own prompt, which used slightly different terminology (`SELF_REPORTED` vs. the actual `CUSTOMER_REPORTED`) corrected here to match the real backend.

### Included in 0.4.0 — SDK3: SecurityContext

Additive only — no change to `ClaimsUser`,
`ApplicationPrincipal`, `verify_token`, `verify_application`, or any
existing public import path.

### Added
- `auth_integration.context.SecurityContext` — an immutable, framework-neutral composition of an already-verified human identity (`user`) and/or application identity (`application`). Performs no verification and no Gait network call; only accepts identities already verified elsewhere.
- `SecurityContext.user` accepts either a real `ClaimsUser` instance (Django) or a raw claims dict (FastAPI's `verify_token()` never constructs a `ClaimsUser`) — checked structurally, never via `isinstance(user, ClaimsUser)`, because `ClaimsUser` currently lives in a module (`auth_integration.django.authentication`) that unconditionally imports Django/DRF; importing it for a runtime check would make `SecurityContext` require Django to import. `SecurityContext.application` is strictly `isinstance`-checked against `ApplicationPrincipal`, which has no such coupling.
- `has_user` / `has_application` presence properties — identity-presence only, deliberately not named/shaped like an authorization check.
- `auth_integration/docs/context.md` — full contract, including the neither-identity rejection decision and why no Django/FastAPI request-integration helper was added this milestone.
- `tests/test_context.py` (20 tests): user-only/application-only/both/neither states, immutability, exact-identity preservation, absence of cross-derived fields, no-network-on-construction, credential absence from repr, and type validation for malformed local input.

### Design decisions (documented, not implemented as code changes)
- `SecurityContext()` with neither `user` nor `application` raises `ValueError` — assessed against real usage and declined as a "meaningless context object" per this milestone's own stated default.
- No Django (`request.security_context`) or FastAPI (`Depends(get_security_context)`) integration helper was added: neither framework currently has an established per-request source of `ApplicationPrincipal` (SDK2 didn't wire it in), so such a helper today could only build a human-only context automatically — not enough value over calling `SecurityContext(user=...)` directly, and it would risk implying request-lifecycle integration that doesn't exist yet.
- No `.to_dict()`/serialization was added — no current consumer need identified.

### Included in 0.4.0 — SDK2: Application Identity

Additive only — no change to `ClaimsUser`, human
JWT/claims behavior, or any existing public import path.

### Added
- `auth_integration.application.ApplicationPrincipal` — an immutable, framework-neutral value object representing a Gait-verified machine/software identity (`application_id`, `application_slug`, `organization_id`, `organization_slug`, `environment`). No credential field, no human role, no Lumen-domain fields.
- `auth_integration.application.verify_application(credential=None)` — verifies a Gait `ApplicationCredential` against the frozen Gait backend endpoint `POST {GAIT_AUTH_URL}/applications/verify/`, sent via the dedicated `Gait-Application-Credential` header (never `Authorization: Bearer`). Falls back to the new `GAIT_APPLICATION_CREDENTIAL` setting when no credential is passed explicitly; raises immediately (no network call) if neither is present.
- New `auth_integration.exceptions.InvalidApplicationCredentialError` (401) — kept deliberately separate from `InvalidTokenError` (human identity failures) and deliberately a single exception (Gait's own verification response doesn't distinguish missing/unknown/revoked/expired/suspended-application reasons either).
- New `GAIT_APPLICATION_CREDENTIAL` setting, read through the existing `auth_integration.settings` loader (Django settings, then environment/`.env`) — server-side only, no default, never logged.
- `auth_integration/docs/application.md` — full contract: `ClaimsUser` vs `ApplicationPrincipal`, credential configuration, wire format, and why organization/environment authority belongs to Gait alone (no caller override exists).
- `tests/test_application.py` (34 tests): valid/invalid/missing credential, network failure, timeout, malformed JSON, structurally-invalid responses (missing/empty/wrong-typed fields, unknown environment), `ApplicationPrincipal` construction/immutability, raw-credential absence from repr/logs/exception messages, organization/environment authority, no caller-side tenant-override parameter, and human/application identity independence in both directions.

### Fixed / Changed (SDK1 follow-ups, same milestone)
- `pyproject.toml`'s `[django]` extra now declares `Django >=4.2` explicitly instead of relying on `djangorestframework`'s own transitive dependency — `auth_integration/settings.py` directly imports `django.conf.settings`, so this is a real, direct runtime dependency of this package, not only DRF's.
- Added an end-to-end regression test (`tests/test_role_dependency_status_codes.py`) proving the FastAPI role-check flow keeps a real authentication failure (missing/invalid token → 401, `WWW-Authenticate: Bearer`) distinct from an authorization failure (authenticated but wrong role → 403) — confirmed the existing `require_role`/`verify_token` composition already behaved correctly; no production code change was needed, only the missing test.

### Included in 0.4.0 — SDK1: Foundation Hardening

No JWT/claims-shape/backward-compatibility change for existing Lumen
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
- **`ExternalJWTAuthentication` silently returned 403 instead of 401 for auth failures.** DRF rewrites `AuthenticationFailed`/`NotAuthenticated` from 401 to 403 whenever no authenticator advertises a `WWW-Authenticate` header. Added `authenticate_header()` returning `"Bearer"`, so DRF stops downgrading the status. This had been silently disabling every consuming service's token-refresh-on-401 logic — see `docs/SECURITY.md` → Audit log.

## [0.3.11] - 2026-01-05

### Fixed
- Settings loader when Django is unconfigured; kept `_is_django` alias for backward compatibility.

## [0.3.10] - 2026-01-05

### Changed
- Made package imports framework-agnostic — no FastAPI import path triggered when running under Django.

## [0.3.9] - 2026-01-05

### Added
- DRF auth adapter test coverage (`test_django_authentication.py`).

[Unreleased]: https://github.com/anthonynarine/gait-sdk/compare/v0.5.4...HEAD
[0.5.4]: https://github.com/anthonynarine/gait-sdk/compare/v0.5.3...v0.5.4
[0.5.3]: https://github.com/anthonynarine/gait-sdk/compare/v0.5.2...v0.5.3
[0.5.2]: https://github.com/anthonynarine/gait-sdk/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/anthonynarine/gait-sdk/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/anthonynarine/gait-sdk/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/anthonynarine/gait-sdk/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/anthonynarine/gait-sdk/compare/v0.3.12...v0.4.0
[0.3.12]: https://github.com/anthonynarine/gait-sdk/compare/v0.3.11...v0.3.12
[0.3.11]: https://github.com/anthonynarine/gait-sdk/compare/v0.3.10...v0.3.11
[0.3.10]: https://github.com/anthonynarine/gait-sdk/compare/v0.3.9...v0.3.10
[0.3.9]: https://github.com/anthonynarine/gait-sdk/releases/tag/v0.3.9
