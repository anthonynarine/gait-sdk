# 🤖 Auth Integration — Application (machine) identity

## Status
SDK2 milestone. Framework-neutral primitive + verification only — no
Django/FastAPI request wiring, no `SecurityContext`, no tenant security
signals. Additive: nothing about existing human authentication
(`ExternalJWTAuthentication`, `verify_token`, `ClaimsUser`,
`request.user`/`request.user_claims`) changed.

## Two separate identity questions

This package now answers two independent questions, never merged into one
object or one code path:

| | Question | Answered by | Verified against |
|---|---|---|---|
| **Human identity** | Who is making this request? | `ClaimsUser` / user claims | Gait `/whoami/`, a user JWT |
| **Application (machine) identity** | Which registered software/service is calling? | `ApplicationPrincipal` | Gait `/api/applications/verify/`, an `ApplicationCredential` secret |

Neither ever grants the other's authority. Verifying a human token never
establishes application identity, and verifying an application credential
never establishes — or requires — a human. A request may have a human
identity, an application identity, both, or neither; this package does not
yet compose them into one object (that is a deliberately deferred future
milestone, not built here).

`ApplicationPrincipal` is **not** a superuser or backend-trust escalation.
It represents "Gait has verified this software identity" — nothing about
what that software is authorized to do. Business/domain authorization
(what a given application, or the human using it, may actually access)
remains entirely the consuming application's own responsibility, exactly
as it already is for `ClaimsUser`.

## `ApplicationPrincipal`

```python
from gait_sdk.application import ApplicationPrincipal

ApplicationPrincipal(
    application_id="...",     # Gait Application UUID, as a string
    application_slug="...",   # e.g. "lumen-media"
    organization_id="...",    # Gait Organization UUID, as a string
    organization_slug="...",  # e.g. "mount-sinai" — this is the GAIT
                               # customer/organization, never a Lumen
                               # hospital/business-tenant organization
    environment="...",        # one of: local, test, ci, staging, production
)
```

Immutable (`@dataclass(frozen=True)`), framework-neutral (no Django or
FastAPI import), and deliberately has **no** field for: the raw credential,
a credential hash/id, a human role, business-domain permissions, or a
Lumen Facility/Organization.

## Configuration: `GAIT_APPLICATION_CREDENTIAL`

Read the same way as `GAIT_AUTH_URL`/`GAIT_TIMEOUT` (`gait_sdk.settings`
— Django settings if configured, else environment/`.env` via
`python-decouple`). Requirements, all enforced by convention/design rather
than by a runtime check that could itself leak the value:

- **Backend-only.** Never sent to, read from, or referenced by any
  browser/frontend code. There is no "frontend" story for this setting at
  all.
- **Secret.** Treat it exactly like `JWT_ACCESS_SECRET`/`JWT_REFRESH_SECRET`
  in the Gait backend itself — a credential capable of asserting a
  specific Application's identity to Gait.
- **Environment-specific.** A credential is issued for one specific Gait
  `Application` row, which is itself scoped to one environment (`local`,
  `test`, `ci`, `staging`, `production` — see `ApplicationPrincipal.environment`).
  A staging credential verifies as a staging identity; there is no way to
  present it and get back `"production"` (see "Environment and organization
  authority" below).
- **Rotatable.** Gait supports multiple simultaneously-`ACTIVE` credentials
  per `Application`, so a new one can be issued and deployed before an old
  one is revoked — no forced downtime window. This package does not manage
  rotation itself; it only ever presents whichever raw secret it's given.
- **Never logged.** `gait_sdk.settings._get_setting()` only ever
  logs a setting's *name*, never its value — this is already true for
  every setting this package reads, `GAIT_APPLICATION_CREDENTIAL` included.
  `gait_sdk.application.verify_application()` never interpolates
  the raw credential into any log line or exception message either.
- **No default, no fabricated fallback.** If neither an explicit
  `credential` argument nor `GAIT_APPLICATION_CREDENTIAL` is set,
  `verify_application()` raises `InvalidApplicationCredentialError`
  immediately, before any network call — it never silently proceeds as if
  a machine identity had been verified.

## Verifying application identity

```python
from gait_sdk.application import verify_application
from gait_sdk.exceptions import (
    InvalidApplicationCredentialError,
    AuthServiceUnavailable,
)

try:
    principal = await verify_application()  # reads GAIT_APPLICATION_CREDENTIAL
    # or: await verify_application(credential="...")  # explicit override
except InvalidApplicationCredentialError:
    ...  # missing/unknown/revoked/expired credential, or a suspended/
         # revoked owning Application — Gait does not distinguish these
         # reasons in its response, and this SDK does not try to recover
         # a finer-grained one
except AuthServiceUnavailable:
    ...  # Gait unreachable, timed out, or returned something this SDK
         # cannot parse/trust (malformed JSON, unexpected status code, or
         # a structurally invalid identity payload)
```

`verify_application()` is `async`, matching `gait_sdk.client.validate_token`'s
own style — there is no synchronous wrapper in SDK2 (no Django/FastAPI
request integration exists yet to need one).

### Wire contract (verified read-only against the frozen Gait backend)

- `POST {GAIT_AUTH_URL}/applications/verify/` — same `GAIT_AUTH_URL` base
  used for `/whoami/`.
- Credential transport: the dedicated header `Gait-Application-Credential`
  — **never** `Authorization: Bearer`, which stays reserved for human
  tokens. A single request can carry both without collision.
- No request body is read by Gait's endpoint; none is sent.
- Success (`200`): `{"application_id", "application_slug", "organization_id", "organization_slug", "environment"}`.
- Failure (`401`): one uniform body for every failure reason (missing/unknown/
  revoked/expired credential, or a suspended/revoked owning Application) —
  by design, so an unauthenticated caller can never use the response to
  enumerate credential or application state.

## Environment and organization authority

Both `environment` and `organization_id`/`organization_slug` on the
returned `ApplicationPrincipal` come **exclusively** from Gait's
verification response. `verify_application()` takes exactly one parameter
(the credential) — there is no argument through which a caller can select,
override, or broaden an organization or environment. A staging credential
cannot be asked to "please resolve as production"; the environment (and
organization) are properties of the `Application` row the credential
belongs to on the Gait side, not something the SDK or its caller
determines. See `tests/test_application.py`'s organization/environment
authority tests for this proven directly.

## Failure semantics

| Condition | Exception | Notes |
|---|---|---|
| No credential (not passed, not configured) | `InvalidApplicationCredentialError` | Fails before any network call |
| Gait rejects the credential (`401`) | `InvalidApplicationCredentialError` | Same exception as "missing" — Gait itself doesn't distinguish reasons |
| Gait unreachable / timeout | `AuthServiceUnavailable` | Same failure class `client.py` already uses for `/whoami/` |
| Malformed JSON / structurally invalid response / unexpected status | `AuthServiceUnavailable` | Never produces a partially-populated `ApplicationPrincipal` |

## What's deliberately not here yet

- No `SecurityContext` composing `ClaimsUser` + `ApplicationPrincipal` —
  a later, separate milestone.
- No Django authentication class or FastAPI dependency wiring
  `ApplicationPrincipal` into `request`/`request.state` automatically.
  `verify_application()` is a plain async function today; a consumer
  calls it directly wherever it needs machine identity.
- No caching of verification results (unlike the Django adapter's Bearer
  TTL cache for human tokens) — every call re-verifies against Gait.
- No credential issuance/rotation/revocation client — this package only
  ever *presents* a credential it's given; managing the credential's
  lifecycle is a Gait backend/operator concern.

---

Maintained by **Anthony Narine**
© 2025 — Auth Integration Project
