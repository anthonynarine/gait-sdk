# 🧩 Auth Integration — SecurityContext

## Status
SDK3 milestone. Identity composition only — no tenant security signals, no
Django/FastAPI automatic request wiring, no authorization logic. Additive:
`ClaimsUser`, `ExternalJWTAuthentication`, `verify_token`, `get_current_user`,
`ApplicationPrincipal`, and `verify_application` are all unchanged.

## Three concepts, still never merged

| | Question | Verified by |
|---|---|---|
| `ClaimsUser` / claims dict | Who is the human? | `verify_token` / `ExternalJWTAuthentication`, against Gait `/whoami/` |
| `ApplicationPrincipal` | Which registered software is calling? | `verify_application()`, against Gait `/applications/verify/` |
| `SecurityContext` | What verified identities are present for this execution? | Nothing — pure composition of the two above |

`SecurityContext` does not create authority. It does not perform
verification. It does not select a tenant or environment. It is not an
authorizer: it has no `can_access()`, `is_authorized()`, `allowed_roles()`,
or any tenant/facility permission logic — that stays with the consuming
application (exactly as it already does for `ClaimsUser` alone).

## Verify, then compose

```python
from gait_sdk.context import SecurityContext
from gait_sdk.application import verify_application

# Step 1: verify (separately, already-established elsewhere)
user = ...              # a ClaimsUser (Django) or claims dict (FastAPI)
application = await verify_application()

# Step 2: compose (no I/O, no verification, just carrying identities together)
context = SecurityContext(user=user, application=application)
```

`SecurityContext.__init__` never calls Gait. It cannot raise
`AuthServiceUnavailable`, `InvalidTokenError`, or
`InvalidApplicationCredentialError` — those are verification-time failures,
and verification already happened before you got here. Construction can
only fail for a *locally* invalid value (see "Failure semantics" below).

## Valid states

```python
SecurityContext(user=user)                          # human only
SecurityContext(application=application)             # application only
SecurityContext(user=user, application=application)  # both
```

`SecurityContext()` — neither identity — **raises `ValueError`**. This was
a deliberate design decision, not an oversight: an identity-less context
provides no real benefit over simply not having a `SecurityContext` at
all — every consumer would still need to null-check its contents exactly
as they'd null-check the *absence* of a context. Rather than let a
meaningless placeholder object exist, construction fails loudly so a
caller notices it has nothing to compose.

## Both human identity shapes are accepted

The two existing framework adapters return human identity differently —
this is a pre-existing asymmetry `SecurityContext` had to account for, not
something SDK3 introduced:

- Django's `ExternalJWTAuthentication` constructs a real `ClaimsUser` dataclass instance.
- FastAPI's `verify_token()` returns the raw claims **dict** — it never builds a `ClaimsUser`.

`SecurityContext.user` accepts either shape, checked structurally (by
attribute for a `ClaimsUser`, by key for a dict) against the same
`id`/`email`/`role`/`first_name`/`last_name` fields both shapes carry. This
is why `SecurityContext` doesn't do a strict `isinstance(user, ClaimsUser)`
check — seemingly a smaller detail, but load-bearing: see "Why `ClaimsUser`
isn't imported at runtime" below.

`SecurityContext.application` **is** strictly type-checked
(`isinstance(application, ApplicationPrincipal)`), since there's exactly
one real source for it (`verify_application()`) and no dict-shaped
alternative exists anywhere in this package today.

## Why `ClaimsUser` isn't imported at runtime

`ClaimsUser` currently lives in `gait_sdk.django.authentication`,
which unconditionally imports `rest_framework`/`asgiref` at module level
for the DRF adapter it also defines. Importing `ClaimsUser` for a runtime
`isinstance` check would force `gait_sdk.context` — meant to be
core and framework-neutral — to require Django/DRF just to be imported,
undermining the entire point of `SecurityContext`.

This was assessed directly (see the SDK3 report) rather than worked around
silently: moving `ClaimsUser` to a neutral module was considered and
**deliberately not done** in SDK3 — it's exactly the kind of identity-module
refactor this milestone is meant to avoid unless strictly necessary, and it
risks the existing stable `gait_sdk.authentication.ClaimsUser` /
`gait_sdk.django.authentication.ClaimsUser` import paths. Instead,
`gait_sdk/context.py` imports `ClaimsUser` only under
`TYPE_CHECKING` (for static type checkers, never evaluated at runtime) and
validates the human side structurally instead.

## Identity-presence helpers

```python
context.has_user          # bool — a human identity is present
context.has_application   # bool — an application identity is present
```

These mean "identity was verified and is present" — nothing about
authorization. No `is_authenticated`/`is_authorized`-style helper was added
that could be misread as a permission check.

## Failure semantics

| Condition | Result |
|---|---|
| Neither `user` nor `application` provided | `ValueError` |
| `application` provided but not an `ApplicationPrincipal` | `TypeError` |
| `user` provided but missing a required claims field (either shape) | `TypeError` |
| Gait unreachable, timeout, invalid credential, invalid token | **Not possible here** — these are `verify_token`/`verify_application` failures, which happen before a `SecurityContext` is ever constructed |

## Immutability and no serialization

`SecurityContext` is `@dataclass(frozen=True)` — reassigning `.user` or
`.application` after construction raises `dataclasses.FrozenInstanceError`.
Composing a context never mutates the `ClaimsUser`/claims dict or
`ApplicationPrincipal` passed into it.

No `.to_dict()` or JSON serialization was added in SDK3 — there's no
current consumer needing one, and adding one speculatively risks exposing
more than intended (or needing revision) once a real serialization need
(e.g. structured logging, a future telemetry payload) actually appears.

## Django / FastAPI integration — deliberately not added in SDK3

Both were assessed and explicitly declined for this milestone, for the
same underlying reason: **there is no established per-request source of
`ApplicationPrincipal` in either framework today** (SDK2 deliberately did
not wire application verification into requests). A `request.security_context`
attribute or a `get_security_context(request)` helper could, right now,
only ever build a *human-only* `SecurityContext` automatically — which is
barely more than `SecurityContext(user=request.user)` typed out directly,
and risks implying a level of request-lifecycle integration that doesn't
exist yet. Building that integration is exactly the "magically verify
everything on compose" shortcut this milestone is told to avoid — a
consuming service that already has both a verified user and a verified
application should just call `SecurityContext(user=..., application=...)`
directly at its own call site. A real framework helper is better placed in
a future milestone, once application verification actually has a
per-request home in at least one of the two adapters.

---

Maintained by **Anthony Narine**
© 2025 — Auth Integration Project
