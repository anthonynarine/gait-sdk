# 📡 Auth Integration — Tenant Security Signal Client

## Status
SDK4 milestone. Write-side signal submission only — no findings/evidence
retrieval, no Observatory client, no agent orchestration, no automatic
instrumentation. Additive: `ClaimsUser`, `ExternalJWTAuthentication`,
`verify_token`, `ApplicationPrincipal`, `verify_application`, and
`SecurityContext` are all unchanged.

## What this is (and isn't) for founders/developers

A **tenant security signal** is your application telling Gait: *"here's
something security-relevant I observed about myself."* Maybe a scheduled
self-check ran and passed. Maybe it failed. You send that outcome, and
Gait records it against your organization's security posture.

It is **not** independent proof of anything. Gait didn't run your check —
you did, and you're reporting the result. Gait records this as
**customer-reported** evidence, which is a permanently different category
from evidence Gait produced itself (a CI run Gait executed, a config check
Gait performed). Sending a signal never upgrades that — there is no way to
mark your own report as independently verified.

It is also **not** a general-purpose API into Gait. You cannot use this to
read findings, browse your security posture, or manage anything. It's one
narrow write operation: submit a signal, get back a receipt.

## Authenticating: the same ApplicationCredential, nothing new

```python
from gait_sdk.security import send_security_signal

result = await send_security_signal(
    signal_type="APPLICATION_SELF_CHECK",
    result="PASS",
    source_reference="nightly-check-2026-09-13",
)
```

If `credential` isn't passed explicitly, this reads the same
`GAIT_APPLICATION_CREDENTIAL` setting SDK2's `verify_application()` uses —
there is no second credential, no `GAIT_SIGNAL_CREDENTIAL`, nothing new to
configure. One application identity authenticates both verification and
signal submission.

**No human identity is required or accepted.** This endpoint authenticates
software only — there's no `user`/`ClaimsUser`/`SecurityContext` parameter
anywhere on `send_security_signal()`. A backend service with only an
`ApplicationCredential` configured (no logged-in user anywhere in the
request) can submit signals just fine.

## Fields you control — and the ones you never can

| Field | Who controls it |
|---|---|
| `signal_type` | You (must be one Gait already approves — see below) |
| `result` | You — `"PASS"`, `"FAIL"`, `"WARNING"`, or `"INFORMATIONAL"` |
| `source_reference` | You — **required**, your own idempotency key |
| `payload` | You — bounded, JSON-safe context; see "Payload is data, not authority" |
| Organization | **Gait**, derived from your `ApplicationCredential` |
| Environment | **Gait**, derived from your `ApplicationCredential` |
| Application | **Gait**, derived from your `ApplicationCredential` |
| Evidence trust level | **Gait** — always `CUSTOMER_REPORTED` for this endpoint |
| Which security control this maps to | **Gait**, via `signal_type` → an internal, code-reviewed mapping |

`send_security_signal()` has no `organization`, `environment`,
`application`, `scope`, `trust`, `evidence_type`, or `control` parameter —
not "ignored if you pass one," genuinely absent from the function
signature. Gait's own request contract independently rejects (400, naming
the exact field) any attempt to send one of these at the HTTP level too —
this SDK's narrower signature is a second, structural layer on top of
that, not a replacement for it.

## `signal_type`: Gait's registry, not this SDK's

Gait maintains the list of approved `signal_type` values in its own
backend (a small, code-reviewed, growable registry) — this SDK does not
duplicate that list. Sending an unrecognized `signal_type` is rejected
(you'll get `SecuritySignalRejected`), the same way it always has been on
Gait's side. One value is exposed as a convenience constant:

```python
from gait_sdk.security import APPLICATION_SELF_CHECK
# == "APPLICATION_SELF_CHECK"
```

This is **not exhaustive** — Gait may approve more signal types over time
without a new SDK release being required, since `signal_type` is a plain
string on the wire either way. Ask Gait/check its own documentation for
the current full list rather than assuming this SDK enumerates it.

## Payload is data, not authority

`payload` is your own bounded, JSON-safe context (e.g. `{"scanner": "internal-tool", "version": "1.2.3"}`).
It is stored as opaque detail — Gait never reads a key out of it and
reinterprets it as an authority field. Putting `{"organization": "..."}"`
inside `payload` does not select an organization; it just stores a
`payload.organization` string nobody treats specially. Gait also
sanitizes payload content server-side (redacting anything shaped like a
secret) independent of anything this SDK does client-side.

## Idempotency: `source_reference` is your safety net

Gait deduplicates by **(your application, `signal_type`, `source_reference`)**.
Resubmitting the exact same triple:

- does **not** create a second signal or a second evidence record,
- returns the exact same receipt (`signal_id`, `control_key`, `evidence_id`),
- and — if your retry's `result`/`payload` happen to differ from the first
  successful call — the **original** values are what's kept; Gait never
  overwrites an already-recorded signal.

This SDK never deduplicates on your behalf — every call you make is sent
to Gait; Gait's own idempotency is the only source of truth. Always pass a
`source_reference` that's stable across retries of the *same* logical
event (e.g. a scheduled job's run ID or a deterministic hash of what it
checked) — a new random value on every call defeats idempotency entirely.

## The receipt: `SecuritySignalResult`

```python
result.signal_id     # str  — Gait's own signal record id
result.control_key   # str  — which SecurityControl this maps to
result.evidence_id   # str | None
result.received_at   # str  — ISO-8601 timestamp, as Gait returned it
```

Nothing here tells you whether this call created a fresh signal or
returned an existing one from a prior retry — Gait's own response doesn't
make that distinction, so this object doesn't invent one either.

## Failure behavior

| Condition | Exception |
|---|---|
| No credential (not passed, not configured) | `InvalidApplicationCredentialError` |
| Gait rejects the credential | `InvalidApplicationCredentialError` |
| Locally malformed input (empty `signal_type`/`result`/`source_reference`, non-dict `payload`) | `SecuritySignalRejected` |
| Gait rejects the signal's content (unapproved `signal_type`, invalid `result`, oversized `payload`, ...) | `SecuritySignalRejected` |
| Gait unreachable / timeout | `AuthServiceUnavailable` |
| Malformed/structurally-invalid Gait response | `AuthServiceUnavailable` |

A failed submission is never represented as accepted — every failure path
raises; nothing returns a "partial" or best-effort `SecuritySignalResult`.

## Logging

Only safe, non-sensitive correlation data is logged by default: event
category, status, `signal_type`, `source_reference`. Never the raw
credential, and never the full `payload` body — a security signal's own
detail can itself be sensitive, so it's treated the same way this SDK
already treats tokens and credentials elsewhere.

## What's deliberately not here yet

- No Django/FastAPI automatic wiring — no middleware, no dependency that
  emits a signal for you. Every signal is one explicit call site you
  choose.
- No findings/evidence/posture retrieval (Observatory) — write-side only.
- No client-side caching or deduplication of any kind.
- No integration with `SecurityContext` — `SecurityContext.application`
  never substitutes for the raw credential here (it structurally can't;
  `ApplicationPrincipal` never carries the credential at all). This
  function always authenticates independently.

---

Maintained by **Anthony Narine**
© 2025 — Auth Integration Project
