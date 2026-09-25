# 🧭 Identity & Tenancy Boundaries — Design Decision

## Status
Decided (2026-09-13). Not yet implemented. This document records the boundary so future
work on Gait-as-a-multi-application-SaaS-provider doesn't accidentally collapse three
distinct identity concepts into one.

## Context
Gait started as Lumen's own auth service. It is moving toward being a shared identity
provider that other applications ("customers") could integrate against — not just
Lumen. Separately, Lumen itself has already built its own domain tenancy on top of
Gait identity (`organizations.Organization`, `OrganizationMember`, `IsOrgMember`,
`X-Org-Slug` — see `Lumen/lumen_reports/reports/docs/tenancy.md`).

These are three different questions, and this package (`gait_sdk`, the Gait
SDK) must keep answering only the first one:

| Axis | Question | Owner today |
|---|---|---|
| **User identity** | Who is making this request? | `gait_sdk` (this package) — `ClaimsUser` / `UserClaims`, validated against Gait `/whoami/` |
| **Application/customer identity** | Which registered application (Gait "customer") issued/accepts this token? | Not yet built. Belongs to Gait + this SDK once it exists (see below) |
| **Organization/tenant membership** | Which org, within that application's own domain model, does this user belong to? | The consuming application (e.g. Lumen's `organizations` app) — **not** Gait, **not** this SDK |

## Decision

1. **`gait_sdk`'s authentication contract stays tenant-agnostic.** `ClaimsUser` /
   `UserClaims` (`gait_sdk/django/authentication.py`) continue to carry only
   `id`, `email`, `role`, `first_name`, `last_name`, `is_2fa_enabled` — identity and
   role, nothing domain-specific. This is the existing contract; nothing here changes
   it today.
2. **Application/customer identity is a separate, future concept**, added for SaaS
   integration — i.e. "which registered Gait application is this token for," analogous
   to an OAuth `client_id`/audience. It answers a different question than org
   membership: it's about which product integrates with Gait, not which tenant a user
   belongs to inside that product. When built, it is additive (e.g. an `app_id`/`aud`
   claim or a separate credential on the request) and does not require every existing
   consumer (Reports, AI brain) to adopt it, since today Gait effectively has one
   application (Lumen).
3. **Organization membership does not go into JWTs or the Principal object yet.**
   No `org_id`, `organization`, or membership list gets added to `UserClaims` /
   `ClaimsUser` as part of this work. Doing so would (a) couple Gait's core auth
   contract to one customer's domain model, (b) create staleness risk — a 15-minute
   access token embedding org membership can outlive a membership change — and
   (c) duplicate what `organizations.OrganizationMember` already does correctly in
   Lumen today.
4. **Application-specific domain tenancy stays in the consuming service.** Org
   membership, roles-within-org, facility scoping, etc. remain owned by each
   application's own backend (Lumen's `organizations` app + `IsOrgMember`), resolved
   per-request from that service's own database — exactly as documented in
   `Lumen/lumen_reports/reports/docs/tenancy.md`. This package has no opinion about
   organizations and should not gain one implicitly.
5. **A server-verified Gait Organization API is a deferred, optional future piece** —
   only worth building if Gait-managed membership becomes part of the *public* Gait
   product (i.e. Gait itself starts offering "we manage your app's org/tenant
   membership" as a service to multiple customer applications, not just Lumen). If
   that happens:
   - It is a **separate API call**, not a JWT claim — a consuming service asks Gait
     "what orgs does this validated identity belong to?" at request time (or on a
     short cache), the same shape `validate_token()` already uses for `/whoami/`.
   - It must be **server-verified**: the calling service authenticates itself to Gait
     (its own service credential, not the end user's token) and trusts Gait's live
     answer — never a client-supplied or long-lived-token-embedded claim.
   - It stays **optional** — a consuming application that manages its own tenancy
     (like Lumen does today) has no reason to adopt it, and this package's core
     authentication contract (decision #1) must not depend on it existing.

## Non-goals right now
- No `Application`/`Client` model, no `app_id`/`aud` claim, no new SDK surface for
  either concept is being added as part of this decision — this document only records
  the boundary so the next implementation milestone builds on the right one.
- No changes to `UserClaims`, `ClaimsUser`, `/whoami/`, or any consumer's
  `requirements.txt` pin.

## Related
- `README.md` → "Authorization (RBAC) guidance" (existing tenant-agnostic contract)
- `Lumen/lumen_reports/reports/docs/tenancy.md` (how Lumen owns org tenancy today)
- `Lumen/CLAUDE.md` → Tenancy section (hard rules for org-scoped clinical data)
