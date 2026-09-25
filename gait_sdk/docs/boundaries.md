# Identity, application and tenancy boundaries: design decision

## Status
Decided 2026-09-13; **implemented** across 0.4.0–0.5.0. Updated 2026-09-25.

## The three questions

| Axis | Question | Owner |
|---|---|---|
| **User identity** | Who is making this request? | **Gait** issues it; **gait-sdk** verifies it into `VerifiedIdentity` (`subject`, `email`, `session_id`, `token_id`, `issuer`) |
| **Application identity** | Which registered service is calling? | **Gait** (`Application`, `ApplicationCredential`); gait-sdk exposes it through `gait_sdk.application.verify_application()` → `ApplicationPrincipal` |
| **Tenancy / authorization** | Which organization, role and permissions does this user have *inside this app*? | **The consuming application**, e.g. Lumen's `OrganizationMember`. Never Gait's tokens, never this SDK. |

`SecurityContext` (`gait_sdk.context`) composes the first two. It pairs "which user" with "which application" and performs no authorization.

## Decisions

1. **Tokens carry identity only.** Gait's RS256 access token has `sub, email, sid, jti, iss, aud, token_use, iat, exp`: no roles, orgs or permissions. The SDK ignores such claims even if present.
2. **The SDK never authorizes.** The legacy role helpers (`HasRole`, `HasAnyRole`, `require_role`, `utils.is_*`) are deprecated. Under JWKS the role is always `""`, so they always deny.
3. **Consumers key on the opaque subject.** They store `VerifiedIdentity.subject` (for example `OrganizationMember.external_user_id`) and never parse it. With more than one issuer, they key on `(issuer, subject)`.
4. **Two "organization" concepts must not be confused:**
   - Gait's `Organization` → `Application` means *Gait's customers and their registered apps* (for example "Lumen, production").
   - A consumer's own organizations mean *its customers* (for example hospitals in Lumen).

   They are linked only by the user `subject`. Gait knows nothing about a consumer's organizations.

## Why

- **Staleness.** A role or membership copied into a 15-minute token is wrong for up to 15 minutes after it changes. The consuming app reads its own database per request and is always current.
- **Reuse.** One Gait identity can serve many apps with different permission models, because none of them are baked into tokens.
- **Smaller attack surface.** The SDK's job, verifying identity, is small enough to audit completely. Authorization logic stays where the domain knowledge is.
