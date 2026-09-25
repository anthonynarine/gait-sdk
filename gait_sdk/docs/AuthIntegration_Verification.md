# Token Verification (0.4.0)

`gait_sdk.verification` and `gait_sdk.session`.

## Boundary

| Layer | Owns |
|---|---|
| Gait | Authentication: it issues and signs identity. |
| `gait_sdk` | Verification and normalization. The result is a `VerifiedIdentity`. |
| Consuming app (Lumen) | Authorization: organizations, facilities, roles, exams, workflow actions. |

This package never grants, checks, or carries roles, orgs, facilities, or permissions. The legacy role helpers are deprecated (see the README).

## Architecture

```
                TokenVerifier
                /           \
IntrospectionVerifier     JwksVerifier
       |                       |
       +-----------+-----------+
                   v
           VerifiedIdentity
           subject, email, session_id, token_id, issuer
                   |
          +--------+--------+
          v                 v
    Django adapter     FastAPI adapter
     ClaimsUser         identity dict

SessionChecker (separate): GET /whoami/ with the same bearer token.
No bearer cache, no JWKS cache, no fallback.
```

The verifier is selected explicitly with `GAIT_TOKEN_VERIFIER`. The default is `introspection`, and nothing changes for a consumer until it opts in. One process-wide verifier instance is built lazily by `get_token_verifier()`, so every request shares one JWKS cache.

## Gait's RS256 access-token contract (what `JwksVerifier` requires)

Header `alg` must be `RS256`, with a non-empty `kid`.

Claims:

| Claim | Requirement |
|---|---|
| `sub` | non-empty string, opaque |
| `email` | string |
| `sid` | non-empty string (the revocable session) |
| `jti` | non-empty string |
| `iss` | must equal `GAIT_ISSUER` |
| `aud` | must equal `GAIT_AUDIENCE` |
| `token_use` | must equal `"access"` |
| `iat`, `exp` | required, with 30 s leeway |

There is no role claim. If a token carried one anyway, it is ignored and never reaches `VerifiedIdentity` or `ClaimsUser`.

## JWKS cache rules

| Situation | Outcome |
|---|---|
| Known `kid`, keys younger than 5 min | Verify locally, no network |
| Unknown `kid`, keys fresh | One single-flight forced refresh. No more than one forced refresh per 30 s cooldown; during the cooldown an unknown `kid` gets 401 immediately. |
| Keys older than 5 min | Normal refresh (single-flight) |
| Refresh succeeds | The key set is **replaced**. A `kid` missing from it gets 401 immediately. |
| Refresh fails: network, non-200, malformed document, duplicate `kid` | The previous keys are kept. A known `kid` verifies while those keys are 1 h old or less. After a failure, further fetches back off for 30 s. |
| Unknown `kid` and refresh fails | 503 (fails closed) |
| Known `kid`, but keys older than 1 h and refresh fails | 503 |
| Any JWKS verification failure | **Never** downgrades to `/whoami/` |

Keys in the JWKS that are not RSA signing keys (other `kty`, `use != sig`, or `alg != RS256`), are malformed, or are smaller than 2048 bits are skipped, so they can never verify anything.

## Live session check

JWKS verification is local, so revoking a Gait session takes effect only when its tokens expire (15 minutes). For sensitive operations:

`local verification -> app authorization -> check_session_live() -> Gait /whoami/ live`

| Gait answer | Result |
|---|---|
| 200, same subject | continue |
| 401 (revoked or expired) | deny, 401 |
| 200, different subject | deny, 401 |
| timeout, unreachable, 5xx, other status, malformed body | deny, 503 |

Entry points:
- `gait_sdk.session.check_session_live(token, expected_subject=...)` and its async twin `acheck_session_live`.
- Django: `gait_sdk.django.authentication.require_live_session(request)`.
- FastAPI: `Depends(gait_sdk.fastapi.dependencies.require_live_session)`.

Which operations are sensitive is the consuming application's decision.

## Django specifics (JWKS mode)

- Credentials: the Bearer header, or else the `access_token` cookie. Refresh and temp cookies are never used.
- The 45 s bearer cache is not used, because local verification is already cheap.
- `ClaimsUser(id=subject, email, role="", first_name="", last_name="")`.
- `request.user_claims` and `request.auth` hold `VerifiedIdentity.as_claims()`. The legacy keys `id`, `first_name`, `last_name` and `role` are kept but empty, so existing indexing code does not break.
- `request.verified_identity` holds the `VerifiedIdentity`.
