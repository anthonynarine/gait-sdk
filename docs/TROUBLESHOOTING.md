# Troubleshooting

Search this page for the exact message you're seeing.

## The service won't start

| Message | Cause | Fix |
|---|---|---|
| `GAIT_TOKEN_VERIFIER=jwks requires GAIT_JWKS_URL, GAIT_ISSUER, GAIT_AUDIENCE.` (or a subset) | JWKS mode is on but configuration is missing | Set all three. The values come from your Gait deployment (`JWT_ISSUER`, `JWT_AUDIENCE`, `https://<gait>/.well-known/jwks.json`). |
| `GAIT_JWKS_URL must use https:// (http only for localhost).` | A plain `http://` URL to a real host, **or** a lookalike such as `http://localhost.evil.com` | Use `https://…`. Plain http works only for exactly `localhost`, `127.0.0.1` or `::1`. |
| `GAIT_AUTH_URL must use https:// (http only for localhost).` | Same rule for Gait's API base. It carries tokens and your app credential. | Use `https://<gait>/api` |
| `GAIT_TOKEN_VERIFIER must be one of ['introspection', 'jwks']` | Typo | Fix the value |

Startup failures are intentional: a broken auth configuration should stop the service before it serves traffic, not fail every request.

## Requests get 401

| Message | Cause | Fix |
|---|---|---|
| `Invalid or expired token.` | Expired (15 min), wrong signature, wrong `iss`/`aud`, wrong token type, or malformed | The client should refresh and retry. If it keeps happening with fresh tokens, check that `GAIT_ISSUER` and `GAIT_AUDIENCE` **exactly** match Gait's `JWT_ISSUER`/`JWT_AUDIENCE` (a trailing slash counts). |
| `Unknown signing key.` | The token's `kid` isn't in Gait's current key set | Normal briefly after Gait rotates keys (the SDK refetches, at most once per 30 s). If it persists, the token came from a different Gait or a retired key. |
| `Session is not active.` | The live session check found the session revoked or expired (logout, admin revoke, password change) | Expected. The user must log in again. |
| 401 with **no token at all** | No `Authorization: Bearer …` header | Send the header. JWKS mode ignores cookies. |

## Requests get 503

| Message | Cause | Fix |
|---|---|---|
| `Unable to refresh signing keys.` | An unknown `kid` arrived **and** Gait's JWKS couldn't be fetched | Check Gait is up and `GAIT_JWKS_URL` is reachable from your server |
| `Signing keys unavailable.` | Keys haven't been refreshable for over 1 hour | Same. The stale-key grace period has run out. |
| `Unable to confirm session.` | A live session check couldn't reach Gait | Sensitive actions deliberately fail closed. Fix connectivity to `GAIT_AUTH_URL`. |
| `Authentication service misconfigured.` | `GAIT_AUTH_URL` is missing or not https at call time | Set it correctly |

503 means "couldn't check", never "not allowed". Clients should retry later, not log the user out.

## Other surprises

**"`request.user.role` is empty."** Correct under JWKS. Gait tokens carry identity only. Look up roles in your own data using `request.verified_identity.subject`. See [Concepts](CONCEPTS.md#authentication-vs-authorization).

**"I logged out but my API calls still work."** Local verification can't see revocation until the token expires (≤15 min). Protect sensitive endpoints with `require_live_session`. See [Concepts → revocation](CONCEPTS.md#revocation-and-the-live-session-check).

**"`DeprecationWarning: The 'auth_integration' package was renamed`."** Replace `auth_integration` with `gait_sdk` in imports, `INSTALLED_APPS` and DRF settings. See the [upgrade table](INTEGRATION_GUIDE.md#upgrading-from-auth_integration).

**"Cookie authentication stopped working after upgrading to 0.5."** JWKS mode is Bearer-only, and legacy cookie mode is now opt-in (`GAIT_ALLOW_COOKIE_AUTH=True`). Prefer sending `Authorization: Bearer`. See [Security](SECURITY.md).

**"`GAIT_AUTH_URL is not set!` printed at import."** Harmless if you only use JWKS verification and never call live checks. Set it anyway if you use `require_live_session`.

**"My tests hit the real Gait."** Install a fake verifier with `set_token_verifier(...)`, or use `force_authenticate`. See [Integration guide → testing](INTEGRATION_GUIDE.md#6-testing-your-integration).
