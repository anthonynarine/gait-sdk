# Confidential application sign-in (0.6.0 candidate)

This client is unreleased source. Pin a published version with this contract only after its release and integration checks pass. Installing an older verification-only SDK does not implement the application sign-in transport.

Configure `AsyncConfidentialClient` with your environment's exact API base URL, application UUID, audience and backend credential. Development and production use separate issuers, signing keys, credentials, registrations and accounts. Keep Gait tokens and the credential in backend storage; give the browser only your application's opaque session cookie, with CSRF protection.

`login(email=..., password=...)` has two successful response shapes:

- `mfa_required: true`: keep `mfa_transaction` on the server and request the second factor. Complete it with `complete_mfa`; the challenge alone is not a signed-in session.
- `mfa_required: false`: the response contains `access_token`, `refresh_token`, `token_type`, `sid` and `aud`. A separate MFA call is unnecessary. This is password-only sign-in, not MFA assurance.

Optional is the default for new application registrations. An account with MFA enabled still receives a challenge. Required policy denies password-only login until the user has enrolled MFA. The client never supplies or overrides this server policy. Missing, non-boolean or mixed login outcomes fail closed without retry.

The client checks response shapes and application/session consistency. It does not verify a token's signature or authorize a user. Verify issuer, audience, signature, expiration and the live session using the supported verification interfaces before granting application access. Require the appropriate current-session assurance for sensitive actions.

Serialize refresh requests in the application's backend and save every replacement pair. An ambiguous refresh result requires fresh sign-in; never retry the consumed token automatically. Send activity only for real foreground interaction with the current generation. Polling and token refresh are not activity. Test password-only login, enabled and Required MFA, refresh, activity, logout and private-page denial through the real browser integration.
