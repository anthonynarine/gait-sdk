# Confidential application client candidate

`gait_sdk.confidential` implements the GAIT-36 candidate server-to-server protocol, prepared as SDK 0.6.0 release-candidate source. It is not published in SDK 0.5.4 and does not establish that a hosted development service is available. Existing SDK interfaces remain unchanged. Publication of 0.6.0 and real hosted/BFF/browser acceptance are separate release requirements; do not assume this candidate is available from PyPI yet.

Use explicit deployment configuration from your backend's secret store. The module reads no environment files or Django settings. The API base must be a canonical HTTPS DNS URL ending in `/api`. Application UUID and expected `urn:gait:application:<UUID>` audience come from the same reviewed enrollment; they are different identifiers. The credential is the backend-only issued 43-character application secret, never a browser token.

```python
from gait_sdk.confidential import ConfidentialConfig, AsyncConfidentialClient

config = ConfidentialConfig(
    api_base_url=development_api_base,
    application_id=development_application_id,
    audience=development_audience,
    credential=backend_application_secret,
)
client = AsyncConfidentialClient(config)
pending = await client.login(email=submitted_email, password=submitted_password)
pair = await client.complete_mfa(
    mfa_transaction=pending["mfa_transaction"], otp=submitted_otp,
)
# Save tokens in the BFF's protected server-side session, never browser storage.
```

`complete_mfa` accepts exactly one of `otp` or `recovery_code`. The other operations are `refresh(refresh_token=...)`, `logout(refresh_token=...)`, `status(access_token=...)`, and `activity(access_token=..., generation=...)`. All arguments are keyword-only. The client sends fixed JSON schemas to the application-bound namespace and never forwards browser headers, cookies, Origin, Authorization or arbitrary client options. An external `httpx.AsyncClient` cannot be supplied. `transport` is a trusted test hook; use `httpx.MockTransport` for offline tests, not browser-controlled infrastructure.

Each operation owns a fresh HTTP client and cookie jar with TLS verification, no redirects, no environment proxies, a bounded response body and an overall timeout (default eight seconds; maximum thirty). There are no automatic request retries. Configuration and client representations hide the application secret. Do not log request/response bodies, tokens, passwords, MFA handles or response dictionaries. Your application's HTTP tracing must also protect these values.

Successful responses are checked against the configured audience and canonical session identifiers. Access-token payload parsing checks envelope consistency only: **this client does not verify JWT signatures, issuer, expiry or key provenance**. Use the existing reviewed verification facilities with explicitly pinned development issuer/JWKS/audience and perform live, credential-bound `status` checks. An unverified payload is never user authorization. Status includes the existing server assurance vocabulary (`amr`, `acr`, optional `auth_time` and `gait_mfa_time`); recovery proof does not become password-plus-TOTP assurance.

`ConfidentialDenied`, `ConfidentialThrottled`, `ConfidentialUnavailable` and `ConfidentialProtocolError` expose constant messages, never upstream error bodies. A refresh transport failure, timeout, 5xx, redirect or unusable success response raises `AmbiguousRefresh`: rotation may already have happened. Require fresh sign-in; do not resend the token. Explicit denial/throttling are separate errors, and the client still never retries them. Cancellation/interruption during refresh also requires treating the outcome as unknown. `StaleActivity` means reconcile status and wait for a new real interaction; do not replay the old interaction with a newer generation.

The BFF must serialize refresh across workers, atomically persist the replacement pair, use only server-provided activity generations, and report meaningful foreground activity rather than polling or refresh. Own browser session rotation, exact-origin/CSRF checks and logout/private-page denial remain the BFF's responsibility. Clear local access immediately if upstream logout is unavailable, and do not claim revocation succeeded without its response. Local-host cookies are shared across ports; a trusted developer workstation and local services remain prerequisites. No production endpoint, policy, tenant authorization or cookie isolation is relaxed by this client.
