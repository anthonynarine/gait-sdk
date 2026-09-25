# gait_sdk: module reference

Per-module references for maintainers. Start with the repository docs if you're new: [README](../../README.md) → [Architecture](../../docs/ARCHITECTURE.md) → [Integration guide](../../docs/INTEGRATION_GUIDE.md).

## Module map

```
gait_sdk/
├── verification.py        TokenVerifier, JwksVerifier, IntrospectionVerifier, VerifiedIdentity,
│                          is_secure_gait_url, load_verifier_config, get/set_token_verifier
├── session.py             check_session_live / acheck_session_live (live revocation check)
├── client.py              low-level async /whoami/ call (used by introspection)
├── application.py         verify_application(): the service's own Gait credential
├── context.py             SecurityContext (user identity + application identity)
├── security.py            send_security_signal(): tenant security signals to Gait
├── settings.py            configuration loading (Django settings → env / .env)
├── exceptions.py          InvalidTokenError (401), AuthServiceUnavailable (503), …
├── apps.py                Django AppConfig: validates configuration at startup
├── authentication.py      stable DRF entrypoint (re-exports the Django adapter)
├── django/authentication.py   ExternalJWTAuthentication, ClaimsUser, require_live_session
├── fastapi/dependencies.py    verify_token, require_live_session, validate_configuration
├── permissions.py, utils.py   DEPRECATED role helpers (legacy introspection only)
auth_integration/          DEPRECATED alias package (0.5.x) → same gait_sdk modules
```

## Reference docs

| Doc | Covers |
|---|---|
| [verification.md](verification.md) | Verifier modes, token contract, key caching, live session check |
| [client.md](client.md) | The `/whoami/` client and its error mapping |
| [application.md](application.md) | Application (machine) identity |
| [context.md](context.md) | `SecurityContext` |
| [security_signals.md](security_signals.md) | Tenant security signals |
| [boundaries.md](boundaries.md) | The identity / application / tenancy boundary (design decision) |
| [settings.md](settings.md), [exceptions.md](exceptions.md) | Configuration and error types |
| [permissions.md](permissions.md), [utils.md](utils.md) | Deprecated role helpers |
| [../django/docs/authentication.md](../django/docs/authentication.md) | The DRF adapter in detail |

## Consumers

The first consumer is Lumen: `lumen_reports` (Django/DRF) and `lumen_media` (FastAPI, which uses this SDK since Lumen's auth Stage 3a). A fix here reaches a consumer only once it bumps its pinned version.
