# Integration guide

How to wire gait-sdk into a service, move it from introspection to local JWKS verification safely, protect sensitive actions, and test it. Examples come from Lumen, the first consumer.

## 1. Install and pin

```bash
pip install "gait-sdk[django]==0.5.0"      # or [fastapi]
```

Pin exact versions in `requirements.txt`. Upgrades should be deliberate, reviewed changes (see [Publishing → consuming safely](PUBLISHING.md#consuming-safely)).

## 2. Wire the framework adapter

**Django REST Framework**
```python
INSTALLED_APPS = [..., "gait_sdk"]   # its AppConfig validates settings at startup

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["gait_sdk.authentication.ExternalJWTAuthentication"],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated", ...],
}
```

After authentication, a request carries:

| Attribute | Contents |
|---|---|
| `request.user` | `ClaimsUser(id=<subject>, email=…)`. `role`, `first_name` and `last_name` are `""` under JWKS. |
| `request.verified_identity` | `VerifiedIdentity(subject, email, session_id, token_id, issuer)`. **Use this.** |
| `request.auth` / `request.user_claims` | The same identity as a dict |

**FastAPI**
```python
from gait_sdk.fastapi.dependencies import validate_configuration, verify_token
validate_configuration()                          # at startup
async def route(claims: dict = Depends(verify_token)): ...
# request.state.verified_identity is set too
```

## 3. Map identity to your own users (authorization lives here)

Store the Gait subject on your membership records and look it up per request:

```python
member = OrganizationMember.objects.get(
    organization=request.organization,          # e.g. resolved from an X-Org-Slug header
    external_user_id=request.verified_identity.subject,
)
if not member.can_finalize_reports: ...
```

- Treat `subject` as an **opaque string**. Don't parse it or assume it's numeric.
- If you ever trust more than one Gait issuer, key on `(issuer, subject)`.
- Never authorize from anything in the token beyond identity. There are no role claims, by design.

## 4. Protect sensitive actions

```python
from gait_sdk.django.authentication import require_live_session

def post(self, request, exam_id):
    if not request.org_member.can_finalize_reports:      # 1. your role check
        return Response(status=403)
    get_object_or_404(scoped_exams(request), id=exam_id)  # 2. your object scope (404 if not theirs)
    require_live_session(request)                         # 3. Gait, live: 401 revoked / 503 unreachable
    finalize(exam_id)                                     # 4. mutate
```

Choose these actions deliberately: anything irreversible, clinical sign-off, or permission changes. Lumen gates exam sign / finalize / unfinalize / addendum and all membership changes. **Do the authorization first**, so Gait is never called for requests you would reject anyway.

## 5. Cut over from introspection to JWKS

Introspection (`/whoami/` per request) is the default only so that upgrading changes nothing. JWKS is the goal. Work through this one environment at a time:

1. **Gait issues RS256 tokens:** `JWT_ACCESS_SIGNING_ALG=RS256`, with a key, `JWT_ISSUER` and `JWT_AUDIENCE` set (see Gait's RS256 runbook).
2. **Confirm Gait publishes a key:** `curl https://<gait>/.well-known/jwks.json` shows ≥1 key.
3. **Deploy with protection in place first:** `require_live_session` on sensitive actions, while still on `introspection`.
4. **Switch the service:**
   ```
   GAIT_TOKEN_VERIFIER=jwks
   GAIT_JWKS_URL=https://<gait>/.well-known/jwks.json
   GAIT_ISSUER=<exactly Gait's JWT_ISSUER>
   GAIT_AUDIENCE=<exactly Gait's JWT_AUDIENCE>
   ```
   Restart. A wrong or missing value fails startup, which is what you want.
5. **Verify:** normal requests no longer hit Gait `/whoami/`; sensitive actions still do; logging out makes sensitive actions return 401.
6. **Roll back if needed** by setting `GAIT_TOKEN_VERIFIER=introspection` and restarting. Nothing else changes.

## 6. Testing your integration

- **Unit tests:** don't call Gait. Either use DRF's `force_authenticate` with a stand-in user whose `id` matches a membership, or install a fake verifier:
  ```python
  from gait_sdk.verification import JwksVerifier, set_token_verifier
  set_token_verifier(JwksVerifier(jwks_url="https://t/jwks", issuer=ISS, audience=AUD,
                                  fetch=lambda url, timeout: {"keys": [my_test_jwk]}))
  # ... sign tokens with your test RSA key; reset with set_token_verifier(None)
  ```
- **Gate tests:** replace your app's `require_live_session` wrapper in one place (Lumen uses a `conftest.py` fixture) and assert three things: (a) revoked → 401 and **nothing mutated**, (b) Gait down → 503 and nothing mutated, (c) a user without permission never triggers the Gait call.
- **Keep one test on the real path:** a token with no role authenticates, `ClaimsUser.role == ""`, and `subject` resolves your stored membership.

## Upgrading from `auth_integration`

0.5.0 renamed the package. The old name is a deprecated alias until 0.6.0. It returns the **same** module objects, so shared state such as the verifier and key cache stays single.

| Before | After |
|---|---|
| `auth_integration @ git+https://github.com/…@<sha>` | `gait-sdk[django]==0.5.0` |
| `"auth_integration"` in `INSTALLED_APPS` | `"gait_sdk"` |
| `"auth_integration.authentication.ExternalJWTAuthentication"` | `"gait_sdk.authentication.ExternalJWTAuthentication"` |
| `from auth_integration.x import y` | `from gait_sdk.x import y` |
| logger `auth_integration.*` | logger `gait_sdk.*` |

**Behavior changes in 0.5.0 to check:**
- JWKS mode is **Bearer-only** (cookies are ignored).
- Legacy cookie mode needs `GAIT_ALLOW_COOKIE_AUTH=True` and forwards only `access_token`.
- `GAIT_AUTH_URL` / `GAIT_JWKS_URL` must be `https` (except localhost).

Search for leftovers with `grep -rn auth_integration .`. Once none remain, the deprecation warning disappears.
