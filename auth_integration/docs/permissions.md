# 🛡 Auth Integration — permissions.py

## Overview
Provides role-based access control helpers based on the `role` claim returned
from Gait Auth's `/whoami/`. Two implementations live in this one module:
a real Django REST Framework (DRF) branch, and a DRF-less fallback branch
intended for FastAPI/framework-agnostic code. Which branch loads is decided
automatically at import time by whether `rest_framework.permissions` is
importable — there is no separate FastAPI-specific import path.

**`role` is an opaque, consuming-application-defined string** (see the root
README's "Claims contract") — these classes only ever compare it to whatever
value(s) you pass in; they don't define or restrict what values are valid.

---

## DRF classes

| Class | Description |
|--------|-------------|
| `HasRole` | Grants access if `request.user_claims["role"]` matches the required one |
| `HasAnyRole` | Grants access if the role is in an allowed list |
| `require_role` | No-op decorator — DRF enforces via `permission_classes`, this exists only for cross-framework API parity |

```python
from rest_framework.views import APIView
from auth_integration.permissions import HasRole

class PhysicianOnly(APIView):
    permission_classes = [HasRole("physician")]

    def get(self, request):
        return Response({"msg": "Hello Doctor!"})
```

---

## FastAPI / DRF-less fallback (SDK1)

These are not wired into any FastAPI dependency-injection mechanism — FastAPI
has no `permission_classes` equivalent — so they must be called directly.

**Fail-closed guarantee**: none of these ever silently grant access because
DRF (or FastAPI) happens to be unavailable. Missing claims, non-dict claims,
and a role mismatch all deny.

```python
from fastapi import Depends, HTTPException
from auth_integration.fastapi.dependencies import verify_token
from auth_integration.permissions import HasRole, require_role

# Option 1: call has_permission directly against verified claims
@app.get("/physician-only")
async def physician_only(claims=Depends(verify_token)):
    if not HasRole("physician").has_permission(claims):
        raise HTTPException(status_code=403, detail="Insufficient role.")
    return {"msg": "Hello Doctor!"}

# Option 2: decorator — the wrapped function MUST receive its verified
# claims via a `claims` keyword argument (the same convention as
# Depends(verify_token) in the README's FastAPI quickstart).
@require_role("physician")
async def physician_only_decorated(claims=Depends(verify_token)):
    return {"msg": "Hello Doctor!"}
```

`require_role` raises `HTTPException(403)` (never calling the wrapped
function) if `claims` is missing, not a dict, or its `role` doesn't match —
and raises a `RuntimeError` at call time (not at import time) if FastAPI
itself isn't installed, rather than silently doing nothing.

---

Maintained by **Anthony Narine**  
© 2025 — Auth Integration Project
