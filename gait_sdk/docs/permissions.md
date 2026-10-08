# 🛡 Auth Integration — permissions.py

## Overview
Provides role-based access control helpers based on the `role` claim returned
from Gait Auth's `/whoami/`. Two implementations live in this one module:
a real Django REST Framework (DRF) branch, and a DRF-less fallback branch
intended for FastAPI/framework-agnostic code. Which shape `HasRole` and
`HasAnyRole` take is decided automatically at import time by whether
`rest_framework.permissions` is importable — there is no separate
FastAPI-specific import path. `require_role` does not depend on DRF: it has
one implementation and always enforces (GAIT-SEC-029).

**Fail-closed rules (GAIT-SEC-056)**: a user whose `role` is missing, not a
string, or empty/blank is always denied. `HasRole(...)` / `require_role(...)`
reject an empty or non-string role at construction. `HasAnyRole(...)` rejects
a bare string (it would be a substring test), an empty collection, and any
empty or non-string entry.

**Which shape you get depends on what is importable (GAIT-SEC-072).** If
`rest_framework` can be imported, `HasRole`/`HasAnyRole` are DRF permissions
(`has_permission(request, view)`), even inside FastAPI code. A FastAPI service
that also has DRF installed therefore cannot call
`HasRole("x").has_permission(claims)`: it raises `TypeError` (the request
fails, it is never allowed). In FastAPI code, use `require_role` or your own
`Depends()` check (below), which work the same with or without DRF.

**`role` is an opaque, consuming-application-defined string** (see the root
README's "Claims contract") — these classes only ever compare it to whatever
value(s) you pass in; they don't define or restrict what values are valid.

---

## DRF classes

| Class | Description |
|--------|-------------|
| `HasRole` | Grants access if `request.user_claims["role"]` matches the required one |
| `HasAnyRole` | Grants access if the role is in an allowed list |
| `require_role` | Not for DRF views (use `permission_classes`). It is the FastAPI-style decorator below and enforces even when DRF is installed |

`permission_classes` takes **classes**: DRF instantiates each entry with no
arguments. Subclass `HasRole`/`HasAnyRole` with the role fixed and list the
subclass. This works on every version, 0.5.2 and 0.5.3 alike. These
classes are for DRF only; never hand them to FastAPI's `Depends()` (see the
FastAPI section). Do not put an
instance such as `HasRole("physician")` in `permission_classes`; the request
fails (GAIT-SEC-071).

```python
from rest_framework.response import Response
from rest_framework.views import APIView
from gait_sdk.permissions import HasAnyRole, HasRole

class PhysicianRole(HasRole):
    def __init__(self):
        super().__init__("physician")

class AdminOrPhysician(HasAnyRole):
    def __init__(self):
        super().__init__(["admin", "physician"])

class PhysicianOnly(APIView):
    permission_classes = [PhysicianRole]

    def get(self, request):
        return Response({"msg": "Hello Doctor!"})

class Shared(APIView):
    permission_classes = [AdminOrPhysician]
```

A denied request gets 403 (or 401 if the request was not authenticated at
all).

---

## FastAPI / DRF-less fallback (SDK1)

These are not wired into any FastAPI dependency-injection mechanism — FastAPI
has no `permission_classes` equivalent — so they must be called directly.

**Fail-closed guarantee**: none of these ever silently grant access because
DRF (or FastAPI) happens to be unavailable. Missing claims, non-dict claims,
and a role mismatch all deny.

**`HasRole`/`HasAnyRole` and every subclass of them (including the DRF
class form above) are for DRF `permission_classes` only. Never use them, or
any subclass, with FastAPI's `Depends()`:** FastAPI would only construct
them and never check the role. Since 0.5.3 FastAPI refuses such a route at
registration (GAIT-SEC-074, GAIT-SEC-075). FastAPI apps use an app-owned
dependency (below) or `require_role` in the documented order.

**Recommended: a `Depends()` check your application owns.** FastAPI runs it
as part of the route, so it cannot be left off by decorator order, and it
does not depend on whether DRF is installed:

```python
from fastapi import Depends, HTTPException
from gait_sdk.fastapi.dependencies import verify_token

def role_required(role: str):
    async def dependency(claims: dict = Depends(verify_token)):
        if claims.get("role") != role:
            raise HTTPException(status_code=403, detail="Insufficient role.")
        return claims
    return dependency

@app.get("/physician-only")
async def physician_only(claims: dict = Depends(role_required("physician"))):
    return {"msg": "Hello Doctor!"}
```

**`require_role` decorator.** Order matters (GAIT-SEC-070): the route
decorator goes on top and `require_role` directly below it. FastAPI's route
decorator registers the function it is handed; if `require_role` sits above
it, FastAPI registers the unwrapped function and the role is never checked.

```python
from gait_sdk.permissions import require_role

@app.get("/physician-only-decorated")   # 1. route decorator on top
@require_role("physician")              # 2. require_role below it
async def physician_only_decorated(claims: dict = Depends(verify_token)):
    return {"msg": "Hello Doctor!"}
```

The wrapped function MUST receive its verified claims via a `claims` keyword
argument, and that argument MUST be `Depends(verify_token)` (or another
dependency that verifies the token). `require_role` checks whatever `claims`
it is given; it does not verify them itself (GAIT-SEC-073).

Without DRF installed, `HasRole("physician").has_permission(claims)` can also
be called directly against verified claims (see the shape note above).

`require_role` raises `HTTPException(403)` (never calling the wrapped
function) if `claims` is missing, not a dict, has a missing/empty `role`, or
its `role` doesn't match. It works on `async def` and plain `def` routes. It
raises at decoration time, rather than silently doing nothing, if FastAPI
itself isn't installed (`RuntimeError`) or if it decorates something that is
not a function (`TypeError`).

---

Maintained by **Anthony Narine**  
© 2025 — Auth Integration Project
