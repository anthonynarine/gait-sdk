# 🧩 Auth Integration — utils.py

## Overview
Contains helper functions for safely extracting and checking user claims across frameworks.

---

## Key Functions

| Function | Description |
|-----------|-------------|
| `get_user_claims(request)` | Extracts validated claims from Django or FastAPI request |
| `has_role(request, role)` | Returns `True` if user matches role |
| `has_any_role(request, roles)` | Returns `True` if user has one of the roles |

---

Maintained by **Anthony Narine**  
© 2025 — Auth Integration Project
