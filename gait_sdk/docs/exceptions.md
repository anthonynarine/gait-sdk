# 🚨 Auth Integration — exceptions.py

## Overview
Defines reusable exceptions for authentication failures and service errors.

These are raised by the `client.py` validator and caught by Django or FastAPI adapters.

---

## Exception Classes

| Class | Description | Typical Use |
|--------|-------------|--------------|
| `InvalidTokenError` | Raised when Gait returns 401 (invalid/expired token) | Token rejection |
| `AuthServiceUnavailable` | Raised when Gait is unreachable or misconfigured | Network/service errors |

---

Maintained by **Anthony Narine**  
© 2025 — Auth Integration Project
