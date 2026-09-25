# ⚙️ Auth Integration — Settings Module (`gait_sdk/settings.py`)

## 🧱 Overview
This module provides a **unified configuration system** for both Django and FastAPI microservices.  
It ensures every service using `gait_sdk` can locate and load the `GAIT_AUTH_URL` safely, regardless of framework.

---

## 🧩 Responsibilities

| Function | Purpose |
|-----------|----------|
| `_get_setting()` | Smart loader that checks Django settings first, then `.env`. |
| `GAIT_AUTH_URL` | URL of the Gait Auth API (used for `/whoami/` validation). |
| `GAIT_TIMEOUT` | Request timeout in seconds (default 5). |

---

## ⚙️ Behavior by Framework

| Framework | Source | Example |
|------------|---------|----------|
| **Django** | Reads from project `settings.py` | `AUTH_API_URL="https://gait.example.com/api"` |
| **FastAPI** | Reads from `.env` via python-decouple | `GAIT_AUTH_URL=https://gait.example.com/api` |

---

## 🔄 Resolution Order
1. Django settings → `AUTH_API_URL` or `GAIT_AUTH_URL`
2. `.env` file → via `python-decouple`
3. Default → Timeout only (`GAIT_TIMEOUT=5`)

---

## 🔐 Security Notes
- Never logs full URLs or tokens.  
- Only logs the domain for sanity checks.  
- No PHI or sensitive info ever printed.

---

## 🧠 Teaching Notes
- **Why?** Because FastAPI doesn’t have Django’s global settings registry.
- **How?** By using `python-decouple`, we achieve parity between frameworks.
- **Result:** All services — Reports (Django), Media (FastAPI), HL7 (FastAPI) — read auth configs consistently.

---

## ✅ Usage Example

### Django (Lumen Reports)
```python
from gait_sdk.settings import GAIT_AUTH_URL, GAIT_TIMEOUT
```
Reads automatically from `core/settings.py`.

### FastAPI (Lumen Media)
```python
from gait_sdk.settings import GAIT_AUTH_URL
print(GAIT_AUTH_URL)  # "https://ant-django-auth.herokuapp.com/api"
```
Reads from `.env` file using `python-decouple`.

---

## 🧩 Integration Diagram

```mermaid
graph TD
  A[Django Settings.py] --> B[_get_setting()]
  C[.env File (FastAPI)] --> B
  B --> D[GAIT_AUTH_URL]
  D --> E[gait_sdk.client.validate_token()]
  E --> F[Gait Auth API (/whoami/)]
```

---

Maintained by **Anthony Narine**  
© 2025 — The Lumen Project
