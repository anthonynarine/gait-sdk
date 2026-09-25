# 🧪 gait_sdk Test Suite — Client + conftest.py Overview

## 📘 Purpose
This document explains how the **`tests/test_client.py`** module validates the core functionality of the `validate_token()` function in `gait_sdk.client`, and how the **`conftest.py`** file provides a stable, framework-agnostic test environment.

---

## 🧱 1. Test Module — `tests/test_client.py`

### ✅ Goal
To verify that `validate_token()` correctly handles **four major response scenarios** when communicating with the external **Gait Auth API** `/whoami/` endpoint.

### 🧩 Covered Scenarios
| Test | Description | Expected Result |
|------|--------------|-----------------|
| `test_validate_token_success` | Simulates a successful `/whoami/` response (HTTP 200). | Returns valid user claims dict. |
| `test_validate_token_invalid` | Simulates an invalid or expired token (HTTP 401). | Raises `InvalidTokenError`. |
| `test_validate_token_unreachable` | Simulates a network failure or timeout. | Raises `AuthServiceUnavailable`. |
| `test_validate_token_malformed_json` | Simulates invalid JSON body in a 200 response. | Raises `AuthServiceUnavailable`. |

### 🧰 Implementation Notes
- Uses **pytest** and **async/await** for non-blocking test execution.
- Mocked `httpx.AsyncClient.get()` with `monkeypatch` instead of `httpx-mock` (for environments without external dependencies).
- Automatically injects fake `GAIT_AUTH_URL` and `GAIT_TIMEOUT` using a fixture.

Example:
```python
@pytest.fixture(autouse=True)
def mock_env(monkeypatch):
    monkeypatch.setenv("GAIT_AUTH_URL", "https://dummy-auth.com/api")
    monkeypatch.setenv("GAIT_TIMEOUT", "5")
```

This ensures the environment variables are always available, even outside Django.

---

## ⚙️ 2. Test Environment Setup — `tests/conftest.py`

### 🧭 Purpose
`conftest.py` acts as a **test bootstrap file** that automatically prepares the runtime environment **before** pytest collects or executes any tests.

This avoids repetitive setup code in each module and prevents import errors when `gait_sdk.settings` tries to access Django settings.

### 🧱 File Contents
```python
# ✅ Filename: tests/conftest.py
import os
import sys
import pytest

# Step 1: Ensure gait_sdk is importable
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Step 2: Mock Django settings module
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "fake.settings")

# Step 3: Provide safe defaults for required environment variables
os.environ.setdefault("GAIT_AUTH_URL", "https://dummy-auth.com/api")
os.environ.setdefault("GAIT_TIMEOUT", "5")

@pytest.fixture(autouse=True)
def setup_env(monkeypatch):
    """Inject mock environment into all tests automatically."""
    monkeypatch.setenv("GAIT_AUTH_URL", "https://dummy-auth.com/api")
    monkeypatch.setenv("GAIT_TIMEOUT", "5")
```

### 🔍 What It Fixes
| Issue | Solution |
|--------|-----------|
| `ImproperlyConfigured` error from Django settings | Adds fake `DJANGO_SETTINGS_MODULE` so Django doesn’t crash when imported indirectly. |
| Missing `GAIT_AUTH_URL` or `GAIT_TIMEOUT` | Automatically sets defaults for all tests. |
| Manual import path setup | Ensures `gait_sdk` is in `sys.path`. |

### ✅ Benefits
- Zero manual setup needed per test file.
- Works seamlessly in **Django or standalone FastAPI** contexts.
- Ensures consistency and reliability across all test modules.

---

## 🧠 3. Running Tests

### ▶️ Run All Tests
```bash
pytest -v -s
```

### ▶️ Run Specific Module
```bash
pytest -v -s tests/test_client.py
```

Expected Output:
```
tests/test_client.py::test_validate_token_success PASSED
tests/test_client.py::test_validate_token_invalid PASSED
tests/test_client.py::test_validate_token_unreachable PASSED
tests/test_client.py::test_validate_token_malformed_json PASSED
```

---

## 🧾 Summary
| File | Purpose |
|------|----------|
| `tests/test_client.py` | Tests async JWT validation logic with mocked responses. |
| `tests/conftest.py` | Provides environment setup, Django isolation, and consistent configuration for all tests. |

With these two files, your **Phase 2 Testing Plan** achieves full isolation from Django while retaining accurate, real-world validation coverage for `gait_sdk.client`.

