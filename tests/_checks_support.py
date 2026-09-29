"""Shared setup for the check-pack tests (tests/test_checks_*.py).

Configures Django from tests/checks_settings.py (if nothing configured it
first) and gives each test a fresh copy of those settings plus overrides.
All HTTP is mocked: `fake_gait()` replaces verify_application and
send_security_signal, and nothing here opens a socket.
"""

from __future__ import annotations

import contextlib
from typing import Any, Optional

import django
from django.conf import settings
from django.test.utils import override_settings

from tests import checks_settings

BASE_SETTINGS = {
    name: getattr(checks_settings, name) for name in dir(checks_settings) if name.isupper()
}
SECRET_KEY = checks_settings.SECRET_KEY

if not settings.configured:
    settings.configure(**BASE_SETTINGS)
django.setup()


@contextlib.contextmanager
def django_settings(**overrides: Any):
    """BASE_SETTINGS with `overrides`, regardless of what configured Django first."""
    # DATABASES only when a test asks for it (Django warns on every DATABASES override).
    base = {k: v for k, v in BASE_SETTINGS.items() if k != "DATABASES"}
    with override_settings(**{**base, **overrides}):
        yield


class FakeGait:
    """Records calls; scripted responses per check id."""

    def __init__(self, environment: str = "production", slug: str = "lumen-api"):
        self.environment = environment
        self.slug = slug
        self.verify_calls = 0
        self.verify_errors: list[Exception] = []
        self.sent: list[dict[str, Any]] = []
        # check id -> list of exceptions to raise on successive attempts
        self.errors: dict[str, list[Exception]] = {}
        self.always: dict[str, Exception] = {}

    async def verify_application(self, credential: Optional[str] = None):
        from gait_sdk.application import ApplicationPrincipal

        self.verify_calls += 1
        if self.verify_errors:
            raise self.verify_errors.pop(0)
        return ApplicationPrincipal(
            application_id="11111111-1111-1111-1111-111111111111",
            application_slug=self.slug,
            organization_id="22222222-2222-2222-2222-222222222222",
            organization_slug="acme",
            environment=self.environment,
        )

    async def send_security_signal(self, *, signal_type, result, source_reference, payload=None, credential=None):
        from gait_sdk.security import SecuritySignalResult

        self.sent.append(
            {"signal_type": signal_type, "result": result, "source_reference": source_reference, "payload": payload}
        )
        if signal_type in self.always:
            raise self.always[signal_type]
        queue = self.errors.get(signal_type)
        if queue:
            raise queue.pop(0)
        return SecuritySignalResult(
            signal_id=f"sig-{len(self.sent)}",
            control_key="TENANT.CHECK." + signal_type.split(".", 1)[1],
            evidence_id=None,
            received_at="2026-09-28T12:00:00Z",
        )

    def attempts(self, check_id: str) -> list[dict[str, Any]]:
        return [call for call in self.sent if call["signal_type"] == check_id]


def install_fake_gait(monkeypatch, fake: FakeGait, credential: Optional[str] = "app-credential-value"):
    import gait_sdk.application as application
    import gait_sdk.security as security

    monkeypatch.setattr(application, "GAIT_APPLICATION_CREDENTIAL", credential)
    monkeypatch.setattr(application, "verify_application", fake.verify_application)
    monkeypatch.setattr(security, "send_security_signal", fake.send_security_signal)
    return fake


class SleepRecorder:
    def __init__(self):
        self.calls: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)
