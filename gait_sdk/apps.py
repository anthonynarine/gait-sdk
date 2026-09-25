# Filename: gait_sdk/apps.py
"""Django app config: validate verifier configuration at startup.

With GAIT_TOKEN_VERIFIER=jwks, a missing GAIT_JWKS_URL / GAIT_ISSUER /
GAIT_AUDIENCE stops the service at startup instead of failing every request.
Only imported by Django (via INSTALLED_APPS = [..., "gait_sdk"]).
"""

from django.apps import AppConfig


class GaitSdkConfig(AppConfig):
    name = "gait_sdk"
    verbose_name = "Gait SDK"

    def ready(self):
        from gait_sdk.verification import load_verifier_config

        load_verifier_config()  # raises AuthConfigurationError on misconfiguration
