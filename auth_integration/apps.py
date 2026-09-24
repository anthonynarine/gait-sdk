# Filename: auth_integration/apps.py
"""Django app config: validate verifier configuration at startup.

With GAIT_TOKEN_VERIFIER=jwks, a missing GAIT_JWKS_URL / GAIT_ISSUER /
GAIT_AUDIENCE stops the service at startup instead of failing every request.
Only imported by Django (via INSTALLED_APPS = [..., "auth_integration"]).
"""

from django.apps import AppConfig


class AuthIntegrationConfig(AppConfig):
    name = "auth_integration"
    verbose_name = "Gait auth integration"

    def ready(self):
        from auth_integration.verification import load_verifier_config

        load_verifier_config()  # raises AuthConfigurationError on misconfiguration
