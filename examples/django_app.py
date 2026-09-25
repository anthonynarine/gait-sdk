"""A complete Django REST Framework app protected by gait-sdk, in one file.

Run it (from this examples/ folder):

    pip install "gait-sdk[django]"
    python dev_issuer.py serve                  # in another terminal: local stand-in for Gait
    python django_app.py runserver 8002
    curl -H "Authorization: Bearer $(python dev_issuer.py token alice)" http://localhost:8002/me

Everything a real project puts in settings.py is in the settings.configure()
call below.
"""

import sys

from django.conf import settings

settings.configure(
    DEBUG=True,
    SECRET_KEY="example-only-not-secret",
    ROOT_URLCONF=__name__,
    ALLOWED_HOSTS=["localhost", "127.0.0.1"],
    INSTALLED_APPS=[
        "django.contrib.contenttypes",
        "django.contrib.auth",
        "rest_framework",
        "gait_sdk",  # its AppConfig validates the GAIT_* settings at startup
    ],
    REST_FRAMEWORK={
        "DEFAULT_AUTHENTICATION_CLASSES": ["gait_sdk.authentication.ExternalJWTAuthentication"],
        "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
        "UNAUTHENTICATED_USER": None,
    },
    # gait-sdk: verify tokens locally against the (dev) issuer's public keys.
    GAIT_TOKEN_VERIFIER="jwks",
    GAIT_JWKS_URL="http://localhost:9000/.well-known/jwks.json",
    GAIT_ISSUER="http://localhost:9000",
    GAIT_AUDIENCE="urn:gait:example",
)

import django  # noqa: E402

django.setup()

from django.urls import path  # noqa: E402
from rest_framework.decorators import api_view  # noqa: E402
from rest_framework.response import Response  # noqa: E402

# Your app owns authorization (normally your database).
ROLES = {"alice": "editor", "bob": "viewer"}


@api_view(["GET"])
def me(request):
    identity = request.verified_identity  # gait-sdk: WHO this is
    return Response(
        {
            "subject": identity.subject,
            "email": identity.email,
            "your_app_role": ROLES.get(identity.subject, "none"),  # your app: WHAT they may do
        }
    )


@api_view(["POST"])
def create_article(request):
    subject = request.verified_identity.subject
    if ROLES.get(subject) != "editor":
        return Response({"detail": "Editors only."}, status=403)
    return Response({"created_by": subject})


urlpatterns = [path("me", me), path("articles", create_article)]

if __name__ == "__main__":
    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)
