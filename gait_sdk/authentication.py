# Filename: gait_sdk/authentication.py
"""
gait_sdk.authentication
===============================

Public, stable DRF authentication entrypoint.

Downstream services should reference:
- gait_sdk.authentication.ExternalJWTAuthentication

The implementation lives in:
- gait_sdk.django.authentication

This re-export layer lets us refactor internal modules without breaking consumers.
"""


from gait_sdk.django.authentication import (  
    ClaimsUser,
    ExternalJWTAuthentication,
)
