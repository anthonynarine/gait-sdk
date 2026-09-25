"""
auth_integration -- DEPRECATED compatibility alias for `gait_sdk`
=================================================================

The package was renamed to `gait_sdk` in 0.5.0. This shim keeps every old
import path working for one release so consumers can migrate in their own
commit:

    import auth_integration.verification      -> gait_sdk.verification
    "auth_integration.authentication.ExternalJWTAuthentication"  (DRF setting)
    INSTALLED_APPS = [..., "auth_integration"]

Old names resolve to the SAME module objects as the new ones (not copies),
so process-wide state -- the configured token verifier and its JWKS cache,
the Django bearer cache -- is shared no matter which name a caller used.

Scheduled for removal in 0.6.0. Migrate: replace `auth_integration` with
`gait_sdk` in imports, settings strings, and INSTALLED_APPS.
"""

from __future__ import annotations

import importlib
import importlib.abc
import importlib.util
import sys
import warnings

_OLD = "auth_integration"
_NEW = "gait_sdk"

warnings.warn(
    "The 'auth_integration' package was renamed to 'gait_sdk' (0.5.0). "
    "The old name is a deprecated alias and will be removed in 0.6.0.",
    DeprecationWarning,
    stacklevel=2,
)


class _GaitSdkAliasFinder(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """Resolve `auth_integration.<x>` to the already-importable `gait_sdk.<x>` module object."""

    def find_spec(self, fullname, path=None, target=None):
        if fullname.startswith(_OLD + "."):
            if importlib.util.find_spec(_NEW + fullname[len(_OLD):]) is None:
                return None
            return importlib.util.spec_from_loader(fullname, self)
        return None

    def create_module(self, spec):
        # Return the real gait_sdk module; the import system registers it in
        # sys.modules under the old name too, so both names share one object.
        return importlib.import_module(_NEW + spec.name[len(_OLD):])

    def exec_module(self, module):
        # Already executed when imported under its real name.
        pass


if not any(isinstance(f, _GaitSdkAliasFinder) for f in sys.meta_path):
    sys.meta_path.insert(0, _GaitSdkAliasFinder())

from gait_sdk import *  # noqa: E402,F401,F403
from gait_sdk import __version__  # noqa: E402,F401
