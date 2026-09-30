"""gait_sdk.checks: built-in check packs.

Run them with `gait-check` or `python manage.py gait_check`. Each check
reads your application's own configuration and reports an outcome plus a
few typed facts (booleans, bounded integers, enums). Setting values and
request data are never sent. See docs/CHECKS.md.

- `registry`: the check definitions, loaded from `checks_v1.json` (shared
  byte for byte with the Gait server), and `validate_payload()`.
- `django_pack`, `fastapi_pack`, `deps_pack`: the packs.
- `engine`: runs packs, validates payloads and sends them.
- `cli`: the `gait-check` command.

Importing this package has no side effects and imports nothing else, so
`python -m gait_sdk.checks.registry` runs cleanly. Import the submodules
directly, e.g. `from gait_sdk.checks.registry import validate_payload`.
"""
