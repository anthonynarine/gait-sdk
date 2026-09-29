"""`python manage.py gait_check`: run gait-sdk's built-in checks.

Same flags and exit codes as the `gait-check` CLI (Django's own --settings
applies here). Needs "gait_sdk" in INSTALLED_APPS.
"""

from __future__ import annotations

import sys

from django.core.management.base import BaseCommand

from gait_sdk.checks import cli


class Command(BaseCommand):
    help = (
        "Run gait-sdk's built-in security checks and report them to Gait. "
        "Exit codes: 0 ok, 1 a result at or above --fail-on, 2 delivery failure, "
        "3 usage/config error or environment mismatch."
    )
    # The pack runs Django's security checks itself; don't let a failing
    # system check stop the command before it can report.
    requires_system_checks = []

    def add_arguments(self, parser):
        cli.add_arguments(parser, include_settings=False)

    def handle(self, *args, **options):
        code = cli.run(options, out=self.stdout, err=self.stderr)
        if code:
            sys.exit(code)
