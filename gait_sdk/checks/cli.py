"""`gait-check`: run gait-sdk's built-in checks and report them to Gait.

    gait-check --pack django --settings mysite.settings --dry-run
    gait-check --pack django --settings mysite.settings --run-id ci:$SHA:$JOB
    gait-check --pack fastapi --app mypackage.main:app --pack deps

`python manage.py gait_check` takes the same flags (Django's own --settings
applies there; no --app, and it runs the django and deps packs by default)
and shares this code.

Exit codes:
    0  nothing at or above --fail-on
    1  at least one check at or above --fail-on (--fail-on-unknown also
       counts unknown/error)
    2  delivery failure: credential rejected (401), Gait unreachable after
       retries, or any per-check 400
    3  usage or configuration error, or an --environment mismatch
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any, Callable, Optional, Sequence, TextIO

from gait_sdk.checks import engine

AVAILABLE_PACKS = engine.AVAILABLE_PACKS
CLI_DEFAULT_PACKS = ("django",)
# manage.py gait_check: the app is already the Django project, so FastAPI doesn't apply.
MANAGEMENT_PACKS = ("django", "deps")
DEPS_TOOLS = ("pip-audit", "osv-scanner")


class _UsageExit(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    """argparse exits 2 on bad flags; gait-check reserves 2 for delivery failures."""

    def error(self, message: str):  # type: ignore[override]
        raise _UsageExit(message)


def add_arguments(parser: argparse.ArgumentParser, *, include_settings: bool = True, management: bool = False) -> None:
    if management:
        pack_help = "Check pack to run (repeatable): django, deps. Default: both."
    else:
        pack_help = "Check pack to run (repeatable): django, fastapi, deps. Default: django."
    parser.add_argument("--pack", action="append", dest="packs", metavar="PACK", help=pack_help)
    if include_settings:
        parser.add_argument(
            "--settings", dest="settings_module", metavar="MODULE",
            help="Django settings module (sets DJANGO_SETTINGS_MODULE, then django.setup()).",
        )
    if not management:
        parser.add_argument(
            "--app", metavar="MODULE:ATTR",
            help="The FastAPI app for --pack fastapi, e.g. mypackage.main:app. Imported only; never started.",
        )
    parser.add_argument(
        "--strict", action="store_true",
        help="Stricter rules where a check has them (FastAPI docs exposed in production: FAIL instead of WARNING).",
    )
    parser.add_argument(
        "--deps-tool", choices=DEPS_TOOLS, default="pip-audit",
        help="Scanner for --pack deps (default: pip-audit).",
    )
    parser.add_argument(
        "--no-batch", action="store_true",
        help="Send one request per check even if Gait supports batches.",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Run the checks and print the exact payloads that would be sent. Sends nothing; needs no credential.",
    )
    parser.add_argument(
        "--no-send", action="store_true",
        help="Run the checks and gate on the results without contacting Gait.",
    )
    parser.add_argument(
        "--environment", choices=engine.VALID_ENVIRONMENTS,
        help="When sending: an assertion that the credential's Application is in this environment "
             "(exit 3 on mismatch). With --dry-run/--no-send: the environment to evaluate (default production).",
    )
    parser.add_argument("--json", action="store_true", dest="as_json", help="Print a JSON report.")
    parser.add_argument(
        "--fail-on", choices=engine.FAIL_ON_CHOICES, default="fail",
        help="Exit 1 when a result is at or above this level (default: fail).",
    )
    parser.add_argument(
        "--fail-on-unknown", action="store_true",
        help="Also exit 1 on unknown or error outcomes.",
    )
    parser.add_argument(
        "--run-id", metavar="ID",
        help="Source reference for every signal in this run: letters, digits and : . _ - (max 128). Default run:<uuid4>. "
             "In CI use something like ci:<sha>:<job>.",
    )
    parser.add_argument("--only", action="append", metavar="CHECK_ID", help="Run only this check (repeatable).")
    parser.add_argument("--skip", action="append", metavar="CHECK_ID", help="Skip this check (repeatable).")


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="gait-check", description="Run gait-sdk's built-in security checks.")
    add_arguments(parser, include_settings=True)
    return parser


# -----------------------------------------------------------------------------
# Output
# -----------------------------------------------------------------------------
def _facts_text(facts: dict[str, Any]) -> str:
    parts = []
    for name, value in facts.items():
        if isinstance(value, bool):
            value = "yes" if value else "no"
        elif isinstance(value, list):
            value = ",".join(_record_text(v) if isinstance(v, dict) else str(v) for v in value) or "-"
        parts.append(f"{name}={value}")
    return " ".join(parts)


def _record_text(record: dict[str, Any]) -> str:
    """e.g. pip==23.1.2:PYSEC-2023-228(fix 23.3) for a deps item."""
    text = f"{record.get('package', '?')}=={record.get('version', '?')}:{record.get('advisory_id', '?')}"
    if record.get("fixed_in"):
        text += f"(fix {record['fixed_in']})"
    return text


def _status(report: engine.RunReport, item: engine.CheckResult) -> str:
    if item.error:
        return item.error
    if item.sent:
        return "sent"
    return "not sent" if report.send else ""


def render_table(report: engine.RunReport, out: TextIO, *, dry_run: bool) -> None:
    mode = "dry run" if dry_run else ("sending" if report.send else "not sending")
    app = report.application or "-"
    out.write(f"gait-check  run={report.run_id}  application={app}  environment={report.environment}  ({mode})\n\n")
    id_w = max([len(r.check_id) for r in report.results] + [5])
    out.write(f"{'CHECK'.ljust(id_w)}  {'RESULT'.ljust(13)}  {'OUTCOME'.ljust(14)}  FACTS\n")
    for item in report.results:
        line = f"{item.check_id.ljust(id_w)}  {item.result.ljust(13)}  {item.outcome.ljust(14)}  {_facts_text(item.facts)}"
        status = _status(report, item)
        if status:
            line += f"  [{status}]"
        out.write(line.rstrip() + "\n")
    counts: dict[str, int] = {}
    for item in report.results:
        counts[item.result] = counts.get(item.result, 0) + 1
    summary = ", ".join(f"{counts[k]} {k}" for k in ("PASS", "FAIL", "WARNING", "INFORMATIONAL") if k in counts)
    out.write(f"\n{len(report.results)} checks: {summary}\n")
    if report.unmapped_django_ids:
        out.write(
            "Unmapped Django check ids (shown here only, not sent): "
            + ", ".join(report.unmapped_django_ids) + "\n"
        )
    if report.delivery_error:
        out.write(f"Delivery failed: {report.delivery_error}\n")
    if dry_run:
        out.write("\nSignals that would be sent (batched when Gait supports it):\n")
        for body in report.request_bodies():
            out.write(json.dumps(body, sort_keys=False) + "\n")


def render_json(report: engine.RunReport, out: TextIO, *, dry_run: bool) -> None:
    data = report.as_dict()
    if dry_run:
        data["dry_run"] = True
        data["requests"] = report.request_bodies()
    if report.delivery_error:
        data["delivery_error"] = report.delivery_error
    out.write(json.dumps(data, indent=2) + "\n")


# -----------------------------------------------------------------------------
# Running
# -----------------------------------------------------------------------------
def run(
    options: dict[str, Any],
    *,
    out: TextIO,
    err: TextIO,
    sleep: Callable[[float], None] = time.sleep,
    allowed_packs: Sequence[str] = AVAILABLE_PACKS,
    default_packs: Sequence[str] = CLI_DEFAULT_PACKS,
) -> int:
    """Run with parsed options (shared by the CLI and the management command)."""
    dry_run = bool(options.get("dry_run"))
    send = not (dry_run or options.get("no_send"))
    try:
        packs = list(dict.fromkeys(options.get("packs") or default_packs))
        for pack in packs:
            if pack not in allowed_packs:
                raise engine.UsageError(
                    f"Unknown or unsupported pack here: {pack!r} (available: {', '.join(allowed_packs)})."
                )
        if "fastapi" in packs and not options.get("app"):
            raise engine.UsageError("--pack fastapi needs --app package.module:app.")
        report = engine.execute(
            packs=packs,
            environment=options.get("environment"),
            send=send,
            run_id=options.get("run_id"),
            only=options.get("only"),
            skip=options.get("skip"),
            sleep=sleep,
            strict=bool(options.get("strict")),
            app=options.get("app"),
            deps_tool=options.get("deps_tool") or "pip-audit",
            batch=not options.get("no_batch"),
        )
        code = engine.exit_code(report, options.get("fail_on") or "fail", bool(options.get("fail_on_unknown")))
    except engine.UsageError as exc:
        err.write(f"gait-check: {exc}\n")
        return engine.EXIT_USAGE
    except engine.DeliveryError as exc:
        err.write(f"gait-check: {exc}\n")
        return engine.EXIT_DELIVERY

    if options.get("as_json"):
        render_json(report, out, dry_run=dry_run)
    else:
        render_table(report, out, dry_run=dry_run)
    return code


def setup_django(settings_module: Optional[str]) -> None:
    """Configure Django for the CLI. Raises engine.UsageError on failure."""
    try:
        import django
        from django.conf import settings
    except ImportError:
        raise engine.UsageError("The django pack needs Django: pip install 'gait-sdk[django]'.") from None

    if settings_module:
        os.environ["DJANGO_SETTINGS_MODULE"] = settings_module
    elif not settings.configured and not os.environ.get("DJANGO_SETTINGS_MODULE"):
        raise engine.UsageError("Pass --settings <module> or set DJANGO_SETTINGS_MODULE.")
    # Console scripts don't put the working directory on sys.path; manage.py does.
    cwd = os.getcwd()
    if cwd not in sys.path:
        sys.path.insert(0, cwd)
    try:
        django.setup()
    except Exception as exc:
        raise engine.UsageError(f"Django setup failed ({type(exc).__name__}).") from None


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    out: Optional[TextIO] = None,
    err: Optional[TextIO] = None,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except _UsageExit as exc:
        err.write(f"gait-check: {exc}\n")
        return engine.EXIT_USAGE
    options = vars(args)
    packs = options.get("packs") or list(CLI_DEFAULT_PACKS)
    unknown = [p for p in packs if p not in AVAILABLE_PACKS]
    if unknown:
        err.write(f"gait-check: unknown pack {unknown[0]!r} (available: {', '.join(AVAILABLE_PACKS)})\n")
        return engine.EXIT_USAGE
    if "django" in packs:
        try:
            setup_django(options.get("settings_module"))
        except engine.UsageError as exc:
            err.write(f"gait-check: {exc}\n")
            return engine.EXIT_USAGE
    return run(options, out=out, err=err, sleep=sleep)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
