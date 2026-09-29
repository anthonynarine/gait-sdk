"""The check engine: run packs, build and validate payloads, deliver them.

Shared by the `gait-check` CLI and `python manage.py gait_check`.

Flow:
1. Decide the environment. When sending, it is the verified Application's
   own environment (`verify_application()`); `--environment` is only an
   assertion and a mismatch is a usage error. With `--dry-run`/`--no-send`
   it is `--environment`, else "production".
2. Run the selected checks. Env-gated checks are `not_applicable` with no
   facts in the "local" and "test" environments. An exception inside one
   check becomes outcome "error" with no facts; the rest still run.
3. Build one payload per check and validate it with
   `registry.validate_payload` BEFORE anything is sent. An invalid payload
   is never sent; it is reported as a local error.
4. Send each result as its own signal (signal_type = check id,
   source_reference = run id). Only `AuthServiceUnavailable` is retried,
   with the same source_reference (the server is idempotent on
   (application, signal_type, source_reference)). 400 and 401 are never
   retried. A 400 on one check doesn't stop the others.

Nothing here ever logs or prints a setting value.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional, Sequence

from gait_sdk.checks import registry

logger = logging.getLogger("gait_sdk.checks")

# Retry delays (seconds) after an AuthServiceUnavailable: one first attempt,
# then up to three retries after 1, 2 and 4 seconds.
RETRY_DELAYS: tuple[float, ...] = (1, 2, 4)

VALID_ENVIRONMENTS = ("local", "test", "ci", "staging", "production")
GATED_ENVIRONMENTS = frozenset({"local", "test"})
DEFAULT_OFFLINE_ENVIRONMENT = "production"
MAX_RUN_ID_LENGTH = 256
FAIL_ON_CHOICES = ("fail", "warning", "never")

EXIT_OK = 0
EXIT_THRESHOLD = 1
EXIT_DELIVERY = 2
EXIT_USAGE = 3

_THRESHOLDS = {
    "fail": frozenset({"FAIL"}),
    "warning": frozenset({"FAIL", "WARNING"}),
    "never": frozenset(),
}


class UsageError(Exception):
    """Bad flags or configuration. Exit code 3."""


class EnvironmentMismatch(UsageError):
    """--environment doesn't match the credential's Application. Exit code 3."""


class DeliveryError(Exception):
    """The run couldn't be delivered at all (credential rejected, Gait unreachable). Exit code 2."""


@dataclass
class CheckResult:
    check_id: str
    outcome: str
    facts: dict[str, Any]
    result: str
    sent: bool = False
    error: Optional[str] = None
    payload: Optional[dict[str, Any]] = None
    valid: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.check_id,
            "outcome": self.outcome,
            "result": self.result,
            "facts": self.facts,
            "sent": self.sent,
            "error": self.error,
        }


@dataclass
class RunReport:
    run_id: str
    environment: str
    application: Optional[str] = None
    results: list[CheckResult] = field(default_factory=list)
    unmapped_django_ids: list[str] = field(default_factory=list)
    send: bool = False
    delivery_failed: bool = False
    delivery_error: Optional[str] = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "application": self.application,
            "environment": self.environment,
            "results": [r.as_dict() for r in self.results],
            "unmapped_django_ids": list(self.unmapped_django_ids),
        }

    def request_bodies(self) -> list[dict[str, Any]]:
        """The exact request bodies that would be (or were) POSTed."""
        return [signal_body(r, self.run_id) for r in self.results if r.valid and r.payload is not None]


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def default_run_id() -> str:
    return f"run:{uuid.uuid4()}"


def sdk_version() -> str:
    from gait_sdk import __version__

    version = str(__version__)[:20]
    return version if registry.VERSION_RE.match(version) else "0.0.0"


def pack_module(pack: str):
    if pack == "django":
        from gait_sdk.checks import django_pack

        return django_pack
    raise UsageError(f"Unknown or unsupported pack: {pack!r} (available: django).")


def select_check_ids(
    packs: Sequence[str],
    only: Optional[Iterable[str]] = None,
    skip: Optional[Iterable[str]] = None,
) -> list[str]:
    available = [cid for pack in packs for cid in registry.check_ids(pack)]
    only = list(only or [])
    skip = list(skip or [])
    for cid in only + skip:
        if cid not in available:
            raise UsageError(f"Unknown check id for the selected packs: {cid!r}.")
    selected = [cid for cid in available if (not only or cid in only) and cid not in skip]
    if not selected:
        raise UsageError("No checks selected.")
    return selected


def _clamp_facts(check_id: str, facts: dict[str, Any]) -> dict[str, Any]:
    """Clamp int facts into the spec's bounds (e.g. 5000 hosts -> 1000)."""
    allowed = registry.allowed_facts(check_id)
    clamped = {}
    for name, value in facts.items():
        spec = allowed.get(name)
        if spec is not None and spec["type"] == "int" and isinstance(value, int) and not isinstance(value, bool):
            value = min(max(value, spec["min"]), spec["max"])
        clamped[name] = value
    return clamped


def build_payload(check_id: str, outcome: str, facts: dict[str, Any]) -> dict[str, Any]:
    definition = registry.get_check(check_id)
    return {
        "v": registry.PAYLOAD_VERSION,
        "pack": definition.pack,
        "pack_version": registry.PACK_VERSIONS[definition.pack],
        "sdk_version": sdk_version(),
        "outcome": outcome,
        "facts": facts,
    }


def signal_body(result: CheckResult, run_id: str) -> dict[str, Any]:
    return {
        "signal_type": result.check_id,
        "result": result.result,
        "source_reference": run_id,
        "payload": result.payload,
    }


# -----------------------------------------------------------------------------
# Running checks
# -----------------------------------------------------------------------------
def run_checks(
    packs: Sequence[str],
    environment: str,
    only: Optional[Iterable[str]] = None,
    skip: Optional[Iterable[str]] = None,
) -> tuple[list[CheckResult], list[str]]:
    """Run the selected checks and build a validated payload for each.

    Returns (results, unmapped Django ids).
    """
    selected = select_check_ids(packs, only, skip)
    gated = environment in GATED_ENVIRONMENTS
    results: list[CheckResult] = []
    unmapped: list[str] = []

    for pack in packs:
        module = pack_module(pack)
        pack_ids = [cid for cid in selected if registry.get_check(cid).pack == pack]
        if not pack_ids:
            continue
        django_ids: dict[str, list[str]] = {}
        deploy = getattr(module, "deploy_check_ids", None)
        if deploy is not None:
            django_ids, pack_unmapped, deploy_error = deploy()
            unmapped.extend(i for i in pack_unmapped if i not in unmapped)
            if deploy_error:
                logger.warning("Django deployment checks could not run (%s).", deploy_error)

        for check_id in pack_ids:
            definition = registry.get_check(check_id)
            if definition.env_gated and gated:
                outcome, facts = "not_applicable", {}
            else:
                try:
                    outcome, facts = module.CHECKS[check_id]()
                    facts = dict(facts)
                    ids = django_ids.get(check_id) or []
                    if ids:
                        facts["django_ids"] = ids[: registry.limits()["max_list_items"]]
                    facts = _clamp_facts(check_id, facts)
                except Exception as exc:
                    # Class name only: an exception message could quote a setting.
                    logger.warning("Check %s raised %s.", check_id, type(exc).__name__)
                    outcome, facts = "error", {}
            results.append(_finish(check_id, outcome, facts))
    return results, unmapped


def _finish(check_id: str, outcome: str, facts: dict[str, Any]) -> CheckResult:
    result = registry.result_for_outcome(outcome)
    payload = build_payload(check_id, outcome, facts)
    item = CheckResult(check_id=check_id, outcome=outcome, facts=facts, result=result, payload=payload)
    try:
        registry.validate_payload(check_id, payload, result=result)
    except registry.PayloadValidationError as exc:
        item.valid = False
        item.error = f"local validation failed ({exc.field}); not sent"
    return item


# -----------------------------------------------------------------------------
# Sending
# -----------------------------------------------------------------------------
def _call_with_retry(fn: Callable[[], Any], sleep: Callable[[float], None]) -> Any:
    from gait_sdk.exceptions import AuthServiceUnavailable

    for delay in (*RETRY_DELAYS, None):
        try:
            return fn()
        except AuthServiceUnavailable:
            if delay is None:
                raise
            sleep(delay)


def resolve_application(credential: Optional[str], sleep: Callable[[float], None]):
    """Verify the credential and return its ApplicationPrincipal."""
    from gait_sdk import application
    from gait_sdk.exceptions import AuthServiceUnavailable, InvalidApplicationCredentialError

    raw = credential if credential is not None else application.GAIT_APPLICATION_CREDENTIAL
    if not raw:
        raise UsageError(
            "GAIT_APPLICATION_CREDENTIAL is not configured. Set it, or use --dry-run / --no-send."
        )
    try:
        return _call_with_retry(lambda: asyncio.run(application.verify_application(credential)), sleep)
    except InvalidApplicationCredentialError:
        raise DeliveryError("The application credential was rejected (401).") from None
    except AuthServiceUnavailable:
        raise DeliveryError("Gait is unreachable (retries exhausted).") from None


def deliver(
    results: Sequence[CheckResult],
    run_id: str,
    *,
    credential: Optional[str] = None,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[bool, Optional[str]]:
    """Send each valid result as its own signal. Returns (failed, reason)."""
    from gait_sdk import security
    from gait_sdk.exceptions import (
        AuthServiceUnavailable,
        InvalidApplicationCredentialError,
        SecuritySignalRejected,
    )

    failed = any(not r.valid for r in results)
    reason: Optional[str] = "a payload failed local validation" if failed else None
    stop: Optional[str] = None

    for item in results:
        if not item.valid:
            continue
        if stop is not None:
            item.error = f"not sent: {stop}"
            continue

        def send(item: CheckResult = item) -> Any:
            return asyncio.run(
                security.send_security_signal(
                    signal_type=item.check_id,
                    result=item.result,
                    source_reference=run_id,
                    payload=item.payload,
                    credential=credential,
                )
            )

        try:
            _call_with_retry(send, sleep)
            item.sent = True
        except SecuritySignalRejected:
            item.error = "rejected by Gait (400)"
            failed, reason = True, reason or "Gait rejected at least one check (400)"
        except InvalidApplicationCredentialError:
            item.error = "credential rejected (401)"
            failed, reason = True, "the application credential was rejected (401)"
            stop = "credential rejected"
        except AuthServiceUnavailable:
            item.error = "Gait unreachable after retries"
            failed, reason = True, "Gait is unreachable (retries exhausted)"
            stop = "Gait unreachable"
    return failed, reason


# -----------------------------------------------------------------------------
# One full run
# -----------------------------------------------------------------------------
def execute(
    *,
    packs: Sequence[str] = ("django",),
    environment: Optional[str] = None,
    send: bool = True,
    run_id: Optional[str] = None,
    only: Optional[Iterable[str]] = None,
    skip: Optional[Iterable[str]] = None,
    credential: Optional[str] = None,
    sleep: Callable[[float], None] = time.sleep,
) -> RunReport:
    """Run the packs and (when `send`) deliver the results.

    Raises UsageError / EnvironmentMismatch (exit 3) or DeliveryError when
    the Application itself can't be verified (exit 2). Per-check delivery
    failures are recorded on the report instead.
    """
    packs = list(dict.fromkeys(packs or ["django"]))
    for pack in packs:
        pack_module(pack)
    run_id = run_id if run_id is not None else default_run_id()
    if not isinstance(run_id, str) or not run_id.strip() or len(run_id) > MAX_RUN_ID_LENGTH:
        raise UsageError(f"--run-id must be 1-{MAX_RUN_ID_LENGTH} characters.")
    if environment is not None and environment not in VALID_ENVIRONMENTS:
        raise UsageError(f"--environment must be one of: {', '.join(VALID_ENVIRONMENTS)}.")
    select_check_ids(packs, only, skip)  # fail on bad --only/--skip before any network call

    application_slug = None
    if send:
        principal = resolve_application(credential, sleep)
        if environment is not None and environment != principal.environment:
            raise EnvironmentMismatch(
                f"--environment {environment} doesn't match the credential's Application "
                f"environment ({principal.environment})."
            )
        effective_env = principal.environment
        application_slug = principal.application_slug
    else:
        effective_env = environment or DEFAULT_OFFLINE_ENVIRONMENT

    results, unmapped = run_checks(packs, effective_env, only, skip)
    report = RunReport(
        run_id=run_id,
        environment=effective_env,
        application=application_slug,
        results=results,
        unmapped_django_ids=unmapped,
        send=send,
    )
    if send:
        report.delivery_failed, report.delivery_error = deliver(results, run_id, credential=credential, sleep=sleep)
    elif any(not r.valid for r in results):
        report.delivery_failed, report.delivery_error = True, "a payload failed local validation"
    return report


def exit_code(report: RunReport, fail_on: str = "fail", fail_on_unknown: bool = False) -> int:
    if fail_on not in _THRESHOLDS:
        raise UsageError(f"--fail-on must be one of: {', '.join(FAIL_ON_CHOICES)}.")
    if report.delivery_failed:
        return EXIT_DELIVERY
    threshold = _THRESHOLDS[fail_on]
    for item in report.results:
        if item.result in threshold:
            return EXIT_THRESHOLD
        if fail_on_unknown and item.outcome in {"unknown", "error"}:
            return EXIT_THRESHOLD
    return EXIT_OK
