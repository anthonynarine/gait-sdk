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
4. Deliver (source_reference = run id):
   - GET the server's accepted signal types once. Checks the server doesn't
     accept are skipped locally ("not supported by this Gait server") and
     don't fail the run. If that call is unavailable or 404 (older
     servers), everything is sent.
   - With a `batch_max`, send chunks of at most that many in one
     all-or-nothing POST each. A 404 on the batch endpoint, no
     `batch_max`, or `--no-batch` means one POST per check
     (`send_security_signal`).
   - Only `AuthServiceUnavailable` is retried, with the same
     source_reference (the server is idempotent on (application,
     signal_type, source_reference)). 400 and 401 are never retried. A 400
     on one check (or one chunk) doesn't stop the others. A 429 on a batch
     waits Retry-After (at most 60 s) once and retries once.

Nothing here ever logs or prints a setting value.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional, Sequence

from gait_sdk.checks import registry

logger = logging.getLogger("gait_sdk.checks")

# Retry delays (seconds) after an AuthServiceUnavailable: one first attempt,
# then up to three retries after 1, 2 and 4 seconds.
RETRY_DELAYS: tuple[float, ...] = (1, 2, 4)
# The longest a 429's Retry-After is honoured, once.
MAX_RATE_LIMIT_WAIT = 60.0
DEFAULT_RATE_LIMIT_WAIT = 1.0

AVAILABLE_PACKS = ("django", "fastapi", "deps")
VALID_ENVIRONMENTS = ("local", "test", "ci", "staging", "production")
GATED_ENVIRONMENTS = frozenset({"local", "test"})
DEFAULT_OFFLINE_ENVIRONMENT = "production"
FAIL_ON_CHOICES = ("fail", "warning", "never")

EXIT_OK = 0
EXIT_THRESHOLD = 1
EXIT_DELIVERY = 2
EXIT_USAGE = 3

NOT_SUPPORTED = "not sent: not supported by this Gait server"

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
class PackContext:
    """Per-run inputs the packs may need."""

    environment: str
    strict: bool = False
    app_path: Optional[str] = None
    app: Any = None
    deps_tool: str = "pip-audit"


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
    supported: bool = True

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
        """The exact signals that would be (or were) sent."""
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
    if pack == "fastapi":
        from gait_sdk.checks import fastapi_pack

        return fastapi_pack
    if pack == "deps":
        from gait_sdk.checks import deps_pack

        return deps_pack
    raise UsageError(f"Unknown pack: {pack!r} (available: {', '.join(AVAILABLE_PACKS)}).")


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
def _call_check(module: Any, check_id: str, ctx: PackContext):
    runner = getattr(module, "run_check", None)
    if runner is not None:
        return runner(check_id, ctx)
    return module.CHECKS[check_id]()


def prepare_packs(packs: Sequence[str], ctx: PackContext) -> None:
    """Pack setup that can fail as a usage error (e.g. a bad --app), before any network call."""
    for pack in packs:
        prepare = getattr(pack_module(pack), "prepare", None)
        if prepare is not None:
            prepare(ctx)


def run_checks(
    packs: Sequence[str],
    environment: str,
    only: Optional[Iterable[str]] = None,
    skip: Optional[Iterable[str]] = None,
    *,
    context: Optional[PackContext] = None,
) -> tuple[list[CheckResult], list[str]]:
    """Run the selected checks and build a validated payload for each.

    Returns (results, unmapped Django ids).
    """
    ctx = context or PackContext(environment=environment)
    ctx.environment = environment
    selected = select_check_ids(packs, only, skip)
    gated = environment in GATED_ENVIRONMENTS
    results: list[CheckResult] = []
    unmapped: list[str] = []

    for pack in packs:
        module = pack_module(pack)
        pack_ids = [cid for cid in selected if registry.get_check(cid).pack == pack]
        if not pack_ids:
            continue
        prepare = getattr(module, "prepare", None)
        if prepare is not None:
            prepare(ctx)
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
                    outcome, facts = _call_check(module, check_id, ctx)
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


def fetch_signal_types(credential: Optional[str], sleep: Callable[[float], None]):
    """The server's accepted types, or None for an older server (404) or when unavailable."""
    from gait_sdk import security
    from gait_sdk.exceptions import (
        AuthServiceUnavailable,
        InvalidApplicationCredentialError,
        SignalEndpointNotFound,
    )

    try:
        info = _call_with_retry(lambda: asyncio.run(security.get_signal_types(credential)), sleep)
    except (SignalEndpointNotFound, AuthServiceUnavailable):
        logger.info("Gait didn't list its accepted check types; sending every check.")
        return None
    except InvalidApplicationCredentialError:
        raise DeliveryError("The application credential was rejected (401).") from None
    if info.check_spec_sha256 and info.check_spec_sha256 != registry.CHECKS_V1_CANONICAL_SHA256:
        logger.warning("This Gait server uses a different check spec; unsupported checks are skipped.")
    return info


class _Delivery:
    """Mutable delivery state for one run."""

    def __init__(self, run_id: str, credential: Optional[str], sleep: Callable[[float], None]):
        self.run_id = run_id
        self.credential = credential
        self.sleep = sleep
        self.failed = False
        self.reason: Optional[str] = None
        self.stop: Optional[str] = None

    def fail(self, reason: str, *, stop: Optional[str] = None, override: bool = False) -> None:
        self.failed = True
        if override or self.reason is None:
            self.reason = reason
        if stop is not None:
            self.stop = stop


def _send_single(items: Sequence[CheckResult], state: _Delivery) -> None:
    from gait_sdk import security
    from gait_sdk.exceptions import (
        AuthServiceUnavailable,
        InvalidApplicationCredentialError,
        SecuritySignalRejected,
    )

    for item in items:
        if state.stop is not None:
            item.error = f"not sent: {state.stop}"
            continue

        def send(item: CheckResult = item) -> Any:
            return asyncio.run(
                security.send_security_signal(
                    signal_type=item.check_id,
                    result=item.result,
                    source_reference=state.run_id,
                    payload=item.payload,
                    credential=state.credential,
                )
            )

        try:
            _call_with_retry(send, state.sleep)
            item.sent = True
        except SecuritySignalRejected:
            item.error = "rejected by Gait (400)"
            state.fail("Gait rejected at least one check (400)")
        except InvalidApplicationCredentialError:
            item.error = "credential rejected (401)"
            state.fail("the application credential was rejected (401)", stop="credential rejected", override=True)
        except AuthServiceUnavailable:
            item.error = "Gait unreachable after retries"
            state.fail("Gait is unreachable (retries exhausted)", stop="Gait unreachable", override=True)


def _rejection_note(exc: Any, chunk: Sequence[CheckResult]) -> str:
    index = getattr(exc, "index", None)
    field_name = getattr(exc, "field", None)
    parts = ["rejected by Gait (400)"]
    if isinstance(index, int) and 0 <= index < len(chunk):
        parts.append(f"batch item {index} ({chunk[index].check_id})")
    if field_name:
        parts.append(f"field {field_name}")
    return ", ".join(parts)


def _send_batches(items: Sequence[CheckResult], batch_max: int, state: _Delivery) -> None:
    """Send in chunks; falls back to single POSTs if the server has no batch endpoint."""
    from gait_sdk import security
    from gait_sdk.exceptions import (
        AuthServiceUnavailable,
        InvalidApplicationCredentialError,
        SecuritySignalRejected,
        SignalEndpointNotFound,
        SignalRateLimited,
    )

    pending = list(items)
    while pending:
        chunk, pending = pending[:batch_max], pending[batch_max:]
        if state.stop is not None:
            for item in chunk:
                item.error = f"not sent: {state.stop}"
            continue
        bodies = [signal_body(item, state.run_id) for item in chunk]

        def post(bodies: list = bodies) -> Any:
            return asyncio.run(security.send_security_signals_batch(bodies, credential=state.credential))

        try:
            try:
                _call_with_retry(post, state.sleep)
            except SignalRateLimited as exc:
                wait = exc.retry_after if exc.retry_after is not None else DEFAULT_RATE_LIMIT_WAIT
                state.sleep(min(wait, MAX_RATE_LIMIT_WAIT))
                _call_with_retry(post, state.sleep)
            for item in chunk:
                item.sent = True
        except SignalEndpointNotFound:
            logger.info("This Gait server has no batch endpoint; sending one check per request.")
            _send_single(chunk + pending, state)
            return
        except SecuritySignalRejected as exc:
            note = _rejection_note(exc, chunk)
            for position, item in enumerate(chunk):
                item.error = note if getattr(exc, "index", None) == position else "not sent: batch rejected (400)"
            state.fail("Gait rejected a batch (400); nothing in that batch was recorded")
        except SignalRateLimited:
            for item in chunk:
                item.error = "not sent: rate limited (429)"
            state.fail("Gait rate-limited the run (429)", stop="rate limited", override=True)
        except InvalidApplicationCredentialError:
            for item in chunk:
                item.error = "credential rejected (401)"
            state.fail("the application credential was rejected (401)", stop="credential rejected", override=True)
        except AuthServiceUnavailable:
            for item in chunk:
                item.error = "Gait unreachable after retries"
            state.fail("Gait is unreachable (retries exhausted)", stop="Gait unreachable", override=True)


def deliver(
    results: Sequence[CheckResult],
    run_id: str,
    *,
    credential: Optional[str] = None,
    sleep: Callable[[float], None] = time.sleep,
    batch: bool = True,
) -> tuple[bool, Optional[str]]:
    """Deliver every valid result. Returns (failed, reason)."""
    state = _Delivery(run_id, credential, sleep)
    if any(not r.valid for r in results):
        state.fail("a payload failed local validation")

    info = fetch_signal_types(credential, sleep)
    sendable = []
    for item in results:
        if not item.valid:
            continue
        if info is not None and item.check_id not in info.signal_types:
            item.supported = False
            item.error = NOT_SUPPORTED
            continue
        sendable.append(item)

    if not sendable:
        return state.failed, state.reason
    if batch and info is not None and info.batch_max:
        _send_batches(sendable, info.batch_max, state)
    else:
        _send_single(sendable, state)
    return state.failed, state.reason


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
    strict: bool = False,
    app: Optional[str] = None,
    app_object: Any = None,
    deps_tool: str = "pip-audit",
    batch: bool = True,
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
    # The Gait server rejects a check signal whose source_reference doesn't match
    # the shared spec's pattern (letters, digits and : . _ -, at most 128).
    if not isinstance(run_id, str) or not re.fullmatch(registry.source_reference_pattern(), run_id):
        raise UsageError(
            "--run-id may only use letters, digits and : . _ - (1-128 characters), e.g. ci:<sha>:<job>."
        )
    if environment is not None and environment not in VALID_ENVIRONMENTS:
        raise UsageError(f"--environment must be one of: {', '.join(VALID_ENVIRONMENTS)}.")
    select_check_ids(packs, only, skip)  # fail on bad --only/--skip before any network call
    ctx = PackContext(
        environment=environment or DEFAULT_OFFLINE_ENVIRONMENT,
        strict=strict,
        app_path=app,
        app=app_object,
        deps_tool=deps_tool or "pip-audit",
    )
    prepare_packs(packs, ctx)  # e.g. a bad --app is a usage error, before any network call

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

    results, unmapped = run_checks(packs, effective_env, only, skip, context=ctx)
    report = RunReport(
        run_id=run_id,
        environment=effective_env,
        application=application_slug,
        results=results,
        unmapped_django_ids=unmapped,
        send=send,
    )
    if send:
        report.delivery_failed, report.delivery_error = deliver(
            results, run_id, credential=credential, sleep=sleep, batch=batch
        )
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
