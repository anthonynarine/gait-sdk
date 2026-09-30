"""The check registry: every built-in check, loaded from `checks_v1.json`.

`checks_v1.json` is the one definition of every check id, its typed facts and
the payload limits. The Gait server vendors the same file byte for byte and
enforces the same schema on ingestion, so never edit ids, fact names, types
or limits here alone. Both repos assert the same canonical hash
(CHECKS_V1_CANONICAL_SHA256): change the spec in both, never in one.

`validate_payload()` mirrors the server's validation exactly. The engine calls
it on every payload before sending, so an invalid payload never leaves the
process. The server check is still the real guarantee: anyone holding an
application credential can call the HTTP API directly.

Print the canonical spec:

    python -m gait_sdk.checks.registry --export-json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from types import MappingProxyType
from typing import Any, Mapping, Optional

SPEC_FILENAME = "checks_v1.json"

# sha256 of json.dumps(spec, sort_keys=True, separators=(",", ":")).encode("utf-8").
# Independent of line endings; the server asserts the same value.
CHECKS_V1_CANONICAL_SHA256 = "29c9ebe147246de7c02e89c7d91c55d2a700af49bb3cb6c95776489e52b8aebf"

PAYLOAD_VERSION = 1
PAYLOAD_KEYS = frozenset({"v", "pack", "pack_version", "sdk_version", "outcome", "facts"})

# Pack versions this SDK builds payloads for.
PACK_VERSIONS = MappingProxyType({"django": "1.0.0", "fastapi": "1.0.0", "deps": "1.0.0"})

CHECK_ID_RE = re.compile(r"^CHK\.[A-Z]{2,20}\.[A-Z0-9_]{2,40}$")
FACT_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
VERSION_RE = re.compile(r"^[0-9A-Za-z.+-]{1,20}$")
FACT_TYPES = frozenset({"bool", "int", "enum", "pattern", "list_pattern", "list_record"})
# Types a list_record field may have (no nested lists or records).
RECORD_FIELD_TYPES = frozenset({"bool", "int", "enum", "pattern"})
SEVERITIES = frozenset({"HIGH", "MEDIUM", "LOW"})

# Gait's audit sanitiser redacts any metadata key containing one of these
# (server security/utils.py). A fact named like this would be stored as
# "[REDACTED]", so the registry refuses to load one.
SENSITIVE_FACT_NAME_PARTS = (
    "password",
    "passphrase",
    "token",
    "refresh",
    "access",
    "authorization",
    "otp",
    "mfa",
    "secret",
    "reset",
    "jwt",
    "cookie",
    "private_key",
    "api_key",
    "patient",
    "diagnosis",
    "phi",
    "mrn",
    "dob",
    "medical_record_number",
)


class PayloadValidationError(ValueError):
    """A payload doesn't match its check's schema.

    `field` names where (for example "facts.hsts_seconds"). The offending
    value is never included in the message.
    """

    def __init__(self, field: str):
        super().__init__(f"Invalid payload field: {field}")
        self.field = field


class SpecError(RuntimeError):
    """The packaged checks_v1.json is malformed or has drifted from the server's copy."""


@dataclass(frozen=True)
class CheckDefinition:
    id: str
    pack: str
    severity: str
    env_gated: bool
    title: str
    remediation: str
    facts: Mapping[str, Mapping[str, Any]]
    valid_for_seconds: Optional[int] = None


# -----------------------------------------------------------------------------
# Loading
# -----------------------------------------------------------------------------
def spec_bytes() -> bytes:
    """The packaged spec file, exactly as shipped."""
    return resources.files("gait_sdk.checks").joinpath(SPEC_FILENAME).read_bytes()


def canonical_spec_sha256(spec: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(spec, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def validate_spec(spec: Mapping[str, Any]) -> None:
    """Fail fast on a malformed spec (same rules as the server)."""
    if spec.get("schema_version") != 1:
        raise SpecError("Unsupported check spec schema_version.")
    outcomes = spec["outcomes"]
    if set(spec["outcome_results"]) != set(outcomes):
        raise SpecError("Every outcome needs a result mapping.")
    common = spec.get("common_facts", {})
    limits = spec["limits"]
    for check_id, check in spec["checks"].items():
        if not CHECK_ID_RE.match(check_id) or len(check_id) > 64:
            raise SpecError(f"Bad check id {check_id!r}.")
        if check["severity"] not in SEVERITIES:
            raise SpecError(f"{check_id}: unknown severity.")
        if not isinstance(check.get("env_gated"), bool):
            raise SpecError(f"{check_id}: env_gated must be a bool.")
        if set(check["facts"]) & set(common):
            raise SpecError(f"{check_id}: a fact redefines a common fact.")
        for name, fact in {**common, **check["facts"]}.items():
            if not FACT_NAME_RE.match(name):
                raise SpecError(f"{check_id}: bad fact name {name!r}.")
            lowered = name.lower()
            if any(part in lowered for part in SENSITIVE_FACT_NAME_PARTS):
                raise SpecError(f"{check_id}: fact name {name!r} would be redacted by Gait's sanitiser.")
            _validate_fact_spec(f"{check_id}: fact {name!r}", fact, limits, FACT_TYPES)
        valid_for = check.get("valid_for_seconds")
        if isinstance(valid_for, bool) or not isinstance(valid_for, int) or valid_for <= 0:
            raise SpecError(f"{check_id}: valid_for_seconds must be a positive integer.")


def _compile(where: str, pattern: Any) -> None:
    if not isinstance(pattern, str) or not pattern:
        raise SpecError(f"{where} needs a pattern.")
    try:
        re.compile(pattern)
    except re.error:
        raise SpecError(f"{where} has a pattern that doesn't compile.") from None


def _validate_fact_spec(where: str, fact: Mapping[str, Any], limits: Mapping[str, Any], allowed: frozenset) -> None:
    kind = fact.get("type")
    if kind not in allowed:
        raise SpecError(f"{where} has unknown or disallowed type {kind!r}.")
    if kind == "int" and not (isinstance(fact.get("min"), int) and isinstance(fact.get("max"), int)):
        raise SpecError(f"{where} needs min and max.")
    if kind == "enum" and not fact.get("values"):
        raise SpecError(f"{where} needs values.")
    if kind == "pattern":
        _compile(where, fact.get("pattern"))
    if kind == "list_pattern":
        _compile(where, fact.get("pattern"))
        if not 1 <= int(fact.get("max_items", 0)) <= limits["max_list_items"]:
            raise SpecError(f"{where} needs 1..max_list_items items.")
    if kind == "list_record":
        max_record = limits.get("max_record_items")
        if not isinstance(max_record, int) or not 1 <= int(fact.get("max_items", 0)) <= max_record:
            raise SpecError(f"{where} needs 1..max_record_items items.")
        fields = fact.get("fields")
        if not isinstance(fields, dict) or not fields:
            raise SpecError(f"{where} needs fields.")
        required = fact.get("required", [])
        if not isinstance(required, list) or not set(required) <= set(fields):
            raise SpecError(f"{where}: required must be a subset of fields.")
        for field_name, field_spec in fields.items():
            if not FACT_NAME_RE.match(field_name):
                raise SpecError(f"{where}: bad field name {field_name!r}.")
            if any(part in field_name.lower() for part in SENSITIVE_FACT_NAME_PARTS):
                raise SpecError(f"{where}: field name {field_name!r} would be redacted by Gait's sanitiser.")
            _validate_fact_spec(f"{where} field {field_name!r}", field_spec, limits, RECORD_FIELD_TYPES)


@lru_cache(maxsize=1)
def load_spec() -> Mapping[str, Any]:
    """Load, hash-check and validate the packaged spec (cached)."""
    spec = json.loads(spec_bytes().decode("utf-8"))
    digest = canonical_spec_sha256(spec)
    if digest != CHECKS_V1_CANONICAL_SHA256:
        raise SpecError(
            "gait_sdk/checks/checks_v1.json does not match the canonical hash shared with the Gait server."
        )
    validate_spec(spec)
    return spec


@lru_cache(maxsize=1)
def checks() -> Mapping[str, CheckDefinition]:
    spec = load_spec()
    return MappingProxyType(
        {
            check_id: CheckDefinition(
                id=check_id,
                pack=check["pack"],
                severity=check["severity"],
                env_gated=check["env_gated"],
                title=check["title"],
                remediation=check["remediation"],
                facts=MappingProxyType(dict(check["facts"])),
                valid_for_seconds=check.get("valid_for_seconds"),
            )
            for check_id, check in spec["checks"].items()
        }
    )


def get_check(check_id: str) -> CheckDefinition:
    return checks()[check_id]


def check_ids(pack: Optional[str] = None) -> tuple[str, ...]:
    return tuple(cid for cid, c in checks().items() if pack is None or c.pack == pack)


def packs() -> tuple[str, ...]:
    return tuple(dict.fromkeys(c.pack for c in checks().values()))


def outcomes() -> tuple[str, ...]:
    return tuple(load_spec()["outcomes"])


def limits() -> Mapping[str, Any]:
    return load_spec()["limits"]


def source_reference_pattern() -> str:
    """The pattern the Gait server enforces on a check signal's source_reference (the run id)."""
    return load_spec()["limits"]["source_reference_pattern"]


def common_facts() -> Mapping[str, Mapping[str, Any]]:
    return load_spec().get("common_facts", {})


def allowed_facts(check_id: str) -> dict[str, Mapping[str, Any]]:
    """The check's own facts plus the common facts."""
    return {**common_facts(), **get_check(check_id).facts}


# -----------------------------------------------------------------------------
# Result mapping
# -----------------------------------------------------------------------------
def result_for_outcome(outcome: str) -> str:
    """ok -> PASS, fail -> FAIL, weak -> WARNING, anything else -> INFORMATIONAL."""
    return load_spec()["outcome_results"].get(outcome, "INFORMATIONAL")


# -----------------------------------------------------------------------------
# Payload validation (mirrors the server's security/check_packs.py)
# -----------------------------------------------------------------------------
def _check_fact(field: str, fact: Mapping[str, Any], value: Any) -> None:
    kind = fact["type"]
    if kind == "bool":
        if not isinstance(value, bool):
            raise PayloadValidationError(field)
    elif kind == "int":
        if isinstance(value, bool) or not isinstance(value, int) or not fact["min"] <= value <= fact["max"]:
            raise PayloadValidationError(field)
    elif kind == "enum":
        if not isinstance(value, str) or value not in fact["values"]:
            raise PayloadValidationError(field)
    elif kind == "list_pattern":
        max_items = min(fact["max_items"], limits()["max_list_items"])
        if not isinstance(value, list) or len(value) > max_items:
            raise PayloadValidationError(field)
        pattern = re.compile(fact["pattern"])
        for item in value:
            if not isinstance(item, str) or not pattern.fullmatch(item):
                raise PayloadValidationError(field)
    elif kind == "pattern":
        if not isinstance(value, str) or not re.fullmatch(fact["pattern"], value):
            raise PayloadValidationError(field)
    elif kind == "list_record":
        max_items = min(fact["max_items"], limits()["max_record_items"])
        if not isinstance(value, list) or len(value) > max_items:
            raise PayloadValidationError(field)
        fields = fact["fields"]
        required = fact.get("required", [])
        for index, record in enumerate(value):
            where = f"{field}.{index}"
            if not isinstance(record, dict):
                raise PayloadValidationError(field)
            for key in record:
                if key not in fields:
                    # Only echo a key that looks like a field name; never arbitrary text.
                    raise PayloadValidationError(f"{where}.{key}" if FACT_NAME_RE.match(str(key)) else field)
            for key in required:
                if key not in record:
                    raise PayloadValidationError(f"{where}.{key}")
            for key, item in record.items():
                _check_fact(f"{where}.{key}", fields[key], item)
    else:  # pragma: no cover - validate_spec rejects unknown types
        raise PayloadValidationError(field)


def _count_keys(value: Any) -> int:
    if isinstance(value, dict):
        return len(value) + sum(_count_keys(item) for item in value.values())
    if isinstance(value, list):
        return sum(_count_keys(item) for item in value)
    return 0


def encoded_size(payload: Any) -> int:
    """Size in bytes, encoded the way the server measures it."""
    return len(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def validate_payload(check_id: str, payload: Any, *, result: Optional[str] = None) -> None:
    """Accept exactly the check's schema and nothing else.

    `payload` = {"v": 1, "pack", "pack_version", "sdk_version", "outcome",
    "facts"}. Facts come only from the check's declared facts plus the
    common facts, each strictly typed. When `result` (the signal's
    top-level result) is given, it must equal outcome_results[outcome]; the
    engine always passes it.

    Raises PayloadValidationError naming the first bad field.
    """
    spec = load_spec()
    if check_id not in spec["checks"]:
        raise PayloadValidationError("signal_type")
    check = spec["checks"][check_id]
    lim = spec["limits"]

    if not isinstance(payload, dict):
        raise PayloadValidationError("payload")
    try:
        size = encoded_size(payload)
    except (TypeError, ValueError):
        raise PayloadValidationError("payload") from None
    if size > lim["max_payload_bytes"]:
        raise PayloadValidationError("payload")
    if _count_keys(payload) > lim["max_total_keys"]:
        raise PayloadValidationError("payload")

    extra = set(payload) - PAYLOAD_KEYS
    if extra:
        raise PayloadValidationError(sorted(map(str, extra))[0])
    for key in sorted(PAYLOAD_KEYS):
        if key not in payload:
            raise PayloadValidationError(key)
    if isinstance(payload["v"], bool) or payload["v"] != PAYLOAD_VERSION:
        raise PayloadValidationError("v")
    if payload["pack"] != check["pack"]:
        raise PayloadValidationError("pack")
    for key in ("pack_version", "sdk_version"):
        if not isinstance(payload[key], str) or not VERSION_RE.match(payload[key]):
            raise PayloadValidationError(key)
    if not isinstance(payload["outcome"], str) or payload["outcome"] not in spec["outcomes"]:
        raise PayloadValidationError("outcome")
    if result is not None and result != spec["outcome_results"][payload["outcome"]]:
        raise PayloadValidationError("result")

    facts = payload["facts"]
    if not isinstance(facts, dict):
        raise PayloadValidationError("facts")
    allowed = {**spec.get("common_facts", {}), **check["facts"]}
    for name, value in facts.items():
        if name not in allowed:
            raise PayloadValidationError(f"facts.{name}" if FACT_NAME_RE.match(str(name)) else "facts")
        _check_fact(f"facts.{name}", allowed[name], value)


# -----------------------------------------------------------------------------
# python -m gait_sdk.checks.registry --export-json
# -----------------------------------------------------------------------------
def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m gait_sdk.checks.registry",
        description="Inspect the gait-sdk built-in check registry.",
    )
    parser.add_argument("--export-json", action="store_true", help="Print the canonical checks_v1.json.")
    args = parser.parse_args(argv)
    if not args.export_json:
        parser.print_help()
        return 0
    load_spec()  # refuse to export a drifted or malformed spec
    out = getattr(sys.stdout, "buffer", None)
    if out is not None:
        out.write(spec_bytes())
        out.flush()
    else:
        sys.stdout.write(spec_bytes().decode("utf-8"))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
