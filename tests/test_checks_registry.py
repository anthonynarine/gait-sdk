"""CHK2a: the check registry (checks_v1.json) and validate_payload()."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from gait_sdk.checks import registry
from gait_sdk.checks.registry import PayloadValidationError, validate_payload

ROOT = Path(__file__).resolve().parents[1]
SPEC_PATH = ROOT / "gait_sdk" / "checks" / "checks_v1.json"

FORBIDDEN_FACT_PARTS = (
    "password", "passphrase", "token", "refresh", "access", "authorization", "otp", "mfa", "secret",
    "reset", "jwt", "cookie", "private_key", "api_key", "patient", "diagnosis", "phi", "mrn", "dob",
    "medical_record_number",
)


def good_payload(**changes):
    payload = {
        "v": 1,
        "pack": "django",
        "pack_version": "1.0.0",
        "sdk_version": "0.6.0.dev0",
        "outcome": "weak",
        "facts": {"hsts_seconds": 86400, "include_subdomains": False, "preload": False,
                  "django_ids": ["security.W005", "security.W021"]},
    }
    payload.update(changes)
    return payload


def facts(**f):
    return good_payload(facts=f)


# --- Loading and parity with the server -----------------------------------------------
def test_registry_loads_from_package_data():
    raw = registry.spec_bytes()
    assert raw == SPEC_PATH.read_bytes()
    assert len(registry.check_ids("django")) == 21
    assert registry.packs() == ("django",)


def test_packaged_spec_matches_the_canonical_hash_shared_with_the_server():
    spec = json.loads(SPEC_PATH.read_text(encoding="utf-8"))
    canonical = json.dumps(spec, sort_keys=True, separators=(",", ":")).encode("utf-8")
    assert hashlib.sha256(canonical).hexdigest() == registry.CHECKS_V1_CANONICAL_SHA256
    assert registry.CHECKS_V1_CANONICAL_SHA256 == "8fd7af39a4cdb8d39289754d1cb593c6e1876a650d43dadd8b0c226c9206f62b"


def test_a_drifted_spec_refuses_to_load(monkeypatch):
    spec = json.loads(SPEC_PATH.read_text(encoding="utf-8"))
    spec["limits"]["max_payload_bytes"] = 999999
    monkeypatch.setattr(registry, "spec_bytes", lambda: json.dumps(spec).encode("utf-8"))
    registry.load_spec.cache_clear()
    try:
        with pytest.raises(registry.SpecError):
            registry.load_spec()
    finally:
        monkeypatch.undo()
        registry.load_spec.cache_clear()
    assert registry.load_spec()["limits"]["max_payload_bytes"] == 4096


def test_export_json_round_trips():
    proc = subprocess.run(
        [sys.executable, "-m", "gait_sdk.checks.registry", "--export-json"],
        capture_output=True, cwd=str(ROOT), check=True,
    )
    assert proc.stdout == SPEC_PATH.read_bytes()
    exported = json.loads(proc.stdout.decode("utf-8"))
    assert exported == registry.load_spec()
    assert registry.canonical_spec_sha256(exported) == registry.CHECKS_V1_CANONICAL_SHA256
    assert b"RuntimeWarning" not in proc.stderr


def test_export_json_in_process(capsys):
    assert registry.main(["--export-json"]) == 0
    assert json.loads(capsys.readouterr().out) == registry.load_spec()


# --- Spec-level rules -------------------------------------------------------------------------
def test_no_fact_name_contains_a_sensitive_word():
    names = set(registry.common_facts())
    for check_id in registry.check_ids():
        names |= set(registry.get_check(check_id).facts)
    for name in names:
        for part in FORBIDDEN_FACT_PARTS:
            assert part not in name.lower(), f"{name} contains {part}"


def test_sensitive_word_list_matches_the_registry_guard():
    assert tuple(registry.SENSITIVE_FACT_NAME_PARTS) == FORBIDDEN_FACT_PARTS


def test_registry_rejects_a_sensitive_fact_name_at_load():
    spec = json.loads(SPEC_PATH.read_text(encoding="utf-8"))
    spec["checks"]["CHK.DJANGO.NOSNIFF"]["facts"]["session_cookie_secure"] = {"type": "bool"}
    with pytest.raises(registry.SpecError):
        registry.validate_spec(spec)


def test_result_mapping():
    assert registry.result_for_outcome("ok") == "PASS"
    assert registry.result_for_outcome("fail") == "FAIL"
    assert registry.result_for_outcome("weak") == "WARNING"
    for other in ("not_applicable", "unknown", "error"):
        assert registry.result_for_outcome(other) == "INFORMATIONAL"


def test_every_check_has_title_and_remediation():
    for check_id in registry.check_ids():
        definition = registry.get_check(check_id)
        assert definition.title and definition.remediation
        assert definition.severity in {"HIGH", "MEDIUM", "LOW"}


# --- validate_payload: accepts --------------------------------------------------------------
def test_accepts_a_good_payload():
    validate_payload("CHK.DJANGO.HSTS", good_payload(), result="WARNING")


def test_accepts_empty_facts_and_omitted_optional_facts():
    validate_payload("CHK.DJANGO.DEBUG_OFF", good_payload(outcome="not_applicable", facts={}), result="INFORMATIONAL")
    validate_payload("CHK.DJANGO.HSTS", facts(hsts_seconds=0))


# --- validate_payload: rejects ------------------------------------------------------------
@pytest.mark.parametrize(
    "check_id,payload,field",
    [
        # free strings
        ("CHK.DJANGO.HSTS", facts(hsts_seconds="31536000"), "facts.hsts_seconds"),
        ("CHK.DJANGO.DEBUG_OFF", good_payload(facts={"debug": "False"}), "facts.debug"),
        ("CHK.DJANGO.HSTS", facts(django_ids=["patient John Smith"]), "facts.django_ids"),
        ("CHK.DJANGO.HSTS", facts(django_ids="security.W004"), "facts.django_ids"),
        # unknown facts (including another check's fact)
        ("CHK.DJANGO.HSTS", facts(note="free text"), "facts.note"),
        ("CHK.DJANGO.HSTS", facts(debug=True), "facts.debug"),
        ("CHK.DJANGO.HSTS", facts(**{"Bad Key!": 1}), "facts"),
        # bad enums
        ("CHK.DJANGO.REFERRER_POLICY", good_payload(facts={"policy": "SAME-ORIGIN"}), "facts.policy"),
        ("CHK.DJANGO.CLICKJACKING", good_payload(facts={"frame_option": "ALLOW-FROM x"}), "facts.frame_option"),
        # out-of-range ints
        ("CHK.DJANGO.HSTS", facts(hsts_seconds=-1), "facts.hsts_seconds"),
        ("CHK.DJANGO.ALLOWED_HOSTS", good_payload(facts={"host_count": 1001}), "facts.host_count"),
        ("CHK.DJANGO.HSTS", facts(hsts_seconds=1.5), "facts.hsts_seconds"),
        # bools as ints and ints as bools
        ("CHK.DJANGO.HSTS", facts(hsts_seconds=True), "facts.hsts_seconds"),
        ("CHK.DJANGO.DEBUG_OFF", good_payload(facts={"debug": 1}), "facts.debug"),
        # lists
        ("CHK.DJANGO.HSTS", facts(django_ids=["security.W004"] * 26), "facts.django_ids"),
        ("CHK.DJANGO.HSTS", facts(django_ids=[1]), "facts.django_ids"),
        # envelope
        ("CHK.DJANGO.HSTS", good_payload(extra="x"), "extra"),
        ("CHK.DJANGO.HSTS", {k: v for k, v in good_payload().items() if k != "sdk_version"}, "sdk_version"),
        ("CHK.DJANGO.HSTS", good_payload(v=2), "v"),
        ("CHK.DJANGO.HSTS", good_payload(v=True), "v"),
        ("CHK.DJANGO.HSTS", good_payload(pack="fastapi"), "pack"),
        ("CHK.DJANGO.HSTS", good_payload(pack_version="1.0.0 beta"), "pack_version"),
        ("CHK.DJANGO.HSTS", good_payload(sdk_version="x" * 21), "sdk_version"),
        ("CHK.DJANGO.HSTS", good_payload(sdk_version=6), "sdk_version"),
        ("CHK.DJANGO.HSTS", good_payload(outcome="unmapped_django_check"), "outcome"),
        ("CHK.DJANGO.HSTS", good_payload(outcome="OK"), "outcome"),
        ("CHK.DJANGO.HSTS", good_payload(facts=["hsts_seconds"]), "facts"),
        ("CHK.DJANGO.HSTS", "not a dict", "payload"),
        ("CHK.DJANGO.NOT_A_CHECK", good_payload(), "signal_type"),
    ],
)
def test_rejects(check_id, payload, field):
    with pytest.raises(PayloadValidationError) as exc:
        validate_payload(check_id, payload)
    assert exc.value.field == field


def test_rejects_nested_extra_keys():
    payload = facts(hsts_seconds={"nested": "x"})
    with pytest.raises(PayloadValidationError):
        validate_payload("CHK.DJANGO.HSTS", payload)


def test_rejects_oversize_payload():
    payload = good_payload(facts={"django_ids": ["security.W004"] * 25}, sdk_version="1" * 20)
    validate_payload("CHK.DJANGO.HSTS", payload)  # the largest legal payload fits
    big = good_payload(pack_version="x" * 5000)
    with pytest.raises(PayloadValidationError) as exc:
        validate_payload("CHK.DJANGO.HSTS", big)
    assert exc.value.field == "payload"


def test_rejects_too_many_keys():
    payload = good_payload(facts={f"k{i}": True for i in range(200)})
    with pytest.raises(PayloadValidationError) as exc:
        validate_payload("CHK.DJANGO.HSTS", payload)
    assert exc.value.field == "payload"


def test_rejects_non_json_values():
    with pytest.raises(PayloadValidationError) as exc:
        validate_payload("CHK.DJANGO.HSTS", good_payload(facts={"hsts_seconds": object()}))
    assert exc.value.field == "payload"


def test_result_must_match_outcome():
    validate_payload("CHK.DJANGO.HSTS", good_payload(outcome="ok"), result="PASS")
    with pytest.raises(PayloadValidationError) as exc:
        validate_payload("CHK.DJANGO.HSTS", good_payload(outcome="ok"), result="FAIL")
    assert exc.value.field == "result"
    with pytest.raises(PayloadValidationError) as exc:
        validate_payload("CHK.DJANGO.HSTS", good_payload(outcome="error"), result="PASS")
    assert exc.value.field == "result"


def test_error_message_never_echoes_the_value():
    with pytest.raises(PayloadValidationError) as exc:
        validate_payload("CHK.DJANGO.HSTS", facts(hsts_seconds="PATIENT-NAME-VALUE"))
    assert "PATIENT-NAME-VALUE" not in str(exc.value)
