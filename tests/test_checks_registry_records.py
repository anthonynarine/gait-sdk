"""CHK2b: the `pattern` and `list_record` fact types, valid_for_seconds and
the stricter spec checks."""

import copy
import json

import pytest

from gait_sdk.checks import registry
from gait_sdk.checks.registry import PayloadValidationError, SpecError, validate_payload

CHECK = "CHK.DEPS.KNOWN_VULNS"


def payload(outcome="fail", **facts):
    return {"v": 1, "pack": "deps", "pack_version": "1.0.0", "sdk_version": "0.6.0.dev0",
            "outcome": outcome, "facts": facts}


def item(**overrides):
    record = {"package": "pip", "version": "23.1.2", "advisory_id": "PYSEC-2023-228", "fixed_in": "23.3"}
    record.update(overrides)
    return {k: v for k, v in record.items() if v is not None}


def rejected(p, field):
    with pytest.raises(PayloadValidationError) as exc:
        validate_payload(CHECK, p)
    assert exc.value.field == field


# --- Accepts ----------------------------------------------------------------------------
def test_accepts_records():
    validate_payload(CHECK, payload(tool="pip-audit", vulnerable_count=2, unfixed_count=1,
                                    items=[item(), item(package="ecdsa", version="0.19.1",
                                                        advisory_id="GHSA-wj6h-64fc-37mp", fixed_in=None)]),
                     result="FAIL")


def test_accepts_empty_items_and_unknown_shape():
    validate_payload(CHECK, payload("ok", tool="pip-audit", vulnerable_count=0, unfixed_count=0, items=[]))
    validate_payload(CHECK, payload("unknown", tool="none", reason="tool_missing"), result="INFORMATIONAL")


def test_accepts_ten_records():
    validate_payload(CHECK, payload(items=[item(package=f"p{i}") for i in range(10)]))


# --- Rejects -------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "items,field",
    [
        ([item()] * 11, "facts.items"),                               # over max_items
        ("pip", "facts.items"),                                       # not a list
        (["pip==1.0"], "facts.items"),                                # a record must be a dict
        ([item(), {"package": "x", "version": "1"}], "facts.items.1.advisory_id"),  # required missing
        ([item(severity="high")], "facts.items.0.severity"),          # unknown field
        ([dict(item(), **{"Free Text!": "x"})], "facts.items"),       # unknown field, never echoed
        ([item(package="bad name!")], "facts.items.0.package"),       # pattern
        ([item(package="x" * 101)], "facts.items.0.package"),
        ([item(version=1.0)], "facts.items.0.version"),               # a number, not a string
        ([item(advisory_id="BIT-pip-2023-1")], "facts.items.0.advisory_id"),
        ([item(advisory_id="patient John Smith")], "facts.items.0.advisory_id"),
        ([item(fixed_in="23.3 (next week)")], "facts.items.0.fixed_in"),
        ([item(fixed_in=["23.3"])], "facts.items.0.fixed_in"),
        ([item(package={"name": "pip"})], "facts.items.0.package"),
    ],
)
def test_rejects_bad_records(items, field):
    rejected(payload(items=items), field)


def test_rejects_bad_enums_and_ints_on_the_deps_check():
    rejected(payload(tool="safety"), "facts.tool")
    rejected(payload("unknown", tool="pip-audit", reason="because"), "facts.reason")
    rejected(payload(vulnerable_count=-1), "facts.vulnerable_count")
    rejected(payload(vulnerable_count=True), "facts.vulnerable_count")
    rejected(payload(package_list=["a", "b"]), "facts.package_list")


def test_pattern_type_fullmatches():
    fact = {"type": "pattern", "pattern": "^[a-z]{1,5}$"}
    registry._check_fact("facts.x", fact, "abc")
    for bad in ("abcdef", "ab1", "", 5, None, ["abc"]):
        with pytest.raises(PayloadValidationError):
            registry._check_fact("facts.x", fact, bad)
    # fullmatch, not search, even when the pattern has no anchors
    loose = {"type": "pattern", "pattern": "[a-z]+"}
    registry._check_fact("facts.x", loose, "abc")
    with pytest.raises(PayloadValidationError):
        registry._check_fact("facts.x", loose, "abc DEF")


def test_record_field_types_bool_int_enum():
    fact = {"type": "list_record", "max_items": 3, "required": ["n"], "fields": {
        "n": {"type": "int", "min": 0, "max": 5},
        "b": {"type": "bool"},
        "e": {"type": "enum", "values": ["x", "y"]},
    }}
    registry._check_fact("facts.r", fact, [{"n": 1, "b": True, "e": "x"}])
    for record, field in [({"n": 6}, "facts.r.0.n"), ({"n": True}, "facts.r.0.n"),
                          ({"n": 1, "b": 1}, "facts.r.0.b"), ({"n": 1, "e": "z"}, "facts.r.0.e"),
                          ({"b": True}, "facts.r.0.n")]:
        with pytest.raises(PayloadValidationError) as exc:
            registry._check_fact("facts.r", fact, [record])
        assert exc.value.field == field


def test_many_records_stay_under_the_key_and_size_caps():
    long = item(package="p" * 100, version="1" * 50, advisory_id="GHSA-" + "a" * 40, fixed_in="2" * 50)
    p = payload(tool="osv-scanner", vulnerable_count=10000, unfixed_count=10000, items=[long] * 10)
    validate_payload(CHECK, p)
    assert registry.encoded_size(p) <= 4096


# --- Spec strictness ------------------------------------------------------------------------
def spec():
    return copy.deepcopy(json.loads(registry.spec_bytes().decode("utf-8")))


def items_spec(s):
    return s["checks"][CHECK]["facts"]["items"]


def test_valid_for_seconds_is_loaded_and_required():
    assert registry.get_check(CHECK).valid_for_seconds == 172800
    assert registry.get_check("CHK.DJANGO.HSTS").valid_for_seconds == 604800
    s = spec()
    del s["checks"]["CHK.DJANGO.HSTS"]["valid_for_seconds"]
    with pytest.raises(SpecError):
        registry.validate_spec(s)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda f: f.update(max_items=11),                              # over max_record_items
        lambda f: f.update(max_items=0),
        lambda f: f.pop("fields"),
        lambda f: f.update(fields={}),
        lambda f: f.update(required=["package", "nope"]),              # required not a subset
        lambda f: f["fields"].update(nested={"type": "list_record", "max_items": 1, "fields": {"a": {"type": "bool"}}}),
        lambda f: f["fields"].update(ids={"type": "list_pattern", "pattern": "^a$", "max_items": 2}),
        lambda f: f["fields"]["package"].update(pattern="(unclosed"),
        lambda f: f["fields"].update(session_token={"type": "bool"}),  # would be redacted
        lambda f: f["fields"].update(**{"Bad": {"type": "bool"}}),
    ],
)
def test_spec_rejects_bad_list_record(mutate):
    s = spec()
    mutate(items_spec(s))
    with pytest.raises(SpecError):
        registry.validate_spec(s)


def test_spec_rejects_bad_pattern_fact():
    s = spec()
    s["checks"]["CHK.DJANGO.HSTS"]["facts"]["label"] = {"type": "pattern", "pattern": "(unclosed"}
    with pytest.raises(SpecError):
        registry.validate_spec(s)
    s["checks"]["CHK.DJANGO.HSTS"]["facts"]["label"] = {"type": "pattern"}
    with pytest.raises(SpecError):
        registry.validate_spec(s)


def test_spec_rejects_list_record_without_the_limit():
    s = spec()
    del s["limits"]["max_record_items"]
    with pytest.raises(SpecError):
        registry.validate_spec(s)


def test_packaged_spec_passes():
    registry.validate_spec(spec())
