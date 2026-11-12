"""Tests for the experimental restricted Terraform evidence contract."""

from copy import deepcopy

import pytest

from evidence_engine.restricted_contract import validate_restricted_document


PROFILE_20 = "terraform-restricted-2.0"
PROFILE_21 = "terraform-restricted-change-summary-2.1"

COUNTS = {
    "scope": "resource_changes",
    "creates": 1,
    "updates": 2,
    "deletes": 3,
    "replacements": 4,
    "reads": 5,
    "no_ops": 6,
    "total": 21,
}


def document(profile=PROFILE_21, name="plan.json"):
    result = {
        "evidence_profile": profile,
        "format_version": "1.0",
        "terraform_version": "1.9.0",
        "resource_details": "omitted",
    }

    if profile == PROFILE_20 and name == "plan.json":
        result["change_details"] = "omitted"
    elif profile == PROFILE_21 and name == "plan.json":
        result["change_summary"] = deepcopy(COUNTS)

    return result

@pytest.mark.parametrize("profile", [PROFILE_20, PROFILE_21])
@pytest.mark.parametrize("name", ["plan.json", "state.json"])
def test_accepts_valid_restricted_documents(profile, name):
    validate_restricted_document(name, document(profile, name))


@pytest.mark.parametrize("name", ["other.json", "", "../plan.json"])
def test_rejects_unsupported_artifact_names(name):
    with pytest.raises(ValueError):
        validate_restricted_document(name, document())


@pytest.mark.parametrize(
    "profile",
    ["", "terraform-restricted-9.9", None, 21],
)
def test_rejects_unsupported_profiles(profile):
    payload = document()
    payload["evidence_profile"] = profile

    with pytest.raises(ValueError):
        validate_restricted_document("plan.json", payload)


@pytest.mark.parametrize(
    "field,value",
    [
        ("resource_details", "included"),
        ("format_version", "2.0"),
        ("format_version", "1"),
        ("terraform_version", ""),
        ("terraform_version", "1.9"),
        ("terraform_version", "1.9.0-extra"),
    ],
)
def test_rejects_invalid_envelope_fields(field, value):
    payload = document()
    payload[field] = value

    with pytest.raises(ValueError):
        validate_restricted_document("plan.json", payload)


@pytest.mark.parametrize(
    "field",
    [
        "evidence_profile",
        "format_version",
        "terraform_version",
        "resource_details",
    ],
)
def test_rejects_missing_envelope_fields(field):
    payload = document()
    del payload[field]

    with pytest.raises(ValueError):
        validate_restricted_document("plan.json", payload)


@pytest.mark.parametrize(
    "extra",
    [
        {"address": "example.private"},
        {"values": {"password": "secret"}},
        {"planned_values": {}},
        {"resource_changes": []},
        {"configuration": {}},
    ],
)
def test_rejects_unknown_fields(extra):
    payload = document()
    payload.update(extra)

    with pytest.raises(ValueError):
        validate_restricted_document("plan.json", payload)


def test_rejects_change_summary_in_state():
    payload = document(name="state.json")
    payload["change_summary"] = deepcopy(COUNTS)

    with pytest.raises(ValueError):
        validate_restricted_document("state.json", payload)


def test_rejects_change_summary_in_profile_20():
    payload = document(PROFILE_20)
    payload["change_summary"] = deepcopy(COUNTS)

    with pytest.raises(ValueError):
        validate_restricted_document("plan.json", payload)


def test_requires_change_summary_in_profile_21_plan():
    payload = document()
    del payload["change_summary"]

    with pytest.raises(ValueError):
        validate_restricted_document("plan.json", payload)


@pytest.mark.parametrize(
    "field",
    [
        "creates",
        "updates",
        "deletes",
        "replacements",
        "reads",
        "no_ops",
        "total",
    ],
)
@pytest.mark.parametrize("value", [-1, True, 1.5, "1", None])
def test_rejects_invalid_counts(field, value):
    payload = document()
    payload["change_summary"][field] = value

    with pytest.raises(ValueError):
        validate_restricted_document("plan.json", payload)


def test_rejects_incorrect_total():
    payload = document()
    payload["change_summary"]["total"] = 999

    with pytest.raises(ValueError):
        validate_restricted_document("plan.json", payload)


def test_rejects_incorrect_scope():
    payload = document()
    payload["change_summary"]["scope"] = "outputs"

    with pytest.raises(ValueError):
        validate_restricted_document("plan.json", payload)


def test_rejects_extra_summary_field():
    payload = document()
    payload["change_summary"]["addresses"] = ["example.private"]

    with pytest.raises(ValueError):
        validate_restricted_document("plan.json", payload)


def test_rejects_missing_summary_field():
    payload = document()
    del payload["change_summary"]["creates"]

    with pytest.raises(ValueError):
        validate_restricted_document("plan.json", payload)


@pytest.mark.parametrize("value", [None, [], "invalid", 1])
def test_rejects_non_object_documents(value):
    with pytest.raises(ValueError):
        validate_restricted_document("plan.json", value)


def test_does_not_mutate_document():
    payload = document()
    original = deepcopy(payload)

    validate_restricted_document("plan.json", payload)

    assert payload == original


def test_accepts_canonical_restricted_bytes():
    from evidence_engine.canonical import canonical_json_bytes
    from evidence_engine.restricted_contract import validate_restricted_bytes

    payload = canonical_json_bytes(document())
    validate_restricted_bytes("plan.json", payload)


def test_rejects_noncanonical_restricted_bytes():
    import json

    from evidence_engine.restricted_contract import validate_restricted_bytes

    payload = json.dumps(document(), indent=2).encode("utf-8")

    with pytest.raises(ValueError):
        validate_restricted_bytes("plan.json", payload)


def test_rejects_duplicate_json_keys():
    from evidence_engine.restricted_contract import validate_restricted_bytes

    payload = (
        b'{"evidence_profile":"terraform-restricted-2.0",'
        b'"evidence_profile":"terraform-restricted-2.0",'
        b'"format_version":"1.0",'
        b'"terraform_version":"1.9.0",'
        b'"resource_details":"omitted"}'
    )

    with pytest.raises(ValueError):
        validate_restricted_bytes("state.json", payload)


@pytest.mark.parametrize("payload", [
    b"",
    b"not-json",
    b"[]",
    b'{"value":NaN}',
    b"\xff",
])
def test_rejects_invalid_serialized_evidence(payload):
    from evidence_engine.restricted_contract import validate_restricted_bytes

    with pytest.raises(ValueError):
        validate_restricted_bytes("plan.json", payload)


def test_rejects_non_bytes_input():
    from evidence_engine.restricted_contract import validate_restricted_bytes

    with pytest.raises(ValueError):
        validate_restricted_bytes("plan.json", document())


def test_serialized_validation_does_not_change_input():
    from evidence_engine.canonical import canonical_json_bytes
    from evidence_engine.restricted_contract import validate_restricted_bytes

    payload = canonical_json_bytes(document())
    original = bytes(payload)

    validate_restricted_bytes("plan.json", payload)

    assert payload == original




@pytest.mark.parametrize("version", ["2.0", "2.1"])
@pytest.mark.parametrize("name", ["plan.json", "state.json"])
def test_accepts_actual_restricted_sanitizer_output(version, name):
    import json

    from evidence_engine.restricted_contract import validate_restricted_bytes
    from evidence_engine.sanitization import SanitizationRule, Sanitizer

    sanitizer = Sanitizer(
        rules=[
            SanitizationRule(
                name="terraform_json_content",
                description="Experimental restricted evidence",
                version=version,
            )
        ]
    )

    if name == "plan.json":
        source = {
            "format_version": "1.0",
            "terraform_version": "1.9.0",
            "planned_values": {"root_module": {"resources": []}},
            "resource_changes": [
                {
                    "address": "example.private",
                    "change": {
                        "actions": ["create"],
                        "before": None,
                        "after": {"secret": "CONFIDENTIAL-VALUE"},
                    },
                }
            ],
        }
    else:
        source = {
            "format_version": "1.0",
            "terraform_version": "1.9.0",
            "values": {
                "root_module": {
                    "resources": [
                        {
                            "address": "example.private",
                            "values": {"secret": "CONFIDENTIAL-VALUE"},
                        }
                    ]
                }
            },
        }

    result = sanitizer.sanitize_artifact_content(
        name,
        json.dumps(source).encode("utf-8"),
    )

    validate_restricted_bytes(name, result.content)

    assert b"CONFIDENTIAL-VALUE" not in result.content
    assert b"example.private" not in result.content
    assert result.applied_rules == (
        f"terraform_json_content@{version}",
    )


def test_profile_20_plan_requires_change_details_omitted():
    payload = document(PROFILE_20, "plan.json")
    payload["change_details"] = "omitted"

    validate_restricted_document("plan.json", payload)

    del payload["change_details"]

    with pytest.raises(ValueError):
        validate_restricted_document("plan.json", payload)


@pytest.mark.parametrize(
    "value",
    ["included", None, {}, True],
)
def test_profile_20_plan_rejects_invalid_change_details(value):
    payload = document(PROFILE_20, "plan.json")
    payload["change_details"] = value

    with pytest.raises(ValueError):
        validate_restricted_document("plan.json", payload)
