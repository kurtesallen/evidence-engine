"""Focused tests for strict Terraform JSON content sanitization."""

import json

import pytest

from evidence_engine.sanitization import (
    ArtifactSanitizationError,
    SanitizationRule,
    Sanitizer,
)


RULE = SanitizationRule(
    name="terraform_json_content",
    description="Redact sensitive Terraform JSON values",
    version="1.1",
)


def sanitizer():
    return Sanitizer(rules=[RULE])


def parse_result(result):
    return json.loads(result.content.decode("utf-8"))


def state_document(values=None, **extra):
    return {
        "format_version": "1.0",
        "terraform_version": "1.9.0",
        "values": values if values is not None else {"root_module": {"resources": []}},
        **extra,
    }


def plan_document(**overrides):
    result = {
        "format_version": "1.0",
        "terraform_version": "1.9.0",
        "planned_values": {"root_module": {"resources": []}},
        "resource_changes": [],
    }
    result.update(overrides)
    return result


def sanitize(name, document):
    return sanitizer().sanitize_artifact_content(
        name, json.dumps(document).encode("utf-8")
    )


def test_requires_explicit_versioned_content_rule():
    with pytest.raises(ArtifactSanitizationError, match="versioned"):
        Sanitizer().sanitize_artifact_content(
            "state.json", json.dumps(state_document()).encode()
        )


def test_rejects_duplicate_rules():
    with pytest.raises(ArtifactSanitizationError, match="Exactly one"):
        Sanitizer(rules=[RULE, RULE]).sanitize_artifact_content(
            "state.json", json.dumps(state_document()).encode()
        )


def test_redacts_sensitive_key_names_recursively():
    payload = state_document({
        "root_module": {"resources": [{"values": {
            "password": "db-password-value",
            "client_secret": "client-secret-value",
            "ordinary_name": "kept",
        }, "sensitive_values": {}}]}
    })
    result = sanitize("state.json", payload)
    clean = parse_result(result)
    attributes = clean["values"]["root_module"]["resources"][0]["values"]
    assert attributes["password"] == "[REDACTED]"
    assert attributes["client_secret"] == "[REDACTED]"
    assert attributes["ordinary_name"] == "kept"
    assert b"db-password-value" not in result.content
    assert result.applied_rules == ("terraform_json_content@1.1",)


def test_honors_terraform_before_and_after_sensitive_masks():
    payload = plan_document(resource_changes=[{
        "address": "example.test",
        "change": {
            "before": {"setting": "old-secret", "count": 1},
            "before_sensitive": {"setting": True, "count": False},
            "after": {"setting": "new-secret", "count": 2},
            "after_sensitive": {"setting": True, "count": False},
            "actions": ["update"],
        },
    }])
    result = sanitize("plan.json", payload)
    change = parse_result(result)["resource_changes"][0]["change"]
    assert change["before"]["setting"] == "[REDACTED]"
    assert change["after"]["setting"] == "[REDACTED]"
    assert change["before"]["count"] == 1
    assert change["after"]["count"] == 2
    assert b"old-secret" not in result.content
    assert b"new-secret" not in result.content


def test_honors_sensitive_values_mask_for_resource_values():
    payload = state_document({
        "root_module": {"resources": [{
            "address": "example.test",
            "mode": "managed",
            "type": "example",
            "name": "test",
            "values": {
                "password": "already-key-redacted",
                "endpoint": "https://example.invalid",
                "nested": {"value": "unlabelled-secret"},
            },
            "sensitive_values": {
                "password": True,
                "nested": {"value": True},
            },
        }]}
    })
    result = sanitize("state.json", payload)
    values = parse_result(result)["values"]
    resource = values["root_module"]["resources"][0]
    resource_values = resource["values"]
    assert resource_values["password"] == "[REDACTED]"
    assert resource_values["nested"]["value"] == "[REDACTED]"
    assert resource_values["endpoint"] == "https://example.invalid"
    assert b"unlabelled-secret" not in result.content


def test_redacts_sensitive_output_value_flag():
    payload = state_document({"outputs": {"endpoint": {
        "sensitive": True,
        "value": "sensitive-output-value",
        "type": "string",
    }}})
    result = sanitize("state.json", payload)
    output = parse_result(result)["values"]["outputs"]["endpoint"]
    assert output["value"] == "[REDACTED]"
    assert b"sensitive-output-value" not in result.content


@pytest.mark.parametrize(
    "content",
    [b"not-json", b'{"x": 1, "x": 2}', b'{"x": NaN}', b"\xff"],
)
def test_rejects_invalid_or_ambiguous_json(content):
    with pytest.raises(ArtifactSanitizationError):
        sanitizer().sanitize_artifact_content("state.json", content)


def test_rejects_non_object_json_root():
    with pytest.raises(ArtifactSanitizationError, match="root must be an object"):
        sanitizer().sanitize_artifact_content("state.json", b'[1, 2]')


def test_rejects_wrong_filename_and_non_bytes_content():
    with pytest.raises(ArtifactSanitizationError, match="only supports"):
        sanitizer().sanitize_artifact_content("commit.txt", b"abc")
    with pytest.raises(ArtifactSanitizationError, match="must be bytes"):
        sanitizer().sanitize_artifact_content("state.json", "{}")  # type: ignore[arg-type]


def test_fails_closed_when_recognizable_credential_remains_under_unknown_key():
    payload = state_document({"outputs": {"misc": {
        "value": "AKIA1234567890ABCDEF", "type": "string", "sensitive": False
    }}})
    with pytest.raises(ArtifactSanitizationError, match="credential pattern"):
        sanitize("state.json", payload)


def test_fails_closed_when_sensitivity_mask_shape_is_ambiguous():
    payload = plan_document(resource_changes=[{"change": {
        "after": {"items": ["first", "second"]},
        "after_sensitive": {"items": [True]},
        "actions": ["update"],
    }}])
    with pytest.raises(ArtifactSanitizationError, match="does not match list"):
        sanitize("plan.json", payload)


def test_content_sanitization_does_not_mutate_caller_input():
    source = json.dumps(state_document({"outputs": {
        "api_token": {"value": "secret-value", "sensitive": True, "type": "string"}
    }})).encode("utf-8")
    original = bytes(source)
    sanitizer().sanitize_artifact_content("state.json", source)
    assert source == original


def test_requires_format_version():
    payload = state_document()
    del payload["format_version"]
    with pytest.raises(ArtifactSanitizationError, match="format_version"):
        sanitize("state.json", payload)


@pytest.mark.parametrize("format_version", ["1", "1.0.0", "one.two", "01.0", "1.-1"])
def test_rejects_malformed_format_version(format_version):
    with pytest.raises(ArtifactSanitizationError, match="format_version"):
        sanitize("state.json", state_document(format_version=format_version))


def test_rejects_unsupported_major_format_version():
    with pytest.raises(ArtifactSanitizationError, match="Unsupported.*major version"):
        sanitize("state.json", state_document(format_version="2.0"))


def test_accepts_future_minor_format_version():
    payload = state_document(format_version="1.99", future_minor_field={"ignored_by_sanitizer": True})
    result = sanitize("state.json", payload)
    assert parse_result(result)["format_version"] == "1.99"
    assert parse_result(result)["future_minor_field"] == {"ignored_by_sanitizer": True}


@pytest.mark.parametrize("terraform_version", [None, "", "   ", 1])
def test_requires_non_empty_terraform_version(terraform_version):
    with pytest.raises(ArtifactSanitizationError, match="terraform_version"):
        sanitize("state.json", state_document(terraform_version=terraform_version))


def test_plan_requires_planned_values_object():
    with pytest.raises(ArtifactSanitizationError, match="planned_values"):
        sanitize("plan.json", plan_document(planned_values=[]))


def test_plan_requires_resource_changes_array():
    with pytest.raises(ArtifactSanitizationError, match="resource_changes"):
        sanitize("plan.json", plan_document(resource_changes={}))


def test_state_requires_values_object():
    with pytest.raises(ArtifactSanitizationError, match="values to be an object"):
        sanitize("state.json", state_document(values=[]))


def test_rejects_plan_document_named_state_json():
    with pytest.raises(ArtifactSanitizationError, match="plan-shaped"):
        sanitize("state.json", plan_document())


def test_rejects_state_document_named_plan_json():
    with pytest.raises(ArtifactSanitizationError, match="state-shaped"):
        sanitize("plan.json", state_document())
