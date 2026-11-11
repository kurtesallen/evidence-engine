
"""Contract tests for experimental restricted Terraform change summaries."""

import json

import pytest

from evidence_engine.canonical import canonical_json_bytes
from evidence_engine.sanitization import (
    ArtifactSanitizationError,
    SanitizationRule,
    Sanitizer,
)


def restricted_sanitizer():
    return Sanitizer(
        rules=[
            SanitizationRule(
                name="terraform_json_content",
                description="Experimental restricted change summary",
                version="2.1",
            )
        ]
    )


def plan_document(changes):
    return {
        "format_version": "1.0",
        "terraform_version": "1.9.0",
        "planned_values": {"root_module": {"resources": []}},
        "resource_changes": changes,
    }


def change_entry(actions):
    return {
        "address": "example.confidential_resource",
        "change": {
            "actions": actions,
            "before": {"secret": "CONFIDENTIAL-BEFORE-VALUE"},
            "after": {"secret": "CONFIDENTIAL-AFTER-VALUE"},
        },
    }


def sanitize_plan(document):
    return restricted_sanitizer().sanitize_artifact_content(
        "plan.json",
        json.dumps(document).encode("utf-8"),
    )


def test_restricted_summary_classifies_supported_actions():
    actions = [
        ["create"],
        ["update"],
        ["delete"],
        ["delete", "create"],
        ["create", "delete"],
        ["read"],
        ["no-op"],
    ]

    document = plan_document(
        [change_entry(action) for action in actions]
    )

    result = sanitize_plan(document)

    expected = {
        "evidence_profile": "terraform-restricted-change-summary-2.1",
        "format_version": "1.0",
        "terraform_version": "1.9.0",
        "resource_details": "omitted",
        "change_summary": {
            "scope": "resource_changes",
            "creates": 1,
            "updates": 1,
            "deletes": 1,
            "replacements": 2,
            "reads": 1,
            "no_ops": 1,
            "total": 7,
        },
    }

    assert result.content == canonical_json_bytes(expected)
    assert result.applied_rules == ("terraform_json_content@2.1",)

    assert b"CONFIDENTIAL-BEFORE-VALUE" not in result.content
    assert b"CONFIDENTIAL-AFTER-VALUE" not in result.content
    assert b"example.confidential_resource" not in result.content


@pytest.mark.parametrize(
    "actions",
    [
        [],
        ["unknown"],
        ["create", "update"],
        ["delete", "create", "update"],
        "create",
        None,
        [1],
        [True],
    ],
)
def test_restricted_summary_rejects_invalid_actions(actions):
    document = plan_document([change_entry(actions)])

    with pytest.raises(
        ArtifactSanitizationError,
        match="resource change",
    ):
        sanitize_plan(document)


@pytest.mark.parametrize(
    "entry",
    [
        None,
        {},
        {"change": {}},
        {"change": {"actions": ["create"]}},
        {"address": "example.test"},
        {"address": "example.test", "change": None},
    ],
)
def test_restricted_summary_rejects_malformed_entries(entry):
    document = plan_document([entry])

    with pytest.raises(
        ArtifactSanitizationError,
        match="resource change",
    ):
        sanitize_plan(document)


def test_restricted_summary_handles_zero_changes():
    output = json.loads(sanitize_plan(plan_document([])).content)
    assert output["change_summary"] == {
        "scope": "resource_changes",
        "creates": 0,
        "updates": 0,
        "deletes": 0,
        "replacements": 0,
        "reads": 0,
        "no_ops": 0,
        "total": 0,
    }


def test_restricted_summary_excludes_confidential_plan_metadata():
    document = plan_document([change_entry(["update"])])
    document["configuration"] = {
        "secret": "CONFIDENTIAL-PROVIDER-VALUE"
    }
    document["variables"] = {
        "password": {"value": "CONFIDENTIAL-VARIABLE-VALUE"}
    }
    document["output_changes"] = {
        "password": {"after": "CONFIDENTIAL-OUTPUT-VALUE"}
    }

    result = sanitize_plan(document)
    output = json.loads(result.content)

    for secret in (
        b"CONFIDENTIAL-PROVIDER-VALUE",
        b"CONFIDENTIAL-VARIABLE-VALUE",
        b"CONFIDENTIAL-OUTPUT-VALUE",
    ):
        assert secret not in result.content

    for field in ("configuration", "variables", "output_changes"):
        assert field not in output


def test_restricted_summary_state_omits_resource_values():
    document = {
        "format_version": "1.0",
        "terraform_version": "1.9.0",
        "values": {
            "root_module": {
                "resources": [{
                    "address": "example.private_resource",
                    "values": {
                        "password": "CONFIDENTIAL-STATE-VALUE"
                    },
                }]
            }
        },
    }

    result = restricted_sanitizer().sanitize_artifact_content(
        "state.json",
        json.dumps(document).encode("utf-8"),
    )

    assert result.content == canonical_json_bytes({
        "evidence_profile": "terraform-restricted-change-summary-2.1",
        "format_version": "1.0",
        "terraform_version": "1.9.0",
        "resource_details": "omitted",
    })
    assert b"CONFIDENTIAL-STATE-VALUE" not in result.content
    assert b"example.private_resource" not in result.content


def test_restricted_summary_is_deterministic():
    document = plan_document([
        change_entry(["create"]),
        change_entry(["update"]),
        change_entry(["delete"]),
    ])

    first = sanitize_plan(document)
    second = sanitize_plan(document)

    assert first.content == second.content
    assert first.content == canonical_json_bytes(
        json.loads(first.content)
    )


@pytest.mark.parametrize(
    "terraform_version",
    ["", "1.9", "1.9.0-extra", None],
)
def test_restricted_summary_rejects_invalid_terraform_version(
    terraform_version,
):
    document = plan_document([])
    document["terraform_version"] = terraform_version

    with pytest.raises(ArtifactSanitizationError):
        sanitize_plan(document)


def test_restricted_summary_does_not_mutate_input():
    document = plan_document([change_entry(["update"])])
    original = json.dumps(document).encode("utf-8")

    restricted_sanitizer().sanitize_artifact_content(
        "plan.json", original
    )

    assert original == json.dumps(document).encode("utf-8")
