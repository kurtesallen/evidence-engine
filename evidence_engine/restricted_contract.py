"""Structural validation for experimental restricted Terraform evidence.

This module does not authenticate evidence, validate signatures, or authorize
production publication or consumption.
"""

import re
from typing import Any

PROFILE_20 = "terraform-restricted-2.0"
PROFILE_21 = "terraform-restricted-change-summary-2.1"

_SUPPORTED_PROFILES = frozenset({PROFILE_20, PROFILE_21})
_SUPPORTED_ARTIFACTS = frozenset({"plan.json", "state.json"})

_ENVELOPE_FIELDS = frozenset({
    "evidence_profile",
    "format_version",
    "terraform_version",
    "resource_details",
})

_COUNT_FIELDS = frozenset({
    "creates",
    "updates",
    "deletes",
    "replacements",
    "reads",
    "no_ops",
})

_SUMMARY_FIELDS = _COUNT_FIELDS | {"scope", "total"}

_FORMAT_VERSION_RE = re.compile(r"^1\.[0-9]+$")
_TERRAFORM_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


def validate_restricted_document(name: str, document: Any) -> None:
    """Validate an experimental restricted Terraform projection.

    Raises ValueError when the document violates the declared profile.

    Successful validation establishes structural consistency only.
    It does not prove that the summary accurately reflects a Terraform
    plan or state, or that the evidence came from a trusted producer.
    """
    if not isinstance(name, str) or name not in _SUPPORTED_ARTIFACTS:
        raise ValueError("Unsupported restricted evidence artifact name")

    if not isinstance(document, dict):
        raise ValueError("Restricted evidence must be a JSON object")

    profile = document.get("evidence_profile")
    if not isinstance(profile, str) or profile not in _SUPPORTED_PROFILES:
        raise ValueError("Unsupported restricted evidence profile")

    expected_fields = set(_ENVELOPE_FIELDS)

    # Profile 2.0 plans explicitly declare that change details are omitted.
    # Profile 2.1 plans provide an aggregate change summary instead.
    if profile == PROFILE_20 and name == "plan.json":
        expected_fields.add("change_details")
    elif profile == PROFILE_21 and name == "plan.json":
        expected_fields.add("change_summary")

    if set(document) != expected_fields:
        raise ValueError("Restricted evidence has missing or unknown fields")

    format_version = document["format_version"]
    if (
        not isinstance(format_version, str)
        or _FORMAT_VERSION_RE.fullmatch(format_version) is None
    ):
        raise ValueError("Invalid restricted evidence format_version")

    terraform_version = document["terraform_version"]
    if (
        not isinstance(terraform_version, str)
        or _TERRAFORM_VERSION_RE.fullmatch(terraform_version) is None
    ):
        raise ValueError("Invalid restricted evidence terraform_version")

    if document["resource_details"] != "omitted":
        raise ValueError("Restricted evidence must omit resource details")

    # Profile 2.0 does not expose change details or aggregate counts.
    if profile == PROFILE_20 and name == "plan.json":
        if document["change_details"] != "omitted":
            raise ValueError(
                "Restricted profile 2.0 must omit change details"
            )

    # Only profile 2.1 plans contain a change summary.
    if profile != PROFILE_21 or name != "plan.json":
        return

    summary = document["change_summary"]

    if not isinstance(summary, dict):
        raise ValueError("Restricted change summary must be an object")

    if set(summary) != _SUMMARY_FIELDS:
        raise ValueError(
            "Restricted change summary has missing or unknown fields"
        )

    if summary["scope"] != "resource_changes":
        raise ValueError("Unsupported restricted change summary scope")

    for field in _COUNT_FIELDS | {"total"}:
        value = summary[field]

        # bool is a subclass of int; reject it explicitly.
        if type(value) is not int or value < 0:
            raise ValueError(f"Invalid restricted change count: {field}")

    expected_total = sum(summary[field] for field in _COUNT_FIELDS)

    if summary["total"] != expected_total:
        raise ValueError("Restricted change summary total mismatch")


def validate_restricted_bytes(name: str, content: bytes) -> None:
    """Validate canonical serialized experimental restricted evidence.

    This establishes structural and serialization validity only.
    It does not authenticate the producer or authorize consumption.
    """
    from evidence_engine.canonical import (
        canonical_json_bytes,
        parse_json_strict,
    )

    if not isinstance(content, bytes):
        raise ValueError("Restricted evidence content must be bytes")

    document = parse_json_strict(content)

    validate_restricted_document(name, document)

    if canonical_json_bytes(document) != content:
        raise ValueError("Restricted evidence must use canonical JSON")
