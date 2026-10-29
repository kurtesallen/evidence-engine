
"""Strict validation rules for EvidenceEngine manifest v1.1, v1.2, and v1.3."""

import re
from typing import Any

REQUIRED_ARTIFACTS = {
    "plan.json",
    "state.json",
    "commit.txt",
    "version.txt",
}

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
POSITIVE_INTEGER_RE = re.compile(r"^[1-9][0-9]*$")
STREAM_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")

SUPPORTED_SCHEMA_VERSIONS = {"1.1", "1.2", "1.3"}

TOP_LEVEL_FIELDS = {
    "schema_version",
    "hash_algorithm",
    "signature_algorithm",
    "key_id",
    "provenance",
    "artifacts",
}

ARTIFACT_FIELDS = {
    "name",
    "size_bytes",
    "representation",
    "sanitization_rule_version",
    "sha256",
}

PROVENANCE_FIELDS_V1_1 = {
    "repository",
    "commit_sha",
    "workflow_run_id",
    "terraform_version",
    "provider_lock_sha256",
    "source",
}

ORDERED_CI_FIELDS = {
    "ref",
    "workflow_ref",
    "run_number",
    "run_attempt",
}

PROVENANCE_FIELDS_V1_2 = (
    PROVENANCE_FIELDS_V1_1 | ORDERED_CI_FIELDS
)
PROVENANCE_FIELDS_V1_3 = PROVENANCE_FIELDS_V1_2 | {"stream_id"}


def validate_manifest(value: Any) -> None:
    """Reject unsupported or malformed manifest structures."""

    if not isinstance(value, dict):
        raise ValueError("Manifest must be a JSON object")

    if set(value) != TOP_LEVEL_FIELDS:
        raise ValueError(
            "Manifest has missing or unknown top-level fields"
        )

    schema_version = value["schema_version"]

    if (
        not isinstance(schema_version, str)
        or schema_version not in SUPPORTED_SCHEMA_VERSIONS
    ):
        raise ValueError("Unsupported manifest schema")

    if value["hash_algorithm"] != "SHA-256":
        raise ValueError("Unsupported hash algorithm")

    if value["signature_algorithm"] != "RSA-PSS-SHA256":
        raise ValueError("Unsupported signature algorithm")

    key_id = value["key_id"]

    if (
        not isinstance(key_id, str)
        or not key_id
        or len(key_id) > 128
    ):
        raise ValueError("Invalid key ID")

    # Select the exact provenance schema for this manifest version.
    provenance = value["provenance"]

    if not isinstance(provenance, dict):
        raise ValueError("Provenance must be an object")

    if schema_version == "1.1":
        expected_provenance_fields = PROVENANCE_FIELDS_V1_1
    elif schema_version == "1.2":
        expected_provenance_fields = PROVENANCE_FIELDS_V1_2
    else:
        expected_provenance_fields = PROVENANCE_FIELDS_V1_3

    if set(provenance) != expected_provenance_fields:
        raise ValueError(
            "Provenance has missing or unknown fields"
        )

    # Validate every provenance field individually.
    for field in expected_provenance_fields:
        field_value = provenance[field]

        if not isinstance(field_value, str):
            raise ValueError(
                f"Invalid provenance field: {field}"
            )

        # An empty provider lock digest means it has not been
        # captured. Other provenance fields remain mandatory.
        if field == "provider_lock_sha256":
            continue

        if not field_value:
            raise ValueError(
                f"Invalid provenance field: {field}"
            )

    if provenance["source"] not in {
        "local-claimed",
        "github-actions-claimed",
    }:
        raise ValueError("Unsupported provenance source")

    # Validate the provider lock-file digest when present.
    lock_digest = provenance["provider_lock_sha256"]

    if lock_digest and not SHA256_RE.fullmatch(lock_digest):
        raise ValueError("Invalid provider lock-file digest")

    # v1.2 adds ordered CI provenance; v1.3 also binds a stream ID.
    # These fields are claims; their presence does not independently
    # authenticate the workflow or runner.
    if schema_version in {"1.2", "1.3"}:
        if provenance["source"] != "github-actions-claimed":
            raise ValueError(
                "Manifest v1.2 requires GitHub Actions provenance"
            )

        if not provenance["ref"].startswith("refs/"):
            raise ValueError("Invalid provenance ref")

        if not provenance["workflow_ref"]:
            raise ValueError("Invalid workflow reference")

        for field in ("run_number", "run_attempt"):
            if not POSITIVE_INTEGER_RE.fullmatch(
                provenance[field]
            ):
                raise ValueError(
                    f"Invalid provenance field: {field}"
                )

    if schema_version == "1.3":
        stream_id = provenance["stream_id"]
        if not STREAM_ID_RE.fullmatch(stream_id):
            raise ValueError("Invalid provenance stream_id")

    # Validate artifacts.
    artifacts = value["artifacts"]

    if not isinstance(artifacts, list) or not artifacts:
        raise ValueError("Artifacts must be a non-empty list")

    seen = set()

    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise ValueError("Artifact entry must be an object")

        if set(artifact) != ARTIFACT_FIELDS:
            raise ValueError(
                "Artifact entry has missing or unknown fields"
            )

        name = artifact["name"]

        if (
            not isinstance(name, str)
            or not name
            or name in {".", ".."}
            or "/" in name
            or "\\" in name
        ):
            raise ValueError("Invalid artifact name")

        if name in seen:
            raise ValueError(
                f"Duplicate artifact name: {name}"
            )

        seen.add(name)

        size = artifact["size_bytes"]

        if type(size) is not int or size < 0:
            raise ValueError(
                f"Invalid artifact size: {name}"
            )

        representation = artifact["representation"]

        if representation not in {
            "raw",
            "sanitized",
            "sample",
        }:
            raise ValueError(
                f"Invalid representation: {name}"
            )

        rule_version = artifact["sanitization_rule_version"]

        if rule_version is not None and (
            not isinstance(rule_version, str)
            or not rule_version
        ):
            raise ValueError(
                f"Invalid sanitization version: {name}"
            )

        if (
            representation == "sanitized"
            and rule_version is None
        ):
            raise ValueError(
                f"Sanitized artifact lacks a rule version: {name}"
            )

        digest = artifact["sha256"]

        if (
            not isinstance(digest, str)
            or not SHA256_RE.fullmatch(digest)
        ):
            raise ValueError(
                f"Invalid SHA-256 digest: {name}"
            )

    # Require the exact artifact set defined by this policy.
    if seen != REQUIRED_ARTIFACTS:
        missing = REQUIRED_ARTIFACTS - seen
        unexpected = seen - REQUIRED_ARTIFACTS

        raise ValueError(
            f"Artifact set mismatch; missing={sorted(missing)}, "
            f"unexpected={sorted(unexpected)}"
        )
