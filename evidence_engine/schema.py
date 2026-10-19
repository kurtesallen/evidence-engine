"""Strict validation rules for EvidenceEngine manifest v1.1."""

import re
from typing import Any

REQUIRED_ARTIFACTS = {
    "plan.json",
    "state.json",
    "commit.txt",
    "version.txt",
}

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

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

PROVENANCE_FIELDS = {
    "repository",
    "commit_sha",
    "workflow_run_id",
    "terraform_version",
    "provider_lock_sha256",
    "source",
}


def validate_manifest(value: Any) -> None:
    """Reject unsupported or malformed manifest structures."""

    if not isinstance(value, dict):
        raise ValueError("Manifest must be a JSON object")

    if set(value) != TOP_LEVEL_FIELDS:
        raise ValueError(
            "Manifest has missing or unknown top-level fields"
        )

    if value["schema_version"] != "1.1":
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

    # Validate provenance structure.
    provenance = value["provenance"]

    if not isinstance(provenance, dict):
        raise ValueError("Provenance must be an object")

    if set(provenance) != PROVENANCE_FIELDS:
        raise ValueError(
            "Provenance has missing or unknown fields"
        )

    # Validate every provenance field individually.
    for field in PROVENANCE_FIELDS:
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