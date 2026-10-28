"""Build and serialize EvidenceEngine manifests."""

import hashlib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from evidence_engine.canonical import canonical_json_bytes
from evidence_engine.schema import (
    SUPPORTED_SCHEMA_VERSIONS,
    validate_manifest,
)


def sha256_file(path: Path) -> str:
    """Calculate the SHA-256 digest of a file without loading it all into memory."""
    digest = hashlib.sha256()

    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def build_manifest(
    artifact_dir: Path,
    provenance: dict[str, Any],
    key_id: str,
    schema_version: str = "1.1",
    artifact_metadata: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build and validate a manifest, optionally with explicit artifact metadata.

    When metadata is omitted, legacy development behavior labels files as samples.
    Explicit metadata records declarations; it does not prove content was sanitized.
    """
    if schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        raise ValueError(f"Unsupported manifest schema version: {schema_version}")

    if not artifact_dir.is_dir():
        raise ValueError("Artifact directory does not exist")

    paths = sorted(artifact_dir.iterdir())
    for path in paths:
        if path.is_symlink():
            raise ValueError(f"Symlinks are not allowed: {path.name}")
        if not path.is_file():
            raise ValueError(
                "Unexpected directory or special entry: "
                f"{path.name}"
            )

    file_names = {path.name for path in paths}
    if artifact_metadata is not None:
        supplied_names = set(artifact_metadata)
        if any(not isinstance(name, str) for name in supplied_names):
            raise ValueError("Artifact metadata keys must be filenames")
        if supplied_names != file_names:
            missing = sorted(file_names - supplied_names)
            unexpected = sorted(supplied_names - file_names)
            raise ValueError(
                "Artifact metadata must match artifact files exactly; "
                f"missing={missing}, unexpected={unexpected}"
            )

    artifacts = []
    for path in paths:
        if artifact_metadata is None:
            representation = "sample"
            rule_version = None
        else:
            metadata = artifact_metadata[path.name]
            if not isinstance(metadata, Mapping):
                raise ValueError(f"Metadata for {path.name} must be a mapping")
            if set(metadata) != {
                "representation",
                "sanitization_rule_version",
            }:
                raise ValueError(
                    f"Metadata for {path.name} must contain exactly "
                    "'representation' and 'sanitization_rule_version'"
                )

            representation = metadata["representation"]
            rule_version = metadata["sanitization_rule_version"]
            if not isinstance(representation, str) or representation not in {
                "raw",
                "sanitized",
                "sample",
            }:
                raise ValueError(
                    f"Invalid representation for {path.name}: "
                    f"{representation!r}"
                )

            if representation == "sanitized":
                if not isinstance(rule_version, str) or not rule_version.strip():
                    raise ValueError(
                        f"Sanitized artifact {path.name} requires a non-empty "
                        "sanitization rule version"
                    )
            elif rule_version is not None:
                raise ValueError(
                    f"Non-sanitized artifact {path.name} must use "
                    "sanitization_rule_version=None"
                )

        artifacts.append(
            {
                "name": path.name,
                "size_bytes": path.stat().st_size,
                "representation": representation,
                "sanitization_rule_version": rule_version,
                "sha256": sha256_file(path),
            }
        )

    manifest = {
        "schema_version": schema_version,
        "hash_algorithm": "SHA-256",
        "signature_algorithm": "RSA-PSS-SHA256",
        "key_id": key_id,
        "provenance": provenance,
        "artifacts": artifacts,
    }

    validate_manifest(manifest)
    return manifest


def write_manifest(
    artifact_dir: Path,
    destination: Path,
    provenance: dict[str, Any],
    key_id: str,
    schema_version: str = "1.1",
    artifact_metadata: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build, validate, and write a canonical JSON manifest."""
    manifest = build_manifest(
        artifact_dir=artifact_dir,
        provenance=provenance,
        key_id=key_id,
        schema_version=schema_version,
        artifact_metadata=artifact_metadata,
    )

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(canonical_json_bytes(manifest))

    return manifest
