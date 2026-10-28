"""Stage versioned sanitized Terraform artifacts without modifying sources."""
from __future__ import annotations

import os
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from evidence_engine.sanitization import (
    ArtifactSanitizationError,
    SanitizationRule,
    Sanitizer,
    TERRAFORM_JSON_CONTENT_RULE,
    TERRAFORM_JSON_CONTENT_RULE_VERSION,
)
from evidence_engine.schema import REQUIRED_ARTIFACTS

_METADATA_FIELDS = {"representation", "sanitization_rule_version"}
_TERRAFORM_JSON_FILES = {"plan.json", "state.json"}


def stage_sanitized_artifacts(
    source_root: Path,
    destination_root: Path,
    artifact_metadata: Mapping[str, Mapping[str, Any]],
) -> Path:
    """Write a distinct staging copy with plan/state sanitized in-place there.

    Both plan.json and state.json must be explicitly declared sanitized with
    the exact implementation rule version. Other required files may be raw or
    sample, but may not claim this JSON-only sanitizer was applied to them.
    Existing staging directories are reused only when they contain exactly the
    expected regular files; unknown entries and symlinks are rejected.
    """
    source_root = Path(source_root)
    destination_root = Path(destination_root)
    if not source_root.is_dir():
        raise ArtifactSanitizationError("Artifact source root is not a directory")
    if source_root.is_symlink():
        raise ArtifactSanitizationError("Artifact source root must not be a symlink")

    source_resolved = source_root.resolve()
    destination_resolved = destination_root.resolve()
    if (
        source_resolved == destination_resolved
        or source_resolved in destination_resolved.parents
        or destination_resolved in source_resolved.parents
    ):
        raise ArtifactSanitizationError(
            "Sanitized staging directory must not overlap the source directory"
        )

    if not isinstance(artifact_metadata, Mapping):
        raise ArtifactSanitizationError("Explicit artifact metadata is required")
    names = set(artifact_metadata)
    if any(not isinstance(name, str) for name in names):
        raise ArtifactSanitizationError("Artifact metadata keys must be filenames")
    expected_names = set(REQUIRED_ARTIFACTS)
    if names != expected_names:
        raise ArtifactSanitizationError(
            "Artifact metadata must match required artifacts exactly; "
            f"missing={sorted(expected_names - names)}, "
            f"unexpected={sorted(names - expected_names)}"
        )

    normalized_metadata: dict[str, dict[str, Any]] = {}
    for name in sorted(expected_names):
        entry = artifact_metadata[name]
        if not isinstance(entry, Mapping) or set(entry) != _METADATA_FIELDS:
            raise ArtifactSanitizationError(
                f"Metadata for {name} must contain exactly representation and sanitization_rule_version"
            )
        representation = entry["representation"]
        rule_version = entry["sanitization_rule_version"]
        if not isinstance(representation, str) or representation not in {
            "raw", "sanitized", "sample"
        }:
            raise ArtifactSanitizationError(f"Invalid representation for {name}")

        if name in _TERRAFORM_JSON_FILES:
            if representation != "sanitized":
                raise ArtifactSanitizationError(
                    "Both plan.json and state.json must be declared sanitized "
                    "when content sanitization is requested"
                )
            if rule_version != TERRAFORM_JSON_CONTENT_RULE_VERSION:
                raise ArtifactSanitizationError(
                    f"{name} must use sanitization rule version "
                    f"{TERRAFORM_JSON_CONTENT_RULE_VERSION}"
                )
        elif representation not in {"raw", "sample"} or rule_version is not None:
            raise ArtifactSanitizationError(
                f"The Terraform JSON content sanitizer does not support {name}"
            )
        normalized_metadata[name] = {
            "representation": representation,
            "sanitization_rule_version": rule_version,
        }

    source_files: dict[str, Path] = {}
    for path in source_root.iterdir():
        if path.is_symlink() or not path.is_file():
            raise ArtifactSanitizationError(
                f"Unsafe source artifact entry: {path.name}"
            )
        source_files[path.name] = path
    if set(source_files) != expected_names:
        raise ArtifactSanitizationError(
            "Source artifact set mismatch; "
            f"missing={sorted(expected_names - set(source_files))}, "
            f"unexpected={sorted(set(source_files) - expected_names)}"
        )

    sanitizer = Sanitizer(
        rules=[
            SanitizationRule(
                name=TERRAFORM_JSON_CONTENT_RULE,
                description="Versioned Terraform plan/state content sanitization",
                version=TERRAFORM_JSON_CONTENT_RULE_VERSION,
            )
        ]
    )
    output_bytes: dict[str, bytes] = {}
    for name in sorted(expected_names):
        content = source_files[name].read_bytes()
        if name in _TERRAFORM_JSON_FILES:
            result = sanitizer.sanitize_artifact_content(name, content)
            expected_applied = (
                f"{TERRAFORM_JSON_CONTENT_RULE}@"
                f"{TERRAFORM_JSON_CONTENT_RULE_VERSION}"
            )
            if tuple(result.applied_rules) != (expected_applied,):
                raise ArtifactSanitizationError(
                    f"Sanitizer rule audit mismatch for {name}"
                )
            output_bytes[name] = result.content
        else:
            output_bytes[name] = content

    if destination_root.is_symlink():
        raise ArtifactSanitizationError("Staging directory must not be a symlink")
    if destination_root.exists():
        if not destination_root.is_dir():
            raise ArtifactSanitizationError("Staging destination is not a directory")
        existing = list(destination_root.iterdir())
        if any(path.is_symlink() or not path.is_file() for path in existing):
            raise ArtifactSanitizationError("Staging destination contains unsafe entries")
        if {path.name for path in existing} - expected_names:
            raise ArtifactSanitizationError("Staging destination contains unexpected entries")
    else:
        destination_root.mkdir(parents=True, exist_ok=False)

    temporary_paths: list[Path] = []
    try:
        for name, content in output_bytes.items():
            fd, raw_path = tempfile.mkstemp(
                prefix=f".{name}.", suffix=".tmp", dir=destination_root
            )
            temp_path = Path(raw_path)
            temporary_paths.append(temp_path)
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
        for name, temp_path in zip(output_bytes, temporary_paths):
            os.replace(temp_path, destination_root / name)
        temporary_paths.clear()
    finally:
        for temp_path in temporary_paths:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass

    return destination_root
