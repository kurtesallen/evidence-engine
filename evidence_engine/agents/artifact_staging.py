
"""Stage versioned sanitized Terraform artifacts without modifying sources."""

from __future__ import annotations

import json
import logging
import os
import tempfile
import uuid
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


logger = logging.getLogger(__name__)

_METADATA_FIELDS = {"representation", "sanitization_rule_version"}
_TERRAFORM_JSON_FILES = {"plan.json", "state.json"}


def _reject_symlink_components(path: Path, *, label: str) -> None:
    """Reject symlinks in every existing component of a path."""
    try:
        absolute = path.absolute()
        current = Path(absolute.anchor)

        for part in absolute.parts[1:]:
            current = current / part

            if current.is_symlink():
                raise ArtifactSanitizationError(
                    f"{label} contains a symlinked path component: {current}"
                )
    except ArtifactSanitizationError:
        raise
    except OSError as exc:
        raise ArtifactSanitizationError(
            f"Unable to inspect {label} path components"
        ) from exc


def _validate_destination(destination_root: Path) -> None:
    """Reject unsafe existing staging destinations."""
    if destination_root.is_symlink():
        raise ArtifactSanitizationError(
            "Staging directory must not be a symlink"
        )

    if not destination_root.exists():
        return

    if not destination_root.is_dir():
        raise ArtifactSanitizationError(
            "Staging destination is not a directory"
        )

    existing = list(destination_root.iterdir())

    if any(path.is_symlink() or not path.is_file() for path in existing):
        raise ArtifactSanitizationError(
            "Staging destination contains unsafe entries"
        )

    existing_names = {path.name for path in existing}
    expected_names = set(REQUIRED_ARTIFACTS)

    missing = sorted(expected_names - existing_names)
    unexpected = sorted(existing_names - expected_names)

    if missing or unexpected:
        raise ArtifactSanitizationError(
            "Existing staging destination must contain exactly the "
            "required regular files; "
            f"missing files={missing}; "
            f"unexpected entries={unexpected}"
        )


def _write_generation(
    generation_root: Path,
    output_bytes: Mapping[str, bytes],
) -> None:
    """Write and sync every artifact into a fresh private generation."""
    generation_root.mkdir(
        mode=0o700,
        parents=False,
        exist_ok=False,
    )

    try:
        os.chmod(generation_root, 0o700)
    except OSError as exc:
        raise ArtifactSanitizationError(
            "Unable to secure the staging generation directory"
        ) from exc

    for name in sorted(output_bytes):
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{name}.",
            suffix=".tmp",
            dir=generation_root,
        )
        temporary_path: Path | None = Path(temporary_name)

        try:
            os.chmod(temporary_path, 0o600)

            with os.fdopen(descriptor, "wb") as stream:
                descriptor = -1
                stream.write(output_bytes[name])
                stream.flush()
                os.fsync(stream.fileno())

            os.replace(temporary_path, generation_root / name)
            temporary_path = None

        finally:
            if descriptor >= 0:
                os.close(descriptor)

            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)


def _cleanup_backup(backup_root: Path) -> None:
    """Remove a previous generation after successful publication."""
    for path in backup_root.iterdir():
        if path.is_symlink() or not path.is_file():
            raise OSError(
                f"Unexpected entry in staging backup: {path.name}"
            )
        path.unlink()

    backup_root.rmdir()


def _publish_generation(
    generation_root: Path,
    destination_root: Path,
) -> None:
    """Publish a complete generation and restore the previous one on failure.

    Directory replacement is atomic when the destination does not exist.
    Replacing a non-empty destination directory is not portable across
    platforms. Therefore, an existing destination is first renamed to a
    unique backup, the new generation is moved into place, and the backup
    is restored if publication fails.

    Readers must coordinate with the producer and only consume the
    destination after this function returns successfully. The backup
    interval is not a cross-platform atomic directory exchange.
    """
    _validate_destination(destination_root)

    backup_root: Path | None = None

    if destination_root.exists():
        backup_root = destination_root.with_name(
            f".{destination_root.name}.backup-{uuid.uuid4().hex}"
        )

        try:
            os.replace(destination_root, backup_root)
        except OSError as exc:
            raise ArtifactSanitizationError(
                "Unable to preserve the existing staging generation"
            ) from exc

    try:
        os.replace(generation_root, destination_root)

    except OSError as publish_error:
        if backup_root is not None:
            try:
                os.replace(backup_root, destination_root)
                backup_root = None
            except OSError as restore_error:
                raise ArtifactSanitizationError(
                    "Unable to publish the new staging generation or "
                    "restore the previous generation; previous generation "
                    f"remains at {backup_root}"
                ) from restore_error

        raise ArtifactSanitizationError(
            "Unable to publish the sanitized staging generation"
        ) from publish_error

    # Publication has succeeded. Failure to remove the previous generation
    # is a cleanup problem, not a publication failure. Preserve the backup
    # for manual cleanup and report its location through the logger.
    if backup_root is not None:
        try:
            _cleanup_backup(backup_root)
        except OSError as exc:
            logger.warning(
                "New staging generation was published successfully, "
                "but the previous generation could not be removed: %s "
                "(%s)",
                backup_root,
                type(exc).__name__,
            )


def stage_sanitized_artifacts(
    source_root: Path,
    destination_root: Path,
    artifact_metadata: Mapping[str, Mapping[str, Any]],
) -> Path:
    """Write a distinct staging generation with Terraform JSON sanitized.

    Both plan.json and state.json must be explicitly declared sanitized with
    the exact implementation rule version. Other required files may be raw or
    sample, but may not claim this JSON-only sanitizer was applied to them.

    Terraform versions extracted from plan.json and state.json must match.
    All artifacts are written into a fresh generation directory before
    publication. Source files are never modified.
    """
    source_root = Path(source_root)
    destination_root = Path(destination_root)

    # Reject symlinks in the full paths before resolve() can follow them.
    _reject_symlink_components(source_root, label="Artifact source")
    _reject_symlink_components(destination_root, label="Staging destination")

    if not source_root.is_dir():
        raise ArtifactSanitizationError(
            "Artifact source root is not a directory"
        )

    try:
        source_root = source_root.resolve()
        destination_root = destination_root.resolve()
    except (OSError, RuntimeError) as exc:
        raise ArtifactSanitizationError(
            "Unable to resolve artifact staging paths"
        ) from exc

    if (
        source_root == destination_root
        or source_root in destination_root.parents
        or destination_root in source_root.parents
    ):
        raise ArtifactSanitizationError(
            "Sanitized staging directory must not overlap the source directory"
        )

    if not isinstance(artifact_metadata, Mapping):
        raise ArtifactSanitizationError(
            "Explicit artifact metadata is required"
        )

    metadata_names = list(artifact_metadata.keys())

    if any(not isinstance(name, str) for name in metadata_names):
        raise ArtifactSanitizationError(
            "Artifact metadata keys must be filenames"
        )

    names = set(metadata_names)
    expected_names = set(REQUIRED_ARTIFACTS)

    if names != expected_names:
        raise ArtifactSanitizationError(
            "Artifact metadata must match required artifacts exactly; "
            f"missing={sorted(expected_names - names)}, "
            f"unexpected={sorted(names - expected_names)}"
        )

    for name in sorted(expected_names):
        entry = artifact_metadata[name]

        if not isinstance(entry, Mapping) or set(entry) != _METADATA_FIELDS:
            raise ArtifactSanitizationError(
                f"Metadata for {name} must contain exactly "
                "representation and sanitization_rule_version"
            )

        representation = entry["representation"]
        rule_version = entry["sanitization_rule_version"]

        if not isinstance(representation, str) or representation not in {
            "raw",
            "sanitized",
            "sample",
        }:
            raise ArtifactSanitizationError(
                f"Invalid representation for {name}"
            )

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
    terraform_versions: dict[str, str] = {}

    for name in sorted(expected_names):
        try:
            content = source_files[name].read_bytes()
        except OSError as exc:
            raise ArtifactSanitizationError(
                f"Unable to read source artifact: {name}"
            ) from exc

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

            try:
                sanitized_document = json.loads(result.content)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ArtifactSanitizationError(
                    f"Unable to read sanitized Terraform document: {name}"
                ) from exc

            if not isinstance(sanitized_document, dict):
                raise ArtifactSanitizationError(
                    f"Terraform document must be a JSON object: {name}"
                )

            terraform_version = sanitized_document.get("terraform_version")

            if (
                not isinstance(terraform_version, str)
                or not terraform_version.strip()
            ):
                raise ArtifactSanitizationError(
                    f"Terraform version is missing or invalid: {name}"
                )

            terraform_versions[name] = terraform_version
            output_bytes[name] = result.content

        else:
            output_bytes[name] = content

    if terraform_versions["plan.json"] != terraform_versions["state.json"]:
        raise ArtifactSanitizationError(
            "Terraform version mismatch between plan.json and state.json"
        )

    _validate_destination(destination_root)

    parent = destination_root.parent

    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ArtifactSanitizationError(
            "Unable to prepare the staging parent directory"
        ) from exc

    # Recheck after parent creation and immediately before creating the
    # generation. This narrows, but does not eliminate, filesystem races.
    _reject_symlink_components(destination_root, label="Staging destination")

    generation_root = parent / (
        f".{destination_root.name}.generation-{uuid.uuid4().hex}"
    )

    try:
        _write_generation(generation_root, output_bytes)
        _publish_generation(generation_root, destination_root)

    except ArtifactSanitizationError:
        raise

    except OSError as exc:
        raise ArtifactSanitizationError(
            "Unable to create or publish the sanitized artifact generation"
        ) from exc

    finally:
        if generation_root.exists():
            try:
                for path in generation_root.iterdir():
                    if path.is_dir() and not path.is_symlink():
                        raise OSError(
                            f"Unexpected directory in staging generation: {path.name}"
                        )
                    path.unlink(missing_ok=True)
                generation_root.rmdir()
            except OSError:
                logger.warning(
                    "Unable to remove incomplete staging generation: %s",
                    generation_root,
                )

    return destination_root
