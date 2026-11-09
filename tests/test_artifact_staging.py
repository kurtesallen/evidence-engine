
"""Tests for staging sanitized Terraform evidence as a separate artifact set."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

import evidence_engine.agents.artifact_staging as artifact_staging
from evidence_engine.agents.artifact_staging import stage_sanitized_artifacts
from evidence_engine.sanitization import ArtifactSanitizationError
from evidence_engine.schema import REQUIRED_ARTIFACTS


RULE_VERSION = "1.1"


def metadata(*, plan: str = "sanitized", state: str = "sanitized"):
    return {
        "plan.json": {
            "representation": plan,
            "sanitization_rule_version": (
                RULE_VERSION if plan == "sanitized" else None
            ),
        },
        "state.json": {
            "representation": state,
            "sanitization_rule_version": (
                RULE_VERSION if state == "sanitized" else None
            ),
        },
        "commit.txt": {
            "representation": "raw",
            "sanitization_rule_version": None,
        },
        "version.txt": {
            "representation": "raw",
            "sanitization_rule_version": None,
        },
    }


def write_source(root: Path) -> dict[str, bytes]:
    root.mkdir(parents=True)

    plan = {
        "format_version": "1.0",
        "terraform_version": "1.9.0",
        "planned_values": {
            "root_module": {
                "resources": [],
            },
        },
        "resource_changes": [
            {
                "address": "example.db",
                "change": {
                    "actions": ["update"],
                    "before": {
                        "opaque": "PLAN-CANARY-SECRET",
                    },
                    "before_sensitive": {
                        "opaque": True,
                    },
                    "after": {
                        "opaque": "PLAN-CANARY-SECRET",
                    },
                    "after_sensitive": {
                        "opaque": True,
                    },
                },
            },
        ],
    }

    state = {
        "format_version": "1.0",
        "terraform_version": "1.9.0",
        "values": {
            "root_module": {
                "resources": [
                    {
                        "address": "example.db",
                        "mode": "managed",
                        "type": "example",
                        "name": "db",
                        "values": {
                            "opaque": "STATE-CANARY-SECRET",
                        },
                        "sensitive_values": {
                            "opaque": True,
                        },
                    },
                ],
            },
        },
    }

    (root / "plan.json").write_text(
        json.dumps(plan),
        encoding="utf-8",
    )
    (root / "state.json").write_text(
        json.dumps(state),
        encoding="utf-8",
    )
    (root / "commit.txt").write_text(
        "a" * 40 + "\n",
        encoding="utf-8",
    )
    (root / "version.txt").write_text(
        "terraform 1.9.0\n",
        encoding="utf-8",
    )

    assert {path.name for path in root.iterdir()} == set(REQUIRED_ARTIFACTS)

    return {
        path.name: path.read_bytes()
        for path in root.iterdir()
    }


def test_staging_sanitizes_plan_and_state_without_mutating_source(
    tmp_path: Path,
):
    source = tmp_path / "source"
    originals = write_source(source)
    destination = tmp_path / "bundle" / "artifacts"

    staged = stage_sanitized_artifacts(
        source,
        destination,
        metadata(),
    )

    assert staged == destination

    # Original source artifacts remain unchanged.
    assert (source / "plan.json").read_bytes() == originals["plan.json"]
    assert (source / "state.json").read_bytes() == originals["state.json"]

    # Sensitive values are redacted in the staged artifacts.
    plan_bytes = (staged / "plan.json").read_bytes()
    state_bytes = (staged / "state.json").read_bytes()

    assert b"PLAN-CANARY-SECRET" not in plan_bytes
    assert b"STATE-CANARY-SECRET" not in state_bytes

    sanitized_plan = json.loads(plan_bytes)
    sanitized_state = json.loads(state_bytes)

    assert (
        sanitized_plan["resource_changes"][0]["change"]["after"]["opaque"]
        == "[REDACTED]"
    )
    assert (
        sanitized_state["values"]["root_module"]["resources"][0]["values"]["opaque"]
        == "[REDACTED]"
    )

    # Non-Terraform artifacts are copied without modification.
    assert (staged / "commit.txt").read_bytes() == originals["commit.txt"]
    assert (staged / "version.txt").read_bytes() == originals["version.txt"]


def test_rejects_only_one_terraform_file_marked_sanitized(
    tmp_path: Path,
):
    source = tmp_path / "source"
    write_source(source)

    bad = metadata(state="raw")

    with pytest.raises(
        ArtifactSanitizationError,
        match="Both plan.json and state.json",
    ):
        stage_sanitized_artifacts(
            source,
            tmp_path / "bundle" / "artifacts",
            bad,
        )


def test_rejects_metadata_rule_version_mismatch(
    tmp_path: Path,
):
    source = tmp_path / "source"
    write_source(source)

    bad = metadata()
    bad["plan.json"]["sanitization_rule_version"] = "99.0"

    with pytest.raises(
        ArtifactSanitizationError,
        match="rule version",
    ):
        stage_sanitized_artifacts(
            source,
            tmp_path / "bundle" / "artifacts",
            bad,
        )


def test_rejects_invalid_terraform_json_before_creating_staging_directory(
    tmp_path: Path,
):
    source = tmp_path / "source"
    write_source(source)

    (source / "plan.json").write_text(
        "not json",
        encoding="utf-8",
    )

    destination = tmp_path / "bundle" / "artifacts"

    with pytest.raises(ArtifactSanitizationError):
        stage_sanitized_artifacts(
            source,
            destination,
            metadata(),
        )

    assert not destination.exists()


def test_rejects_plan_state_terraform_version_mismatch(
    tmp_path: Path,
):
    source = tmp_path / "source"
    write_source(source)

    state_path = source / "state.json"
    state_document = json.loads(
        state_path.read_text(encoding="utf-8")
    )
    state_document["terraform_version"] = "1.10.0"

    state_path.write_text(
        json.dumps(state_document),
        encoding="utf-8",
    )

    destination = tmp_path / "bundle" / "artifacts"

    with pytest.raises(
        ArtifactSanitizationError,
        match="Terraform version mismatch",
    ):
        stage_sanitized_artifacts(
            source,
            destination,
            metadata(),
        )

    # Version mismatch must be detected before staging is created.
    assert not destination.exists()


def test_rejects_extra_source_file(
    tmp_path: Path,
):
    source = tmp_path / "source"
    write_source(source)

    (source / "unexpected.txt").write_text(
        "extra",
        encoding="utf-8",
    )

    with pytest.raises(
        ArtifactSanitizationError,
        match="Source artifact set mismatch",
    ):
        stage_sanitized_artifacts(
            source,
            tmp_path / "bundle" / "artifacts",
            metadata(),
        )


def test_rejects_unsafe_existing_destination_entry(
    tmp_path: Path,
):
    source = tmp_path / "source"
    write_source(source)

    destination = tmp_path / "bundle" / "artifacts"
    destination.mkdir(parents=True)

    (destination / "unexpected.txt").write_text(
        "do not overwrite",
        encoding="utf-8",
    )

    with pytest.raises(
        ArtifactSanitizationError,
        match="unexpected entries",
    ):
        stage_sanitized_artifacts(
            source,
            destination,
            metadata(),
        )


def test_rejects_overlapping_source_and_destination(
    tmp_path: Path,
):
    source = tmp_path / "source"
    write_source(source)

    with pytest.raises(
        ArtifactSanitizationError,
        match="must not overlap",
    ):
        stage_sanitized_artifacts(
            source,
            source / "staged",
            metadata(),
        )


def test_rejects_symlinked_source_parent(
    tmp_path: Path,
):
    real_parent = tmp_path / "real-source-parent"
    source = real_parent / "source"
    write_source(source)

    linked_parent = tmp_path / "linked-source-parent"

    try:
        linked_parent.symlink_to(
            real_parent,
            target_is_directory=True,
        )
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"Directory symlinks are unavailable: {exc}")

    destination = tmp_path / "destination"

    with pytest.raises(
        ArtifactSanitizationError,
        match="symlinked path component",
    ):
        stage_sanitized_artifacts(
            linked_parent / "source",
            destination,
            metadata(),
        )

    assert not destination.exists()


def test_rejects_symlinked_destination_parent(
    tmp_path: Path,
):
    source = tmp_path / "source"
    write_source(source)

    real_parent = tmp_path / "real-destination-parent"
    real_parent.mkdir()

    linked_parent = tmp_path / "linked-destination-parent"

    try:
        linked_parent.symlink_to(
            real_parent,
            target_is_directory=True,
        )
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"Directory symlinks are unavailable: {exc}")

    destination = linked_parent / "bundle"

    with pytest.raises(
        ArtifactSanitizationError,
        match="symlinked path component",
    ):
        stage_sanitized_artifacts(
            source,
            destination,
            metadata(),
        )

    assert not (real_parent / "bundle").exists()


def test_parent_directory_permissions_are_not_changed(
    tmp_path: Path,
):
    if os.name != "posix":
        pytest.skip("POSIX permission semantics required")

    source = tmp_path / "source"
    write_source(source)

    parent = tmp_path / "bundle"
    parent.mkdir()
    parent.chmod(0o750)

    before = stat.S_IMODE(parent.stat().st_mode)
    destination = parent / "artifacts"

    stage_sanitized_artifacts(
        source,
        destination,
        metadata(),
    )

    after = stat.S_IMODE(parent.stat().st_mode)

    assert before == 0o750
    assert after == before


def test_published_generation_has_restrictive_permissions(
    tmp_path: Path,
):
    if os.name != "posix":
        pytest.skip("POSIX permission semantics required")

    source = tmp_path / "source"
    write_source(source)

    destination = tmp_path / "bundle" / "artifacts"

    staged = stage_sanitized_artifacts(
        source,
        destination,
        metadata(),
    )

    assert stat.S_IMODE(staged.stat().st_mode) == 0o700

    for artifact in REQUIRED_ARTIFACTS:
        artifact_path = staged / artifact

        assert artifact_path.is_file()
        assert stat.S_IMODE(artifact_path.stat().st_mode) == 0o600


def test_backup_cleanup_failure_does_not_fail_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    source = tmp_path / "source"
    write_source(source)

    destination = tmp_path / "bundle" / "artifacts"

    # Publish an initial generation so the next publication has a backup.
    stage_sanitized_artifacts(
        source,
        destination,
        metadata(),
    )

    (source / "commit.txt").write_text(
        "b" * 40 + "\n",
        encoding="utf-8",
    )

    def fail_backup_cleanup(_backup: Path) -> None:
        raise OSError("simulated backup cleanup failure")

    monkeypatch.setattr(
        artifact_staging,
        "_cleanup_backup",
        fail_backup_cleanup,
    )

    with caplog.at_level("WARNING"):
        staged = stage_sanitized_artifacts(
            source,
            destination,
            metadata(),
        )

    assert staged == destination
    assert (destination / "commit.txt").read_text(
        encoding="utf-8"
    ) == "b" * 40 + "\n"

    # Publication succeeded, but the old generation remains for cleanup.
    backups = [
        path
        for path in destination.parent.iterdir()
        if path != destination and path.is_dir()
    ]

    assert backups
    assert any(
        "backup" in record.message.lower()
        for record in caplog.records
    )


def test_staging_returns_resolved_destination(
    tmp_path: Path,
):
    source = tmp_path / "source"
    write_source(source)

    destination = (
        tmp_path / "bundle" / "temporary" / ".." / "artifacts"
    )

    staged = stage_sanitized_artifacts(
        source,
        destination,
        metadata(),
    )

    assert staged == destination.resolve()
    assert staged.is_dir()


def test_failed_publication_restores_previous_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    source = tmp_path / "source"
    write_source(source)

    destination = tmp_path / "bundle" / "artifacts"

    # Publish the original generation.
    stage_sanitized_artifacts(
        source,
        destination,
        metadata(),
    )

    original_contents = {
        name: (destination / name).read_bytes()
        for name in REQUIRED_ARTIFACTS
    }

    # Change the source so the replacement is distinguishable.
    (source / "commit.txt").write_text(
        "b" * 40 + "\n",
        encoding="utf-8",
    )

    original_replace = os.replace
    destination_replace_calls = 0

    def fail_new_generation_once(src, dst):
        nonlocal destination_replace_calls

        if Path(dst) == destination:
            destination_replace_calls += 1

            # Fail the new-generation publication, but allow restoration
            # of the original backup on the subsequent call.
            if destination_replace_calls == 1:
                raise OSError("simulated generation publication failure")

        return original_replace(src, dst)

    monkeypatch.setattr(
        artifact_staging.os,
        "replace",
        fail_new_generation_once,
    )

    with pytest.raises(
        ArtifactSanitizationError,
        match="Unable to publish the sanitized staging generation",
    ):
        stage_sanitized_artifacts(
            source,
            destination,
            metadata(),
        )

    # The first destination replacement failed; the second restored backup.
    assert destination_replace_calls == 2

    # The original generation is intact.
    assert destination.is_dir()

    for name, expected_content in original_contents.items():
        assert (destination / name).read_bytes() == expected_content

    # No temporary generation or backup directories remain.
    assert list(destination.parent.iterdir()) == [destination]
