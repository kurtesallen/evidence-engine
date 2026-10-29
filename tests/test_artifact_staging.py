"""Tests for staging sanitized Terraform evidence as a separate artifact set."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from evidence_engine.agents.artifact_staging import stage_sanitized_artifacts
from evidence_engine.sanitization import ArtifactSanitizationError
from evidence_engine.schema import REQUIRED_ARTIFACTS

RULE_VERSION = "1.1"


def metadata(*, plan: str = "sanitized", state: str = "sanitized"):
    return {
        "plan.json": {"representation": plan, "sanitization_rule_version": RULE_VERSION if plan == "sanitized" else None},
        "state.json": {"representation": state, "sanitization_rule_version": RULE_VERSION if state == "sanitized" else None},
        "commit.txt": {"representation": "raw", "sanitization_rule_version": None},
        "version.txt": {"representation": "raw", "sanitization_rule_version": None},
    }


def write_source(root: Path) -> dict[str, bytes]:
    root.mkdir(parents=True)
    plan = {
        "format_version": "1.0",
        "terraform_version": "1.9.0",
        "planned_values": {"root_module": {"resources": []}},
        "resource_changes": [{
            "address": "example.db",
            "change": {
                "actions": ["update"],
                "before": {"opaque": "PLAN-CANARY-SECRET"},
                "before_sensitive": {"opaque": True},
                "after": {"opaque": "PLAN-CANARY-SECRET"},
                "after_sensitive": {"opaque": True},
            },
        }],
    }
    state = {
        "format_version": "1.0",
        "terraform_version": "1.9.0",
        "values": {"root_module": {"resources": [{
            "address": "example.db",
            "mode": "managed",
            "type": "example",
            "name": "db",
            "values": {"opaque": "STATE-CANARY-SECRET"},
            "sensitive_values": {"opaque": True},
        }]}},
    }
    (root / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
    (root / "state.json").write_text(json.dumps(state), encoding="utf-8")
    (root / "commit.txt").write_text("a" * 40 + "\n", encoding="utf-8")
    (root / "version.txt").write_text("terraform 1.9.0\n", encoding="utf-8")
    assert {p.name for p in root.iterdir()} == set(REQUIRED_ARTIFACTS)
    return {p.name: p.read_bytes() for p in root.iterdir()}


def test_staging_sanitizes_plan_and_state_without_mutating_source(tmp_path: Path):
    source = tmp_path / "source"
    originals = write_source(source)
    destination = tmp_path / "bundle" / "artifacts"

    staged = stage_sanitized_artifacts(source, destination, metadata())

    assert staged == destination
    assert (source / "plan.json").read_bytes() == originals["plan.json"]
    assert (source / "state.json").read_bytes() == originals["state.json"]
    plan_bytes = (staged / "plan.json").read_bytes()
    state_bytes = (staged / "state.json").read_bytes()
    assert b"PLAN-CANARY-SECRET" not in plan_bytes
    assert b"STATE-CANARY-SECRET" not in state_bytes
    assert json.loads(plan_bytes)["resource_changes"][0]["change"]["after"]["opaque"] == "[REDACTED]"
    assert json.loads(state_bytes)["values"]["root_module"]["resources"][0]["values"]["opaque"] == "[REDACTED]"
    assert (staged / "commit.txt").read_bytes() == originals["commit.txt"]
    assert (staged / "version.txt").read_bytes() == originals["version.txt"]


def test_rejects_only_one_terraform_file_marked_sanitized(tmp_path: Path):
    source = tmp_path / "source"
    write_source(source)
    bad = metadata(state="raw")
    with pytest.raises(ArtifactSanitizationError, match="Both plan.json and state.json"):
        stage_sanitized_artifacts(source, tmp_path / "bundle" / "artifacts", bad)


def test_rejects_metadata_rule_version_mismatch(tmp_path: Path):
    source = tmp_path / "source"
    write_source(source)
    bad = metadata()
    bad["plan.json"]["sanitization_rule_version"] = "99.0"
    with pytest.raises(ArtifactSanitizationError, match="rule version"):
        stage_sanitized_artifacts(source, tmp_path / "bundle" / "artifacts", bad)


def test_rejects_invalid_terraform_json_before_creating_staging_directory(tmp_path: Path):
    source = tmp_path / "source"
    write_source(source)
    (source / "plan.json").write_text("not json", encoding="utf-8")
    destination = tmp_path / "bundle" / "artifacts"
    with pytest.raises(ArtifactSanitizationError):
        stage_sanitized_artifacts(source, destination, metadata())
    assert not destination.exists()


def test_rejects_extra_source_file(tmp_path: Path):
    source = tmp_path / "source"
    write_source(source)
    (source / "unexpected.txt").write_text("extra", encoding="utf-8")
    with pytest.raises(ArtifactSanitizationError, match="Source artifact set mismatch"):
        stage_sanitized_artifacts(source, tmp_path / "bundle" / "artifacts", metadata())


def test_rejects_unsafe_existing_destination_entry(tmp_path: Path):
    source = tmp_path / "source"
    write_source(source)
    destination = tmp_path / "bundle" / "artifacts"
    destination.mkdir(parents=True)
    (destination / "unexpected.txt").write_text("do not overwrite", encoding="utf-8")
    with pytest.raises(ArtifactSanitizationError, match="unexpected entries"):
        stage_sanitized_artifacts(source, destination, metadata())


def test_rejects_overlapping_source_and_destination(tmp_path: Path):
    source = tmp_path / "source"
    write_source(source)
    with pytest.raises(ArtifactSanitizationError, match="must not overlap"):
        stage_sanitized_artifacts(source, source / "staged", metadata())
