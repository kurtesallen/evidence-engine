"""Focused tests for explicit manifest artifact metadata declarations."""

import json

import pytest

from evidence_engine.collect import provenance_for
from evidence_engine.manifest import build_manifest, write_manifest
from evidence_engine.signing import KEY_ID


ARTIFACT_CONTENTS = {
    "plan.json": '{"resource_changes": []}\n',
    "state.json": '{"resources": []}\n',
    "commit.txt": "a" * 40 + "\n",
    "version.txt": "Terraform v1.10.0\n",
}


def make_artifacts(tmp_path):
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    for name, content in ARTIFACT_CONTENTS.items():
        (artifact_dir / name).write_text(content, encoding="utf-8")
    return artifact_dir


def valid_metadata():
    return {
        "plan.json": {
            "representation": "raw",
            "sanitization_rule_version": None,
        },
        "state.json": {
            "representation": "sanitized",
            "sanitization_rule_version": "test-redactor-v1",
        },
        "commit.txt": {
            "representation": "sample",
            "sanitization_rule_version": None,
        },
        "version.txt": {
            "representation": "sample",
            "sanitization_rule_version": None,
        },
    }


def build(artifact_dir, tmp_path, metadata):
    return build_manifest(
        artifact_dir=artifact_dir,
        provenance=provenance_for(tmp_path),
        key_id=KEY_ID,
        artifact_metadata=metadata,
    )


def test_manifest_preserves_explicit_artifact_metadata(tmp_path):
    artifact_dir = make_artifacts(tmp_path)

    manifest = build(artifact_dir, tmp_path, valid_metadata())
    artifacts = {item["name"]: item for item in manifest["artifacts"]}

    assert artifacts["plan.json"]["representation"] == "raw"
    assert artifacts["state.json"]["representation"] == "sanitized"
    assert (
        artifacts["state.json"]["sanitization_rule_version"]
        == "test-redactor-v1"
    )
    assert artifacts["commit.txt"]["representation"] == "sample"
    assert artifacts["version.txt"]["representation"] == "sample"


def test_manifest_rejects_missing_metadata_entry(tmp_path):
    artifact_dir = make_artifacts(tmp_path)
    metadata = valid_metadata()
    del metadata["state.json"]

    with pytest.raises(ValueError, match="match artifact files exactly"):
        build(artifact_dir, tmp_path, metadata)


def test_manifest_rejects_unexpected_metadata_entry(tmp_path):
    artifact_dir = make_artifacts(tmp_path)
    metadata = valid_metadata()
    metadata["extra.txt"] = {
        "representation": "sample",
        "sanitization_rule_version": None,
    }

    with pytest.raises(ValueError, match="match artifact files exactly"):
        build(artifact_dir, tmp_path, metadata)


def test_manifest_rejects_non_mapping_artifact_metadata(tmp_path):
    artifact_dir = make_artifacts(tmp_path)
    metadata = valid_metadata()
    metadata["plan.json"] = "raw"

    with pytest.raises(ValueError, match="must be a mapping"):
        build(artifact_dir, tmp_path, metadata)


def test_manifest_rejects_unknown_metadata_field(tmp_path):
    artifact_dir = make_artifacts(tmp_path)
    metadata = valid_metadata()
    metadata["plan.json"]["note"] = "unexpected"

    with pytest.raises(ValueError, match="must contain exactly"):
        build(artifact_dir, tmp_path, metadata)


@pytest.mark.parametrize("representation", ["private", 7, None])
def test_manifest_rejects_invalid_representation(tmp_path, representation):
    artifact_dir = make_artifacts(tmp_path)
    metadata = valid_metadata()
    metadata["plan.json"]["representation"] = representation

    with pytest.raises(ValueError, match="Invalid representation"):
        build(artifact_dir, tmp_path, metadata)


@pytest.mark.parametrize("rule_version", [None, "", "   ", 7])
def test_manifest_rejects_sanitized_artifact_without_valid_rule_version(
    tmp_path, rule_version
):
    artifact_dir = make_artifacts(tmp_path)
    metadata = valid_metadata()
    metadata["state.json"]["sanitization_rule_version"] = rule_version

    with pytest.raises(ValueError, match="requires a non-empty"):
        build(artifact_dir, tmp_path, metadata)


@pytest.mark.parametrize("representation", ["raw", "sample"])
def test_manifest_rejects_rule_version_for_non_sanitized_artifact(
    tmp_path, representation
):
    artifact_dir = make_artifacts(tmp_path)
    metadata = valid_metadata()
    metadata["plan.json"] = {
        "representation": representation,
        "sanitization_rule_version": "should-not-be-set",
    }

    with pytest.raises(ValueError, match="must use sanitization_rule_version=None"):
        build(artifact_dir, tmp_path, metadata)


def test_write_manifest_forwards_explicit_metadata(tmp_path):
    artifact_dir = make_artifacts(tmp_path)
    destination = tmp_path / "sealed" / "manifest.json"
    metadata = valid_metadata()

    manifest = write_manifest(
        artifact_dir=artifact_dir,
        destination=destination,
        provenance=provenance_for(tmp_path),
        key_id=KEY_ID,
        artifact_metadata=metadata,
    )

    persisted = json.loads(destination.read_text(encoding="utf-8"))
    assert persisted == manifest
    assert {
        item["name"]: item["representation"]
        for item in persisted["artifacts"]
    }["state.json"] == "sanitized"
