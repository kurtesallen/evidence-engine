from pathlib import Path
import json
import pytest

from evidence_engine.agents.integrity import IntegrityAgent
from evidence_engine.policy import PolicyEngine
from evidence_engine.manifest import sha256_file
from evidence_engine.canonical import canonical_json_bytes


# --- Helper: schema-valid manifest writer ------------------------------------


def write_manifest(path: Path, artifacts):
    provenance = {
        "source": "local-claimed",
        "workflow_run_id": "none",
        "repository": "example/repo",
        "commit_sha": "a" * 40,
        "terraform_version": "1.9.0",
        "provider_lock_sha256": "b" * 64,
    }

    manifest = {
        "schema_version": "1.1",
        "hash_algorithm": "SHA-256",
        "signature_algorithm": "RSA-PSS-SHA256",
        "key_id": "test-key",
        "provenance": provenance,
        "artifacts": artifacts,
    }

    path.write_bytes(canonical_json_bytes(manifest))
    return manifest


# --- Required artifacts for schema -------------------------------------------

def create_required_artifacts(root: Path):
    (root / "plan.json").write_text("{}", encoding="utf-8")
    (root / "state.json").write_text("{}", encoding="utf-8")
    (root / "commit.txt").write_text("commit", encoding="utf-8")
    (root / "version.txt").write_text("version", encoding="utf-8")



def required_artifact_entries(root: Path):
    return [
        {
            "name": name,
            "size_bytes": (root / name).stat().st_size,
            "representation": "raw",
            "sanitization_rule_version": None,
            "sha256": sha256_file(root / name),
        }
        for name in ("plan.json", "state.json", "commit.txt", "version.txt")
    ]


# --- Tests --------------------------------------------------------------------

def test_integrity_agent_rejects_missing_manifest(tmp_path: Path):
    root = tmp_path / "artifacts"
    root.mkdir()
    agent = IntegrityAgent(artifacts_root=root, manifest_path=tmp_path / "missing.json")

    result = agent.run()
    assert result.success is False
    assert result.error == "manifest-read-failed"


def test_integrity_agent_rejects_malformed_json(tmp_path: Path):
    root = tmp_path / "artifacts"
    root.mkdir()
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{not valid json}", encoding="utf-8")

    agent = IntegrityAgent(root, manifest)
    result = agent.run()

    assert result.success is False
    assert result.error == "manifest-json-invalid"


def test_integrity_agent_rejects_noncanonical_json(tmp_path: Path):
    root = tmp_path / "artifacts"
    root.mkdir()

    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"a": 1}, indent=2), encoding="utf-8")

    agent = IntegrityAgent(root, manifest)
    result = agent.run()

    assert result.success is False
    assert result.error == "manifest-not-canonical"


def test_integrity_agent_rejects_schema_violation(tmp_path: Path):
    root = tmp_path / "artifacts"
    root.mkdir()

    manifest = tmp_path / "manifest.json"
    manifest.write_bytes(canonical_json_bytes({"version": "1.1"}))

    agent = IntegrityAgent(root, manifest)
    result = agent.run()

    assert result.success is False
    assert result.error == "manifest-schema-invalid"


def test_integrity_agent_rejects_missing_artifacts(tmp_path: Path):
    root = tmp_path / "artifacts"
    root.mkdir()
    create_required_artifacts(root)

    manifest = tmp_path / "manifest.json"

    # Manifest lists only required artifacts, but directory contains extra file
    write_manifest(
        manifest,
        artifacts=required_artifact_entries(root)
    )

    # Add unexpected file
    (root / "unexpected.txt").write_text("extra", encoding="utf-8")

    agent = IntegrityAgent(root, manifest)
    result = agent.run()

    assert result.success is False
    assert result.error == "artifact-set-mismatch"


def test_integrity_agent_rejects_directories(tmp_path: Path):
    root = tmp_path / "artifacts"
    root.mkdir()
    create_required_artifacts(root)

    (root / "subdir").mkdir()

    manifest = tmp_path / "manifest.json"
    write_manifest(manifest, artifacts=required_artifact_entries(root))

    agent = IntegrityAgent(root, manifest)
    result = agent.run()

    assert result.success is False
    assert result.error == "non-file-entry-rejected"


def test_integrity_agent_validates_size_and_digest(tmp_path: Path):
    root = tmp_path / "artifacts"
    root.mkdir()
    create_required_artifacts(root)

    manifest = tmp_path / "manifest.json"
    write_manifest(manifest, artifacts=required_artifact_entries(root))

    agent = IntegrityAgent(root, manifest)
    result = agent.run()

    assert result.success is True
    assert result.error is None
    assert "manifest" in result.data


def test_integrity_agent_policy_denial(tmp_path: Path):
    class DenyPolicy(PolicyEngine):
        def evaluate_integrity(self, manifest):
            from evidence_engine.policy import PolicyDecision
            return PolicyDecision(
                allowed=False,
                reason="integrity-denied",
                details={"cause": "test"},
            )

    root = tmp_path / "artifacts"
    root.mkdir()
    create_required_artifacts(root)

    manifest = tmp_path / "manifest.json"
    write_manifest(manifest, artifacts=required_artifact_entries(root))

    agent = IntegrityAgent(root, manifest, policy=DenyPolicy())
    result = agent.run()

    assert result.success is False
    assert result.error == "integrity-denied"
