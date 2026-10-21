import json
from pathlib import Path

from evidence_engine.canonical import canonical_json_bytes
from evidence_engine.receipt import ReceiptAgent


def valid_manifest():
    names = ["plan.json", "state.json", "commit.txt", "version.txt"]
    return {
        "schema_version": "1.1",
        "hash_algorithm": "SHA-256",
        "signature_algorithm": "RSA-PSS-SHA256",
        "key_id": "test-key",
        "provenance": {
            "repository": "example/repo",
            "commit_sha": "a" * 40,
            "workflow_run_id": "none",
            "terraform_version": "1.9.0",
            "provider_lock_sha256": "b" * 64,
            "source": "local-claimed",
        },
        "artifacts": [
            {
                "name": name,
                "size_bytes": 0,
                "representation": "raw",
                "sanitization_rule_version": None,
                "sha256": "0" * 64,
            }
            for name in names
        ],
    }


def make_agent(tmp_path: Path, source="local-claimed"):
    manifest_path = tmp_path / "manifest.json"
    signature_path = tmp_path / "manifest.sig"
    manifest_path.write_bytes(canonical_json_bytes(valid_manifest()))
    signature_path.write_bytes(b"signature-placeholder")

    return ReceiptAgent(
        artifacts_root=tmp_path / "artifacts",
        manifest_path=manifest_path,
        signature_path=signature_path,
        trust_registry_path=tmp_path / "trust.json",
        source=source,
    )


def test_receipt_contains_consumer_and_policy_metadata(tmp_path):
    result = make_agent(tmp_path).run()

    assert result.success is True
    assert result.data is not None

    receipt = result.data["receipt"]
    assert receipt["source"] == "local-claimed"
    assert receipt["signature_key_id"] == "test-key"
    assert receipt["artifacts"] == [
        "plan.json", "state.json", "commit.txt", "version.txt"
    ]
    assert result.data["signature"] == b"signature-placeholder"


def test_receipt_rejects_source_mismatch(tmp_path):
    result = make_agent(tmp_path, source="github-actions-claimed").run()

    assert result.success is False
    assert result.error == "source-mismatch"


def test_receipt_rejects_missing_manifest(tmp_path):
    agent = ReceiptAgent(
        artifacts_root=tmp_path / "artifacts",
        manifest_path=tmp_path / "missing.json",
        signature_path=tmp_path / "manifest.sig",
        trust_registry_path=tmp_path / "trust.json",
    )

    result = agent.run()

    assert result.success is False
    assert result.error == "manifest-read-failed"


def test_receipt_rejects_noncanonical_manifest(tmp_path):
    manifest_path = tmp_path / "manifest.json"
    signature_path = tmp_path / "manifest.sig"
    manifest_path.write_bytes(
        canonical_json_bytes(valid_manifest()) + b"\n"
    )
    signature_path.write_bytes(b"signature-placeholder")

    agent = ReceiptAgent(
        artifacts_root=tmp_path / "artifacts",
        manifest_path=manifest_path,
        signature_path=signature_path,
        trust_registry_path=tmp_path / "trust.json",
    )

    result = agent.run()

    assert result.success is False
    assert result.error == "manifest-not-canonical"
