from pathlib import Path

import pytest

from evidence_engine.agents.consumer import ConsumerAgent
from evidence_engine.canonical import canonical_json_bytes


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


@pytest.fixture
def consumer_setup(tmp_path, monkeypatch):
    root = tmp_path / "artifacts"
    root.mkdir()
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_bytes(canonical_json_bytes(valid_manifest()))

    receipt = {
        "artifacts_root": str(root),
        "manifest_path": str(manifest_path),
        "signature_path": str(tmp_path / "manifest.sig"),
        "trust_registry_path": str(tmp_path / "trust.json"),
        "source": "local-claimed",
        "artifacts": [
            "plan.json", "state.json", "commit.txt", "version.txt"
        ],
        "signature_key_id": "test-key",
    }

    calls = []

    def fake_verify_bundle(*args):
        calls.append(args)
        return True

    monkeypatch.setattr(
        "evidence_engine.agents.consumer.verify_bundle",
        fake_verify_bundle,
    )

    return root, receipt, calls


def test_consumer_requires_expected_key_id(consumer_setup):
    root, receipt, calls = consumer_setup
    result = ConsumerAgent(root).run(receipt)

    assert result.success is False
    assert result.error == "expected-key-id-missing"
    assert calls == []


def test_consumer_verifies_matching_receipt(consumer_setup):
    root, receipt, calls = consumer_setup
    result = ConsumerAgent(
        root,
        expected_source="local-claimed",
        expected_key_id="test-key",
    ).run(receipt)

    assert result.success is True
    assert result.data == {"verified": True, "key_id": "test-key"}
    assert len(calls) == 1


@pytest.mark.parametrize(
    ("field", "value", "expected_error"),
    [
        ("source", "github-actions-claimed", "receipt-source-mismatch"),
        ("signature_key_id", "other-key", "receipt-key-id-mismatch"),
        ("artifacts", ["plan.json"], "receipt-artifacts-mismatch"),
    ],
)
def test_consumer_rejects_receipt_metadata_mismatch(
    consumer_setup, field, value, expected_error
):
    root, receipt, calls = consumer_setup
    receipt[field] = value

    result = ConsumerAgent(
        root, expected_key_id="test-key"
    ).run(receipt)

    assert result.success is False
    assert result.error == expected_error
    assert calls == []


def test_consumer_rejects_key_id_mismatch(consumer_setup):
    root, receipt, calls = consumer_setup
    result = ConsumerAgent(
        root, expected_key_id="different-key"
    ).run(receipt)

    assert result.success is False
    assert result.error == "key-id-mismatch"
    assert calls == []


def test_consumer_reports_failed_cryptographic_verification(
    consumer_setup, monkeypatch
):
    root, receipt, calls = consumer_setup
    monkeypatch.setattr(
        "evidence_engine.agents.consumer.verify_bundle",
        lambda *args: False,
    )

    result = ConsumerAgent(
        root, expected_key_id="test-key"
    ).run(receipt)

    assert result.success is False
    assert result.error == "verification-failed"


def test_consumer_rejects_artifact_root_mismatch(consumer_setup, tmp_path):
    root, receipt, calls = consumer_setup
    receipt["artifacts_root"] = str(tmp_path / "different-root")

    result = ConsumerAgent(
        root, expected_key_id="test-key"
    ).run(receipt)

    assert result.success is False
    assert result.error == "receipt-artifacts-root-mismatch"
    assert calls == []
