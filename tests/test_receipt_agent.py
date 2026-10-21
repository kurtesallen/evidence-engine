import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from evidence_engine.canonical import canonical_json_bytes
from evidence_engine.manifest import write_manifest
from evidence_engine.receipt import ReceiptAgent
from evidence_engine.signing import sign_bytes


ARTIFACT_CONTENTS = {
    "plan.json": b'{"resource_changes":[]}\n',
    "state.json": b'{"version":4}\n',
    "commit.txt": b"test-commit\n",
    "version.txt": b"terraform-test-version\n",
}


def make_agent(tmp_path: Path, source: str = "local-claimed"):
    artifacts_root = tmp_path / "artifacts"
    artifacts_root.mkdir(parents=True, exist_ok=True)

    for name, content in ARTIFACT_CONTENTS.items():
        (artifacts_root / name).write_bytes(content)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    private_key_path = tmp_path / "private.pem"
    private_key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    public_key_path = tmp_path / "public.pem"
    public_key_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    key_id = "test-key"
    manifest_source = "local-claimed"

    provenance = {
        "repository": "example/repo",
        "commit_sha": "a" * 40,
        "workflow_run_id": "none",
        "terraform_version": "1.9.0",
        "provider_lock_sha256": "b" * 64,
        "source": manifest_source,
    }

    manifest_path = tmp_path / "manifest.json"
    signature_path = tmp_path / "manifest.sig"
    trust_registry_path = tmp_path / "trust.json"

    write_manifest(
        artifacts_root,
        manifest_path,
        provenance,
        key_id,
    )

    manifest_bytes = manifest_path.read_bytes()
    signature_path.write_bytes(
        sign_bytes(private_key_path, manifest_bytes)
    )

    trust_registry_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "keys": [
                    {
                        "key_id": key_id,
                        "public_key": "public.pem",
                        "status": "active",
                        "allowed_sources": [manifest_source],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    return ReceiptAgent(
        artifacts_root=artifacts_root,
        manifest_path=manifest_path,
        signature_path=signature_path,
        trust_registry_path=trust_registry_path,
        source=source,
    )


def test_receipt_contains_consumer_and_policy_metadata(tmp_path: Path):
    result = make_agent(tmp_path).run()

    assert result.success is True
    assert result.data is not None

    receipt = result.data["receipt"]
    assert receipt["source"] == "local-claimed"
    assert receipt["signature_key_id"] == "test-key"
    assert set(receipt["artifacts"]) == {
        "plan.json",
        "state.json",
        "commit.txt",
        "version.txt",
    }
    assert result.data["signature"] != b""
    assert result.data["manifest_bytes"] == (
        tmp_path / "manifest.json"
    ).read_bytes()


def test_receipt_rejects_source_mismatch(tmp_path: Path):
    result = make_agent(
        tmp_path,
        source="github-actions-claimed",
    ).run()

    assert result.success is False
    assert result.error == "source-mismatch"


def test_receipt_rejects_missing_manifest(tmp_path: Path):
    agent = ReceiptAgent(
        artifacts_root=tmp_path / "artifacts",
        manifest_path=tmp_path / "missing.json",
        signature_path=tmp_path / "manifest.sig",
        trust_registry_path=tmp_path / "trust.json",
    )

    result = agent.run()

    assert result.success is False
    assert result.error == "manifest-read-failed"


def test_receipt_rejects_noncanonical_manifest(tmp_path: Path):
    agent = make_agent(tmp_path)
    agent._manifest_path.write_bytes(
        canonical_json_bytes(
            json.loads(agent._manifest_path.read_text(encoding="utf-8"))
        )
        + b"\n"
    )

    result = agent.run()

    assert result.success is False
    assert result.error == "manifest-not-canonical"
