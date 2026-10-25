
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from evidence_engine.agents.signing import SigningAgent
from evidence_engine.canonical import canonical_json_bytes
from evidence_engine.signing import KEY_ID


def write_valid_manifest(path: Path) -> None:
    names = ("plan.json", "state.json", "commit.txt", "version.txt")

    manifest = {
        "schema_version": "1.1",
        "hash_algorithm": "SHA-256",
        "signature_algorithm": "RSA-PSS-SHA256",
        "key_id": KEY_ID,
        "provenance": {
            "repository": "example-org/example-repo",
            "commit_sha": "a" * 40,
            "workflow_run_id": "12345",
            "terraform_version": "1.0.0",
            "provider_lock_sha256": "",
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

    path.write_bytes(canonical_json_bytes(manifest))


def test_signing_agent_rejects_missing_manifest(tmp_path: Path):
    agent = SigningAgent(manifest_path=tmp_path / "missing.json")

    result = agent.run()

    assert result.success is False
    assert result.error == "manifest-read-failed"


def test_signing_agent_rejects_missing_private_key(tmp_path: Path):
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}", encoding="utf-8")

    agent = SigningAgent(
        manifest_path=manifest,
        signing_mode="local",
        private_key=None,
    )

    result = agent.run()

    assert result.success is False
    assert result.error == "local-signing-missing-key"


def test_signing_agent_rejects_missing_kms_key_id(tmp_path: Path):
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}", encoding="utf-8")

    agent = SigningAgent(
        manifest_path=manifest,
        signing_mode="kms",
        kms_key_id=None,
    )

    result = agent.run()

    assert result.success is False
    assert result.error == "kms-signing-missing-key-id"


def test_signing_agent_local_success(tmp_path: Path):
    manifest = tmp_path / "manifest.json"
    write_valid_manifest(manifest)

    # Generate a real RSA private key.
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    private_key = tmp_path / "key.pem"
    private_key.write_bytes(pem)

    agent = SigningAgent(
        manifest_path=manifest,
        signing_mode="local",
        private_key=private_key,
    )

    result = agent.run()

    assert result.success is True
    assert result.error is None
    assert result.data["key_id"] == KEY_ID
    assert result.data["mode"] == "local"
    assert isinstance(result.data["signature"], bytes)


def test_signing_agent_kms_success(tmp_path: Path, monkeypatch):
    manifest = tmp_path / "manifest.json"
    write_valid_manifest(manifest)

    # Fake KMS client and signing operation.
    def fake_create_client(region):
        return "client"

    def fake_sign_bytes(client, key_id, data):
        return b"sig"

    monkeypatch.setattr(
        "evidence_engine.kms_signing.create_kms_client",
        fake_create_client,
    )
    monkeypatch.setattr(
        "evidence_engine.kms_signing.sign_bytes",
        fake_sign_bytes,
    )

    agent = SigningAgent(
        manifest_path=manifest,
        signing_mode="kms",
        kms_key_id="kms-key",
    )

    result = agent.run()

    assert result.success is True
    assert result.error is None
    assert result.data["key_id"] == "kms-key"
    assert result.data["mode"] == "kms"
    assert result.data["signature"] == b"sig"


def test_signing_agent_rejects_noncanonical_manifest(tmp_path: Path):
    manifest = tmp_path / "manifest.json"
    write_valid_manifest(manifest)

    # The trailing newline makes the bytes noncanonical.
    manifest.write_bytes(manifest.read_bytes() + b"\n")

    agent = SigningAgent(
        manifest_path=manifest,
        signing_mode="local",
        private_key=tmp_path / "key.pem",
    )

    result = agent.run()

    assert result.success is False
    assert result.error == "manifest-not-canonical"


def test_signing_agent_rejects_schema_invalid_manifest(tmp_path: Path):
    manifest = tmp_path / "manifest.json"
    manifest.write_bytes(canonical_json_bytes({}))

    agent = SigningAgent(
        manifest_path=manifest,
        signing_mode="local",
        private_key=tmp_path / "key.pem",
    )

    result = agent.run()

    assert result.success is False
    assert result.error == "manifest-schema-invalid"


def test_signing_agent_rejects_invalid_json(tmp_path: Path):
    manifest = tmp_path / "manifest.json"
    manifest.write_bytes(b'{"key_id":')

    agent = SigningAgent(
        manifest_path=manifest,
        signing_mode="local",
        private_key=tmp_path / "key.pem",
    )

    result = agent.run()

    assert result.success is False
    assert result.error == "manifest-json-invalid"
