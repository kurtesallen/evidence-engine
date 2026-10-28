import json
import hashlib

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils

from evidence_engine.kms_signing import sign_bytes
from evidence_engine.manifest import write_manifest
from evidence_engine.signing import KEY_ID
from evidence_engine.verify import verify_bundle


TEST_KMS_KEY_ID = "test-kms-key"


class FakeKMSClient:
    """Simulate the KMS Sign API using real RSA-PSS cryptography."""

    def __init__(self, private_key):
        self.private_key = private_key

    def sign(self, *, KeyId, Message, MessageType, SigningAlgorithm):
        assert KeyId == TEST_KMS_KEY_ID
        assert MessageType == "DIGEST"
        assert SigningAlgorithm == "RSASSA_PSS_SHA_256"
        assert len(Message) == hashlib.sha256().digest_size

        signature = self.private_key.sign(
            Message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=hashes.SHA256().digest_size,
            ),
            utils.Prehashed(hashes.SHA256()),
        )
        return {"Signature": signature}


@pytest.fixture
def kms_signed_bundle(tmp_path):
    project = tmp_path / "project"
    artifacts = project / "artifacts"
    output = project / "bundle"
    config = project / "config"
    keys = project / "keys"

    for directory in (artifacts, output, config, keys):
        directory.mkdir(parents=True)

    for name, content in {
        "plan.json": b'{"resource_changes":[]}\n',
        "state.json": b'{"version":4}\n',
        "commit.txt": b"test-commit\n",
        "version.txt": b"terraform-test-version\n",
    }.items():
        (artifacts / name).write_bytes(content)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key_path = keys / "public.pem"
    public_key_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    registry_path = config / "trust_registry.json"
    registry_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "keys": [
                    {
                        "key_id": TEST_KMS_KEY_ID,
                        "public_key": "../keys/public.pem",
                        "status": "active",
                        "allowed_sources": ["local-claimed"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    provenance = {
        "repository": "test/repository",
        "commit_sha": "a" * 40,
        "workflow_run_id": "local-test",
        "terraform_version": "test",
        "provider_lock_sha256": "",
        "source": "local-claimed",
    }

    manifest_path = output / "manifest.json"
    signature_path = output / "manifest.sig"

    write_manifest(
        artifacts,
        manifest_path,
        provenance,
        TEST_KMS_KEY_ID,
    )

    signature = sign_bytes(
        FakeKMSClient(private_key),
        TEST_KMS_KEY_ID,
        manifest_path.read_bytes(),
    )
    signature_path.write_bytes(signature)

    return {
        "artifacts": artifacts,
        "manifest": manifest_path,
        "signature": signature_path,
        "registry": registry_path,
    }


def verify(bundle):
    return verify_bundle(
        bundle["artifacts"],
        bundle["manifest"],
        bundle["signature"],
        bundle["registry"],
        TEST_KMS_KEY_ID,
    )


def test_kms_signature_verifies_through_trust_registry(kms_signed_bundle):
    assert verify(kms_signed_bundle) is True


def test_kms_signature_rejects_modified_artifact(kms_signed_bundle):
    (kms_signed_bundle["artifacts"] / "plan.json").write_bytes(
        b'{"tampered":true}\n'
    )

    assert verify(kms_signed_bundle) is False


def test_kms_signature_rejects_modified_manifest(kms_signed_bundle):
    manifest_path = kms_signed_bundle["manifest"]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["provenance"]["repository"] = "attacker/changed"
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )

    assert verify(kms_signed_bundle) is False


def test_kms_signature_rejects_modified_signature(kms_signed_bundle):
    signature_path = kms_signed_bundle["signature"]
    signature = bytearray(signature_path.read_bytes())
    signature[0] ^= 0x01
    signature_path.write_bytes(bytes(signature))

    assert verify(kms_signed_bundle) is False


def test_kms_signature_rejects_unauthorized_source(kms_signed_bundle):
    registry_path = kms_signed_bundle["registry"]
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    registry["keys"][0]["allowed_sources"] = ["github-actions-claimed"]
    registry_path.write_text(json.dumps(registry), encoding="utf-8")

    assert verify(kms_signed_bundle) is False
