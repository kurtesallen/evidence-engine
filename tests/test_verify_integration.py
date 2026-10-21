import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from evidence_engine.canonical import canonical_json_bytes, parse_json_strict
from evidence_engine.manifest import write_manifest
from evidence_engine.signing import KEY_ID, sign_bytes
from evidence_engine.verify import verify_bundle


@pytest.fixture
def signed_bundle(tmp_path):
    project = tmp_path / "project"
    artifacts = project / "artifacts"
    output = project / "bundle"
    config = project / "config"
    keys = project / "keys"

    for directory in (artifacts, output, config, keys):
        directory.mkdir(parents=True)

    # The manifest schema requires exactly these four artifacts.
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
    private_key_path = keys / "private.pem"
    private_key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    public_key_path = keys / "public.pem"
    public_key_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    trust_registry = config / "trust_registry.json"
    trust_registry.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "keys": [
                    {
                        "key_id": KEY_ID,
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

    write_manifest(artifacts, manifest_path, provenance, KEY_ID)
    manifest_bytes = manifest_path.read_bytes()
    signature_path.write_bytes(sign_bytes(private_key_path, manifest_bytes))

    return {
        "artifacts": artifacts,
        "manifest": manifest_path,
        "signature": signature_path,
        "trust_registry": trust_registry,
        "key_id": KEY_ID,
    }


def verify(bundle):
    return verify_bundle(
        bundle["artifacts"],
        bundle["manifest"],
        bundle["signature"],
        bundle["trust_registry"],
        bundle["key_id"],
    )


def test_real_signature_and_trusted_key_verify(signed_bundle):
    assert verify(signed_bundle) is True


def test_modified_artifact_is_rejected(signed_bundle):
    (signed_bundle["artifacts"] / "plan.json").write_bytes(b'{"tampered":true}\n')

    assert verify(signed_bundle) is False


def test_modified_manifest_is_rejected(signed_bundle):
    manifest_path = signed_bundle["manifest"]
    manifest = parse_json_strict(manifest_path.read_bytes())
    manifest["provenance"]["repository"] = "attacker/changed"
    manifest_path.write_bytes(canonical_json_bytes(manifest))

    assert verify(signed_bundle) is False


@pytest.mark.parametrize(
    ("status", "allowed_sources"),
    [
        ("revoked", ["local-claimed"]),
        ("retired", ["local-claimed"]),
        ("active", ["github-actions-claimed"]),
    ],
)
def test_inactive_or_unauthorized_trust_entry_is_rejected(
    signed_bundle,
    status,
    allowed_sources,
):
    registry_path = signed_bundle["trust_registry"]
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    registry["keys"][0]["status"] = status
    registry["keys"][0]["allowed_sources"] = allowed_sources
    registry_path.write_text(json.dumps(registry), encoding="utf-8")

    assert verify(signed_bundle) is False
