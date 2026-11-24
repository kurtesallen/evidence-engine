
"""Integration tests for signed EvidenceEngine bundles."""

import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from evidence_engine.acceptance import InMemoryAcceptanceState
from evidence_engine.agents.consumer import ConsumerAgent
from evidence_engine.bundle_publication import (
    create_staging_generation,
    publish_generation,
    resolve_current_generation,
)
from evidence_engine.canonical import canonical_json_bytes, parse_json_strict
from evidence_engine.manifest import write_manifest
from evidence_engine.schema import REQUIRED_ARTIFACTS
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
    signature_path.write_bytes(
        sign_bytes(private_key_path, manifest_bytes)
    )

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


@pytest.mark.parametrize("version", ["2.0", "2.1", "99.0"])
def test_validly_signed_bundle_rejects_unsupported_sanitization_version(
    signed_bundle,
    version,
    capsys,
):
    """Reject experimental versions even with a valid signature."""
    manifest_path = signed_bundle["manifest"]
    signature_path = signed_bundle["signature"]

    manifest = parse_json_strict(manifest_path.read_bytes())

    for entry in manifest["artifacts"]:
        if entry["name"] in {"plan.json", "state.json"}:
            entry["representation"] = "sanitized"
            entry["sanitization_rule_version"] = version

    manifest_bytes = canonical_json_bytes(manifest)
    manifest_path.write_bytes(manifest_bytes)

    private_key_path = (
        manifest_path.parent.parent / "keys" / "private.pem"
    )

    signature_path.write_bytes(
        sign_bytes(private_key_path, manifest_bytes)
    )

    assert verify(signed_bundle) is False

    output = capsys.readouterr().out

    assert (
        "unsupported sanitization rule version" in output
        or "integrity-sanitization-rule-unsupported" in output
    )


def test_modified_artifact_is_rejected(signed_bundle):
    (signed_bundle["artifacts"] / "plan.json").write_bytes(
        b'{"tampered":true}\n'
    )

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
    registry = json.loads(
        registry_path.read_text(encoding="utf-8")
    )
    registry["keys"][0]["status"] = status
    registry["keys"][0]["allowed_sources"] = allowed_sources
    registry_path.write_text(
        json.dumps(registry),
        encoding="utf-8",
    )

    assert verify(signed_bundle) is False


def test_mismatched_legacy_terraform_representations_are_rejected(
    signed_bundle,
    capsys,
):
    manifest_path = signed_bundle["manifest"]
    manifest = parse_json_strict(manifest_path.read_bytes())

    entries = {
        entry["name"]: entry
        for entry in manifest["artifacts"]
    }

    # Schema v1.1 permits raw and sample individually, but
    # requires plan.json and state.json to use the same representation.
    entries["plan.json"]["representation"] = "raw"
    entries["state.json"]["representation"] = "sample"

    manifest_path.write_bytes(canonical_json_bytes(manifest))

    assert verify(signed_bundle) is False

    output = capsys.readouterr().out
    assert (
        "integrity-terraform-representation-mismatch"
        in output
    )


# ---------------------------------------------------------------------------
# Real-signature immutable-generation integration
# ---------------------------------------------------------------------------


def test_consumer_verifies_real_signed_published_generation(
    signed_bundle,
    tmp_path,
):
    """Verify and accept a published generation with real RSA-PSS."""
    bundle_root = tmp_path / "published-bundle"

    staged = create_staging_generation(bundle_root)
    staged.artifacts_root.mkdir()

    # Copy all four original signed artifacts into the staging generation.
    # Their bytes must remain identical to the manifest's recorded hashes.
    for name in (
        "plan.json",
        "state.json",
        "commit.txt",
        "version.txt",
    ):
        source = signed_bundle["artifacts"] / name
        destination = staged.artifacts_root / name
        destination.write_bytes(source.read_bytes())

    # Preserve the canonical manifest and RSA signature byte-for-byte.
    staged.manifest_path.write_bytes(
        signed_bundle["manifest"].read_bytes()
    )
    staged.signature_path.write_bytes(
        signed_bundle["signature"].read_bytes()
    )

    published = publish_generation(staged)

    # CURRENT must select the exact generation just published.
    assert resolve_current_generation(bundle_root) == published

    receipt = {
        "artifacts_root": str(published.artifacts_root),
        "manifest_path": str(published.manifest_path),
        "signature_path": str(published.signature_path),
        "source": "local-claimed",
        "artifacts": sorted(REQUIRED_ARTIFACTS),
        "signature_key_id": KEY_ID,
    }

    acceptance_state = InMemoryAcceptanceState()

    consumer = ConsumerAgent(
        published.artifacts_root,
        expected_source="local-claimed",
        expected_key_id=KEY_ID,
        acceptance_state=acceptance_state,
        trust_registry_path=signed_bundle["trust_registry"],
        bundle_root=bundle_root,
    )

    # No monkeypatching: this calls the real verify_bundle().
    first = consumer.run(receipt)

    assert first.success is True
    assert first.data == {
        "verified": True,
        "key_id": KEY_ID,
    }

    # Reusing the same signed manifest must be rejected as a replay.
    replay = consumer.run(receipt)

    assert replay.success is False
    assert replay.error == "bundle-replay-detected"
    assert (
        first.audit["bundle_digest"]
        == replay.audit["bundle_digest"]
    )

    # Publication must preserve the exact original artifact bytes.
    for name in (
        "plan.json",
        "state.json",
        "commit.txt",
        "version.txt",
    ):
        assert (
            published.artifacts_root / name
        ).read_bytes() == (
            signed_bundle["artifacts"] / name
        ).read_bytes()

    assert (
        published.manifest_path.read_bytes()
        == signed_bundle["manifest"].read_bytes()
    )
    assert (
        published.signature_path.read_bytes()
        == signed_bundle["signature"].read_bytes()
    )


def test_tampered_published_generation_does_not_advance_acceptance(
    signed_bundle,
    tmp_path,
):
    """Tampering must fail verification without consuming acceptance state."""
    bundle_root = tmp_path / "tampered-published-bundle"

    staged = create_staging_generation(bundle_root)
    staged.artifacts_root.mkdir()

    for name in (
        "plan.json",
        "state.json",
        "commit.txt",
        "version.txt",
    ):
        source = signed_bundle["artifacts"] / name
        (staged.artifacts_root / name).write_bytes(source.read_bytes())

    staged.manifest_path.write_bytes(
        signed_bundle["manifest"].read_bytes()
    )
    staged.signature_path.write_bytes(
        signed_bundle["signature"].read_bytes()
    )

    published = publish_generation(staged)

    receipt = {
        "artifacts_root": str(published.artifacts_root),
        "manifest_path": str(published.manifest_path),
        "signature_path": str(published.signature_path),
        "source": "local-claimed",
        "artifacts": sorted(REQUIRED_ARTIFACTS),
        "signature_key_id": KEY_ID,
    }

    acceptance_state = InMemoryAcceptanceState()

    consumer = ConsumerAgent(
        published.artifacts_root,
        expected_source="local-claimed",
        expected_key_id=KEY_ID,
        acceptance_state=acceptance_state,
        trust_registry_path=signed_bundle["trust_registry"],
        bundle_root=bundle_root,
    )

    artifact = published.artifacts_root / "plan.json"
    original_bytes = artifact.read_bytes()

    # Tamper with an artifact after the generation is published.
    artifact.write_bytes(original_bytes + b"\n")

    tampered = consumer.run(receipt)

    assert tampered.success is False
    assert tampered.error is not None

    # Restore the exact original bytes.
    artifact.write_bytes(original_bytes)

    # If tampering had consumed acceptance state, this would be a replay.
    first_valid = consumer.run(receipt)

    assert first_valid.success is True
    assert first_valid.data == {
        "verified": True,
        "key_id": KEY_ID,
    }

    # Only the successful verification should consume acceptance.
    replay = consumer.run(receipt)

    assert replay.success is False
    assert replay.error == "bundle-replay-detected"

def test_verification_does_not_reopen_resolved_trust_key(
    signed_bundle,
    monkeypatch,
):
    """Verification must not reopen a key after trust resolution."""
    from pathlib import Path

    import evidence_engine.verify as verify_module

    original_read_bytes = Path.read_bytes
    key_path = (
        signed_bundle["trust_registry"].parent.parent
        / "keys"
        / "public.pem"
    ).resolve()

    key_reads = []

    def tracked_read_bytes(path):
        if Path(path).resolve() == key_path:
            key_reads.append(path)

            if len(key_reads) > 1:
                raise AssertionError(
                    "Trusted public key reopened after validation"
                )

        return original_read_bytes(path)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "read_bytes", tracked_read_bytes)

        assert verify_module.verify_bundle(
            signed_bundle["artifacts"],
            signed_bundle["manifest"],
            signed_bundle["signature"],
            signed_bundle["trust_registry"],
            signed_bundle["key_id"],
        )

    assert len(key_reads) == 0


@pytest.mark.parametrize(
    "registry_kind",
    [
        "missing",
        "malformed",
        "directory",
        "unauthorized",
        "writable",
        "symlink",
    ],
)
def test_invalid_configured_trust_never_falls_back_or_advances_acceptance(
    signed_bundle,
    tmp_path,
    registry_kind,
):
    """Invalid configured trust must fail closed without acceptance."""
    import os

    if registry_kind in {"writable", "symlink"}:
        if os.name != "posix":
            pytest.skip("Requires POSIX filesystem security semantics")

    valid_registry = signed_bundle["trust_registry"]

    # Establish that the original signed evidence is valid.
    assert verify(signed_bundle) is True

    bundle_root = tmp_path / "trust-regression-published-bundle"

    staged = create_staging_generation(bundle_root)
    staged.artifacts_root.mkdir()

    for name in sorted(REQUIRED_ARTIFACTS):
        source = signed_bundle["artifacts"] / name
        destination = staged.artifacts_root / name
        destination.write_bytes(source.read_bytes())

    staged.manifest_path.write_bytes(
        signed_bundle["manifest"].read_bytes()
    )
    staged.signature_path.write_bytes(
        signed_bundle["signature"].read_bytes()
    )

    published = publish_generation(staged)

    assert resolve_current_generation(bundle_root) == published

    # Keep the invalid registry beside the valid registry so that
    # relative public-key references retain their original meaning.
    invalid_registry = (
        valid_registry.parent
        / f"invalid-{registry_kind}.json"
    )

    if registry_kind == "missing":
        assert not invalid_registry.exists()

    elif registry_kind == "malformed":
        invalid_registry.write_text(
            "{invalid-json",
            encoding="utf-8",
        )

    elif registry_kind == "directory":
        invalid_registry.mkdir()

    elif registry_kind == "unauthorized":
        registry = json.loads(
            valid_registry.read_text(encoding="utf-8")
        )

        for key in registry["keys"]:
            if key["key_id"] == KEY_ID:
                key["allowed_sources"] = [
                    "github-actions-claimed"
                ]

        invalid_registry.write_text(
            json.dumps(registry),
            encoding="utf-8",
        )

    elif registry_kind == "writable":
        invalid_registry.write_bytes(
            valid_registry.read_bytes()
        )
        invalid_registry.chmod(0o666)

    elif registry_kind == "symlink":
        invalid_registry.symlink_to(valid_registry)

    else:
        pytest.fail(
            f"Unexpected registry kind: {registry_kind}"
        )

    receipt = {
        "artifacts_root": str(published.artifacts_root),
        "manifest_path": str(published.manifest_path),
        "signature_path": str(published.signature_path),
        "source": "local-claimed",
        "artifacts": sorted(REQUIRED_ARTIFACTS),
        "signature_key_id": KEY_ID,

        # Untrusted receipt metadata must not override the
        # consumer's explicitly configured trust registry.
        "trust_registry_path": str(valid_registry),
    }

    acceptance_state = InMemoryAcceptanceState()

    invalid_consumer = ConsumerAgent(
        published.artifacts_root,
        expected_source="local-claimed",
        expected_key_id=KEY_ID,
        acceptance_state=acceptance_state,
        trust_registry_path=invalid_registry,
        bundle_root=bundle_root,
    )

    # Real verification must reject the configured invalid registry,
    # even though the receipt identifies a valid alternative.
    rejected = invalid_consumer.run(receipt)

    assert rejected.success is False
    assert rejected.error in {
        "verification-failed",
        "verification-error",
    }, rejected

    # Reconfigure the consumer with the valid trust registry while
    # preserving the original acceptance state.
    valid_consumer = ConsumerAgent(
        published.artifacts_root,
        expected_source="local-claimed",
        expected_key_id=KEY_ID,
        acceptance_state=acceptance_state,
        trust_registry_path=valid_registry,
        bundle_root=bundle_root,
    )

    first_valid = valid_consumer.run(receipt)

    # If the rejected attempt had recorded acceptance, this
    # legitimate consumption would incorrectly be a replay.
    assert first_valid.success is True, first_valid
    assert first_valid.data == {
        "verified": True,
        "key_id": KEY_ID,
    }

    # Normal replay protection must remain operational.
    replay = valid_consumer.run(receipt)

    assert replay.success is False
    assert replay.error == "bundle-replay-detected"

    assert (
        first_valid.audit["bundle_digest"]
        == replay.audit["bundle_digest"]
    )
