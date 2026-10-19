import json

from evidence_engine.canonical import canonical_json_bytes
from evidence_engine.collect import collect
from evidence_engine.manifest import build_manifest
from evidence_engine.signing import (
    generate_key_pair,
    sign_bytes,
    verify_bytes,
)
from evidence_engine.verify import seal, verify_bundle


def test_canonical_json_is_deterministic():
    first = {"z": 1, "a": {"y": 2, "b": 3}}
    second = {"a": {"b": 3, "y": 2}, "z": 1}

    assert canonical_json_bytes(first) == canonical_json_bytes(second)


def test_signature_round_trip(tmp_path):
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"

    generate_key_pair(private_key, public_key)

    message = b"EvidenceEngine test message"
    signature = sign_bytes(private_key, message)

    assert verify_bytes(public_key, message, signature)
    assert not verify_bytes(
        public_key,
        b"Modified message",
        signature,
    )


def test_manifest_hashes_exact_file_bytes(tmp_path):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()

    artifact = artifacts / "example.txt"
    artifact.write_bytes(b"original\n")

    original = build_manifest(artifacts)
    artifact.write_bytes(b"modified\n")
    modified = build_manifest(artifacts)

    assert original["artifacts"][0]["sha256"] != (
        modified["artifacts"][0]["sha256"]
    )


def test_valid_bundle_passes(tmp_path):
    artifacts = tmp_path / "artifacts"
    output = tmp_path / "sealed"
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"

    generate_key_pair(private_key, public_key)
    collect(artifacts)
    seal(artifacts, output, private_key)

    assert verify_bundle(
        artifacts,
        output / "manifest.json",
        output / "manifest.sig",
        public_key,
    )


def test_tampered_artifact_fails(tmp_path):
    artifacts = tmp_path / "artifacts"
    output = tmp_path / "sealed"
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"

    generate_key_pair(private_key, public_key)
    collect(artifacts)
    seal(artifacts, output, private_key)

    plan = artifacts / "plan.json"
    plan.write_bytes(plan.read_bytes() + b"TAMPERED")

    assert not verify_bundle(
        artifacts,
        output / "manifest.json",
        output / "manifest.sig",
        public_key,
    )


def test_tampered_manifest_fails_signature(tmp_path):
    artifacts = tmp_path / "artifacts"
    output = tmp_path / "sealed"
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"

    generate_key_pair(private_key, public_key)
    collect(artifacts)
    seal(artifacts, output, private_key)

    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["schema_version"] = "999"
    manifest_path.write_bytes(canonical_json_bytes(manifest))

    assert not verify_bundle(
        artifacts,
        manifest_path,
        output / "manifest.sig",
        public_key,
    )