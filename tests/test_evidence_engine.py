
import json
import subprocess

import pytest

from evidence_engine.canonical import (
    canonical_json_bytes,
    parse_json_strict,
)
from evidence_engine.collect import collect, provenance_for
from evidence_engine.manifest import build_manifest
from evidence_engine.schema import validate_manifest
from evidence_engine.signing import (
    KEY_ID,
    generate_key_pair,
    sign_bytes,
    verify_bytes,
)
from evidence_engine.verify import seal, verify_bundle


def create_bundle(tmp_path):
    artifacts = tmp_path / "artifacts"
    output = tmp_path / "sealed"
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"

    generate_key_pair(private_key, public_key)
    collect(artifacts)
    seal(artifacts, output, private_key)

    return artifacts, output, private_key, public_key

@pytest.fixture(autouse=True)
def isolate_local_sealing_from_github_runner(monkeypatch):
    """Keep ordinary bundle tests in local-sealing mode."""
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)

def check_bundle(artifacts, output, public_key, key_id=KEY_ID):
    registry_path = output / "trust_registry.json"

    registry = {
        "schema_version": "1.0",
        "keys": [
            {
                "key_id": key_id,
                "public_key": "../public.pem",
                "status": "active",
                "allowed_sources": [
                    "local-claimed",
                    "github-actions-claimed",
                ],
            }
        ],
    }

    registry_path.write_text(
        json.dumps(registry),
        encoding="utf-8",
    )

    return verify_bundle(
        artifacts,
        output / "manifest.json",
        output / "manifest.sig",
        registry_path,
        key_id,
    )


def test_canonical_json_is_deterministic():
    first = {"z": 1, "a": {"y": 2, "b": 3}}
    second = {"a": {"b": 3, "y": 2}, "z": 1}

    assert canonical_json_bytes(first) == canonical_json_bytes(second)


def test_duplicate_json_keys_are_rejected():
    with pytest.raises(ValueError, match="Duplicate JSON key"):
        parse_json_strict(b'{"key": 1, "key": 2}')


def test_noncanonical_manifest_bytes_are_rejected(tmp_path):
    artifacts, output, _, public_key = create_bundle(tmp_path)

    manifest_path = output / "manifest.json"
    manifest_path.write_bytes(manifest_path.read_bytes() + b"\n")

    assert not check_bundle(artifacts, output, public_key)


def test_valid_bundle_passes(tmp_path):
    artifacts, output, _, public_key = create_bundle(tmp_path)

    assert check_bundle(artifacts, output, public_key)


def test_tampered_artifact_fails(tmp_path):
    artifacts, output, _, public_key = create_bundle(tmp_path)

    artifact_path = artifacts / "plan.json"
    artifact_path.write_bytes(
        artifact_path.read_bytes() + b"TAMPERED"
    )

    assert not check_bundle(artifacts, output, public_key)


def test_extra_artifact_fails(tmp_path):
    artifacts, output, _, public_key = create_bundle(tmp_path)

    (artifacts / "unexpected.txt").write_text(
        "extra",
        encoding="utf-8",
    )

    assert not check_bundle(artifacts, output, public_key)


def test_missing_artifact_fails(tmp_path):
    artifacts, output, _, public_key = create_bundle(tmp_path)

    (artifacts / "state.json").unlink()

    assert not check_bundle(artifacts, output, public_key)


def test_wrong_key_id_fails(tmp_path):
    artifacts, output, _, public_key = create_bundle(tmp_path)

    assert not check_bundle(
        artifacts,
        output,
        public_key,
        key_id="untrusted-key",
    )


def test_signature_rejects_modified_message(tmp_path):
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"

    generate_key_pair(private_key, public_key)

    signature = sign_bytes(private_key, b"original")

    assert verify_bytes(public_key, b"original", signature)
    assert not verify_bytes(public_key, b"modified", signature)


def test_manifest_rejects_missing_required_artifact(tmp_path):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()

    (artifacts / "plan.json").write_text(
        "{}",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Artifact set mismatch"):
        build_manifest(
            artifacts,
            provenance_for(tmp_path),
            KEY_ID,
        )


def test_manifest_rejects_unknown_field(tmp_path):
    artifacts, output, _, _ = create_bundle(tmp_path)

    manifest = json.loads(
        (output / "manifest.json").read_bytes()
    )
    manifest["unrecognized_field"] = True

    with pytest.raises(
        ValueError,
        match="missing or unknown top-level fields",
    ):
        validate_manifest(manifest)


def test_ci_sealing_rejects_checkout_commit_mismatch(
    tmp_path,
    monkeypatch,
):
    artifacts = tmp_path / "artifacts"
    output = tmp_path / "sealed"
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"

    artifacts.mkdir()
    generate_key_pair(private_key, public_key)

    for name in (
        "plan.json",
        "state.json",
        "commit.txt",
        "version.txt",
    ):
        (artifacts / name).write_text(
            "{}\n",
            encoding="utf-8",
        )

    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv(
        "GITHUB_REPOSITORY",
        "example-org/evidence-engine",
    )
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    monkeypatch.setenv("GITHUB_RUN_ID", "123456789")
    monkeypatch.setenv("GITHUB_RUN_NUMBER", "42")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    monkeypatch.setenv(
        "EVIDENCE_ENGINE_STREAM_ID", "terraform-production"
    )
    monkeypatch.setenv(
        "GITHUB_WORKFLOW_REF",
        "example-org/evidence-engine/.github/workflows/ci.yml@refs/heads/main",
    )

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=0,
            stdout="b" * 40 + "\n",
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(
        ValueError,
        match="does not match checked-out Git commit",
    ):
        seal(artifacts, output, private_key)
