
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

import evidence_engine.verify as verify_module


COMMIT_SHA = "a" * 40
TERRAFORM_VERSION = "1.9.0"


def terraform_documents(
    plan_version=TERRAFORM_VERSION,
    state_version=TERRAFORM_VERSION,
):
    plan = {
        "format_version": "1.2",
        "terraform_version": plan_version,
        "planned_values": {
            "root_module": {"resources": []},
        },
        "resource_changes": [],
    }

    state = {
        "format_version": "1.0",
        "terraform_version": state_version,
        "values": {
            "root_module": {"resources": []},
        },
    }

    return plan, state


def valid_metadata():
    return {
        "plan.json": {
            "representation": "sanitized",
            "sanitization_rule_version": "1.1",
        },
        "state.json": {
            "representation": "sanitized",
            "sanitization_rule_version": "1.1",
        },
        "commit.txt": {
            "representation": "raw",
            "sanitization_rule_version": None,
        },
        "version.txt": {
            "representation": "raw",
            "sanitization_rule_version": None,
        },
    }


@pytest.fixture
def ci_bundle(tmp_path, monkeypatch):
    artifacts = tmp_path / "source-artifacts"
    output = tmp_path / "bundle"
    terraform_root = tmp_path / "terraform"
    artifacts.mkdir()
    output.mkdir()
    terraform_root.mkdir()

    plan, state = terraform_documents()

    (artifacts / "plan.json").write_text(
        json.dumps(plan), encoding="utf-8"
    )
    (artifacts / "state.json").write_text(
        json.dumps(state), encoding="utf-8"
    )
    (artifacts / "commit.txt").write_text(
        f"{COMMIT_SHA}\n", encoding="utf-8"
    )
    (artifacts / "version.txt").write_text(
        f"Terraform {TERRAFORM_VERSION}\n", encoding="utf-8"
    )

    context = {
        "repository": "example/evidence-engine",
        "commit_sha": COMMIT_SHA,
        "run_id": "123456",
        "ref": "refs/heads/main",
        "workflow_ref": "example/evidence-engine/.github/workflows/producer.yml@refs/heads/main",
        "run_number": 12,
        "run_attempt": 1,
        "stream_id": "example-stream",
    }

    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setattr(
        verify_module,
        "capture_ci_context",
        lambda: context,
    )

    monkeypatch.setattr(
        verify_module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            stdout=f"{COMMIT_SHA}\n"
        ),
    )

    monkeypatch.setattr(
        verify_module,
        "provenance_for",
        lambda *args, **kwargs: {
            "repository": "placeholder/repository",
            "commit_sha": COMMIT_SHA,
            "workflow_run_id": "placeholder",
            "terraform_version": "incorrect-caller-version",
            "provider_lock_sha256": "b" * 64,
            "source": "github-actions-claimed",
        },
    )

    # Isolate these tests from cryptographic key handling.
    monkeypatch.setattr(
        verify_module,
        "write_manifest",
        lambda artifacts, manifest_path, provenance, key_id, **kwargs: (
            manifest_path.write_bytes(
                json.dumps(
                    {
                        "provenance": provenance,
                        "key_id": key_id,
                    }
                ).encode("utf-8")
            )
        ),
    )
    monkeypatch.setattr(
        verify_module,
        "sign_bytes",
        lambda private_key, manifest_bytes: b"test-signature",
    )

    return {
        "artifacts": artifacts,
        "output": output,
        "terraform_root": terraform_root,
        "private_key": tmp_path / "unused-private-key.pem",
    }


def seal_ci(bundle, metadata):
    verify_module.seal(
        bundle["artifacts"],
        bundle["output"],
        bundle["private_key"],
        terraform_root=bundle["terraform_root"],
        artifact_metadata=metadata,
    )


def test_ci_sealing_requires_explicit_artifact_metadata(ci_bundle):
    with pytest.raises(
        ValueError,
        match="Explicit artifact metadata is required",
    ):
        seal_ci(ci_bundle, None)

    assert not (ci_bundle["output"] / "manifest.sig").exists()


@pytest.mark.parametrize("artifact_name", ["plan.json", "state.json"])
def test_ci_sealing_rejects_unsanitized_terraform_artifacts(
    ci_bundle,
    artifact_name,
):
    metadata = valid_metadata()
    metadata[artifact_name] = {
        "representation": "raw",
        "sanitization_rule_version": None,
    }

    with pytest.raises(ValueError):
        seal_ci(ci_bundle, metadata)

    assert not (ci_bundle["output"] / "manifest.sig").exists()


def test_ci_sealing_rejects_invalid_terraform_json(ci_bundle):
    (ci_bundle["artifacts"] / "plan.json").write_text(
        '{"format_version": ',
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        seal_ci(ci_bundle, valid_metadata())

    assert not (ci_bundle["output"] / "manifest.sig").exists()


def test_ci_sealing_rejects_plan_state_version_mismatch(ci_bundle):
    plan, state = terraform_documents(
        plan_version="1.9.0",
        state_version="1.8.0",
    )

    (ci_bundle["artifacts"] / "plan.json").write_text(
        json.dumps(plan), encoding="utf-8"
    )
    (ci_bundle["artifacts"] / "state.json").write_text(
        json.dumps(state), encoding="utf-8"
    )

    with pytest.raises(ValueError):
        seal_ci(ci_bundle, valid_metadata())

    assert not (ci_bundle["output"] / "manifest.sig").exists()


def test_manifest_uses_version_from_staged_terraform_documents(
    ci_bundle,
):
    seal_ci(ci_bundle, valid_metadata())

    manifest = json.loads(
        (ci_bundle["output"] / "manifest.json").read_text(
            encoding="utf-8"
        )
    )

    assert manifest["provenance"]["terraform_version"] == (
        TERRAFORM_VERSION
    )
    assert manifest["provenance"]["terraform_version"] != (
        "incorrect-caller-version"
    )

    assert (
        ci_bundle["output"] / "artifacts" / "plan.json"
    ).is_file()
    assert (
        ci_bundle["output"] / "artifacts" / "state.json"
    ).is_file()
    assert (
        ci_bundle["output"] / "manifest.sig"
    ).read_bytes() == b"test-signature"


def test_failed_reseal_removes_preexisting_signature(ci_bundle):
    signature_path = ci_bundle["output"] / "manifest.sig"
    signature_path.write_bytes(b"old-signature")

    metadata = valid_metadata()
    metadata["plan.json"] = {
        "representation": "raw",
        "sanitization_rule_version": None,
    }

    with pytest.raises(ValueError):
        seal_ci(ci_bundle, metadata)

    assert not signature_path.exists()


def test_cli_loads_artifact_metadata_json(
    ci_bundle,
    tmp_path,
    monkeypatch,
):
    metadata_path = tmp_path / "artifact-metadata.json"
    metadata = valid_metadata()
    metadata_path.write_text(
        json.dumps(metadata),
        encoding="utf-8",
    )

    captured = {}

    def fake_seal(*args, **kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(verify_module, "seal", fake_seal)
    monkeypatch.setattr(
        "sys.argv",
        [
            "evidence-engine",
            "seal",
            "--artifacts",
            str(ci_bundle["artifacts"]),
            "--output",
            str(ci_bundle["output"]),
            "--private-key",
            str(ci_bundle["private_key"]),
            "--artifact-metadata",
            str(metadata_path),
        ],
    )

    verify_module.main()

    assert captured["artifact_metadata"] == metadata


def test_cli_rejects_non_object_artifact_metadata(
    ci_bundle,
    tmp_path,
    monkeypatch,
):
    metadata_path = tmp_path / "artifact-metadata.json"
    metadata_path.write_text("[]", encoding="utf-8")

    monkeypatch.setattr(
        "sys.argv",
        [
            "evidence-engine",
            "seal",
            "--artifacts",
            str(ci_bundle["artifacts"]),
            "--output",
            str(ci_bundle["output"]),
            "--private-key",
            str(ci_bundle["private_key"]),
            "--artifact-metadata",
            str(metadata_path),
        ],
    )

    with pytest.raises(SystemExit) as exc:
        verify_module.main()

    assert exc.value.code == 1
