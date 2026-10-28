from __future__ import annotations

import json
import hashlib
from pathlib import Path
from typing import Any
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


from evidence_engine.aws.reference import BundleReference
from evidence_engine.agents.base import AgentResult
from evidence_engine.agents.orchestrator import Orchestrator
from evidence_engine.signing import KEY_ID


PROVENANCE = {
    "repository": "example-org/example-repo",
    "commit_sha": "a" * 40,
    "workflow_run_id": "12345",
    "terraform_version": "1.9.0",
    "provider_lock_sha256": "",
    "source": "local-claimed",
}

ARTIFACT_NAMES = {
    "plan.json",
    "state.json",
    "commit.txt",
    "version.txt",
}


def sample_artifact_metadata() -> dict[str, dict[str, Any]]:
    """Explicitly classify synthetic artifacts used by orchestration tests."""
    return {
        name: {"representation": "sample", "sanitization_rule_version": None}
        for name in ARTIFACT_NAMES
    }

_DEFAULT_PRIVATE_KEY = object()


def make_artifacts(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)

    for name in ARTIFACT_NAMES:
        (root / name).write_text(
            f"test data: {name}\n",
            encoding="utf-8",
        )

    return root


def prepare_signing_and_trust(tmp_path: Path) -> None:
    """Create a real RSA key pair and an active local trust entry."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    (tmp_path / "private.pem").write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    (tmp_path / "public.pem").write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    (tmp_path / "trust.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "keys": [
                    {
                        "key_id": KEY_ID,
                        "public_key": "public.pem",
                        "status": "active",
                        "allowed_sources": ["local-claimed"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def make_orchestrator(
    tmp_path: Path,
    *,
    root: Path | None = None,
    output: Path | None = None,
    signing_mode: str = "local",
    private_key: Path | None | object = _DEFAULT_PRIVATE_KEY,
    kms_key_id: str | None = None,
    provenance: dict | None = None,
    bundle_storage: Any | None = None,
    bundle_prefix: str | None = None,
    require_remote_storage: bool = False,
    artifact_metadata: dict[str, dict[str, Any]] | None = None,
) -> Orchestrator:
    artifacts_root = root or make_artifacts(tmp_path / "artifacts")

    selected_private_key = (
        tmp_path / "private.pem"
        if private_key is _DEFAULT_PRIVATE_KEY
        else private_key
    )

    return Orchestrator(
        artifacts_root=artifacts_root,
        output_dir=output or tmp_path / "bundle",
        provenance=provenance or PROVENANCE,
        trust_registry_path=tmp_path / "trust.json",
        signing_mode=signing_mode,
        private_key=selected_private_key,
        kms_key_id=kms_key_id,
        bundle_storage=bundle_storage,
        bundle_prefix=bundle_prefix,
        require_remote_storage=require_remote_storage,
        artifact_metadata=artifact_metadata,
    )


def test_orchestrator_success_creates_bundle_and_receipt(
    tmp_path: Path,
):
    prepare_signing_and_trust(tmp_path)

    agent = make_orchestrator(tmp_path)
    result = agent.run()

    assert result.success is True
    assert result.error is None
    assert result.data is not None
    assert result.data["key_id"] == KEY_ID
    assert result.data["mode"] == "local"

    bundle = tmp_path / "bundle"
    assert (bundle / "manifest.json").is_file()
    assert (bundle / "manifest.sig").is_file()
    assert (bundle / "manifest.sig").stat().st_size > 0

    assert result.data["receipt"]["signature_key_id"] == KEY_ID
    assert result.data["receipt"]["source"] == "local-claimed"


def test_orchestrator_passes_explicit_artifact_metadata(tmp_path: Path):
    prepare_signing_and_trust(tmp_path)
    metadata = {
        name: {
            "representation": "raw",
            "sanitization_rule_version": None,
        }
        for name in ARTIFACT_NAMES
    }

    result = make_orchestrator(
        tmp_path,
        artifact_metadata=metadata,
    ).run()

    assert result.success is True
    manifest = json.loads(
        (tmp_path / "bundle" / "manifest.json").read_text(encoding="utf-8")
    )
    assert {
        item["name"]: item["representation"]
        for item in manifest["artifacts"]
    } == {name: "raw" for name in ARTIFACT_NAMES}


def test_orchestrator_rejects_incomplete_artifact_metadata(tmp_path: Path):
    prepare_signing_and_trust(tmp_path)
    metadata = {
        "plan.json": {
            "representation": "raw",
            "sanitization_rule_version": None,
        }
    }

    result = make_orchestrator(
        tmp_path,
        artifact_metadata=metadata,
    ).run()

    assert result.success is False
    assert result.error == "manifest-creation-failed"
    assert result.audit["stage"] == "manifest"
    assert (
        "missing=['commit.txt', 'state.json', 'version.txt']"
        in result.audit["exception"]
    )
    assert not (tmp_path / "bundle" / "manifest.sig").exists()


@pytest.mark.parametrize(
    ("mode", "private_key", "kms_key_id", "expected_error"),
    [
        ("unknown", None, None, "signing-mode-invalid"),
        ("local", None, None, "local-signing-missing-key"),
        ("kms", None, "  ", "kms-signing-missing-key-id"),
    ],
)
def test_orchestrator_rejects_invalid_signing_configuration(
    tmp_path: Path,
    mode: str,
    private_key: Path | None,
    kms_key_id: str | None,
    expected_error: str,
):
    agent = make_orchestrator(
        tmp_path,
        signing_mode=mode,
        private_key=private_key,
        kms_key_id=kms_key_id,
    )

    result = agent.run()

    assert result.success is False
    assert result.error == expected_error


def test_orchestrator_rejects_invalid_provenance_source(
    tmp_path: Path,
):
    provenance = {**PROVENANCE, "source": "untrusted-source"}
    agent = make_orchestrator(tmp_path, provenance=provenance)

    result = agent.run()

    assert result.success is False
    assert result.error == "provenance-source-invalid"


@pytest.mark.parametrize("output_inside", ["same", "child"])
def test_orchestrator_rejects_output_inside_artifacts(
    tmp_path: Path,
    output_inside: str,
):
    root = make_artifacts(tmp_path / "artifacts")
    output = root if output_inside == "same" else root / "bundle"

    agent = make_orchestrator(
        tmp_path,
        root=root,
        output=output,
    )

    result = agent.run()

    assert result.success is False
    assert result.error == "output-inside-artifacts-root"


def test_orchestrator_rejects_unexpected_artifact_set(
    tmp_path: Path,
):
    root = make_artifacts(tmp_path / "artifacts")
    (root / "unexpected.txt").write_text(
        "unexpected",
        encoding="utf-8",
    )

    agent = make_orchestrator(tmp_path, root=root)
    result = agent.run()

    assert result.success is False
    assert result.error == "artifact-set-mismatch"


def test_integrity_failure_prevents_signing_and_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    class FailedIntegrityAgent:
        def __init__(self, *args, **kwargs):
            pass

        def run(self):
            return AgentResult(
                success=False,
                data=None,
                error="test-integrity-failure",
                audit={"reason": "injected failure"},
            )

    def unexpected_signing_agent(**kwargs):
        pytest.fail("Signing must not run after integrity failure")

    monkeypatch.setattr(
        "evidence_engine.agents.orchestrator.IntegrityAgent",
        FailedIntegrityAgent,
    )
    monkeypatch.setattr(
        "evidence_engine.agents.orchestrator.SigningAgent",
        unexpected_signing_agent,
    )

    result = make_orchestrator(tmp_path).run()

    assert result.success is False
    assert result.error == "test-integrity-failure"
    assert result.audit["stage"] == "integrity"
    assert not (tmp_path / "bundle" / "manifest.sig").exists()


def test_signing_failure_prevents_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    class FailedSigningAgent:
        def __init__(self, **kwargs):
            pass

        def run(self):
            return AgentResult(
                success=False,
                data=None,
                error="test-signing-failure",
                audit={},
            )

    def unexpected_receipt_agent(**kwargs):
        pytest.fail("Receipt must not run after signing failure")

    monkeypatch.setattr(
        "evidence_engine.agents.orchestrator.SigningAgent",
        FailedSigningAgent,
    )
    monkeypatch.setattr(
        "evidence_engine.agents.orchestrator.ReceiptAgent",
        unexpected_receipt_agent,
    )

    result = make_orchestrator(tmp_path).run()

    assert result.success is False
    assert result.error == "test-signing-failure"
    assert result.audit["stage"] == "signing"
    assert not (tmp_path / "bundle" / "manifest.sig").exists()


def test_orchestrator_rejects_empty_signature(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    class EmptySigningAgent:
        def __init__(self, **kwargs):
            pass

        def run(self):
            return AgentResult(
                success=True,
                data={
                    "signature": b"",
                    "key_id": KEY_ID,
                    "mode": "local",
                },
                error=None,
                audit={},
            )

    monkeypatch.setattr(
        "evidence_engine.agents.orchestrator.SigningAgent",
        EmptySigningAgent,
    )

    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "manifest.sig").write_bytes(b"stale-signature")

    result = make_orchestrator(tmp_path, output=bundle).run()

    assert result.success is False
    assert result.error == "signature-output-invalid"
    assert not (bundle / "manifest.sig").exists()

def test_orchestrator_requires_s3_when_remote_storage_is_mandatory(
    tmp_path: Path,
):
    agent = make_orchestrator(
        tmp_path,
        require_remote_storage=True,
    )

    result = agent.run()

    assert result.success is False
    assert result.error == "s3-storage-required"


def test_orchestrator_rejects_s3_prefix_without_storage(
    tmp_path: Path,
):
    agent = make_orchestrator(
        tmp_path,
        bundle_prefix="runs/test-123",
    )

    result = agent.run()

    assert result.success is False
    assert result.error == "s3-storage-missing"


class FakeBundleStorage:
    def __init__(self, bucket: str = "evidence-test-bucket"):
        self.bucket = bucket
        self.calls = []

    def upload_bundle(
        self,
        *,
        prefix,
        artifacts_root,
        manifest_path,
        signature_path,
    ):
        self.calls.append(
            {
                "prefix": prefix,
                "manifest_path": Path(manifest_path),
                "signature_path": Path(signature_path),
            }
        )

        payloads = {
            f"{prefix}/manifest.json": Path(manifest_path).read_bytes(),
            f"{prefix}/manifest.sig": Path(signature_path).read_bytes(),
        }

        for name in sorted(ARTIFACT_NAMES):
            payloads[f"{prefix}/artifacts/{name}"] = (
                Path(artifacts_root) / name
            ).read_bytes()

        objects = [
            {
                "key": key,
                "sha256": hashlib.sha256(content).hexdigest(),
                "version_id": f"version-{index}",
            }
            for index, (key, content) in enumerate(
                sorted(payloads.items()),
                start=1,
            )
        ]

        reference = BundleReference.from_upload(
            bucket=self.bucket,
            prefix=prefix,
            objects=objects,
        )

        return {
            "bucket": self.bucket,
            "prefix": prefix,
            "objects": objects,
            "reference": reference.to_dict(),
        }


def test_orchestrator_uploads_bundle_and_returns_reference(
    tmp_path: Path,
):
    prepare_signing_and_trust(tmp_path)
    root = make_artifacts(tmp_path / "source-artifacts")
    _write_valid_terraform_json(root)
    storage = FakeBundleStorage()

    agent = make_orchestrator(
        tmp_path,
        root=root,
        bundle_storage=storage,
        bundle_prefix="runs/test-123",
        require_remote_storage=True,
        artifact_metadata=_sanitized_artifact_metadata(),
    )

    result = agent.run()

    assert result.success is True
    assert result.data["storage_mode"] == "s3"
    assert len(storage.calls) == 1
    assert storage.calls[0]["prefix"] == "runs/test-123"
    assert storage.calls[0]["manifest_path"].is_file()
    assert storage.calls[0]["signature_path"].is_file()

    reference = BundleReference.from_dict(
        result.data["bundle_reference"]
    )
    assert reference.bucket == "evidence-test-bucket"
    assert reference.prefix == "runs/test-123"
    assert "s3-upload" in result.audit["stages"]


def test_orchestrator_fails_closed_when_s3_upload_fails(
    tmp_path: Path,
):
    prepare_signing_and_trust(tmp_path)
    root = make_artifacts(tmp_path / "source-artifacts")
    _write_valid_terraform_json(root)

    class FailedStorage:
        def upload_bundle(self, **kwargs):
            raise RuntimeError("simulated S3 failure")

    agent = make_orchestrator(
        tmp_path,
        root=root,
        bundle_storage=FailedStorage(),
        bundle_prefix="runs/test-failure",
        require_remote_storage=True,
        artifact_metadata=_sanitized_artifact_metadata(),
    )

    result = agent.run()

    assert result.success is False
    assert result.error == "bundle-upload-failed"
    assert result.audit["stage"] == "s3-upload"
    assert result.audit["exception_type"] == "RuntimeError"

def test_orchestrator_uses_schema_v13_for_github_provenance(
    tmp_path: Path,
):
    prepare_signing_and_trust(tmp_path)

    # Permit the claimed source in the local test trust registry.
    trust_path = tmp_path / "trust.json"
    trust = json.loads(trust_path.read_text(encoding="utf-8"))
    trust["keys"][0]["allowed_sources"] = ["github-actions-claimed"]
    trust_path.write_text(json.dumps(trust), encoding="utf-8")

    provenance = {
        **PROVENANCE,
        "source": "github-actions-claimed",
        "ref": "refs/heads/main",
        "workflow_ref": (
            "example-org/example-repo/"
            ".github/workflows/ci.yml@refs/heads/main"
        ),
        "run_number": "42",
        "run_attempt": "1",
        "stream_id": "terraform-production",
    }

    root = make_artifacts(tmp_path / "source-artifacts")
    _write_valid_terraform_json(root)
    result = make_orchestrator(
        tmp_path,
        root=root,
        provenance=provenance,
        artifact_metadata=_sanitized_artifact_metadata(),
    ).run()

    assert result.success is True

    manifest = json.loads(
        Path(result.data["manifest_path"]).read_text(encoding="utf-8")
    )
    assert manifest["schema_version"] == "1.3"
    assert manifest["provenance"]["stream_id"] == "terraform-production"
    assert manifest["provenance"]["run_number"] == "42"
    assert manifest["provenance"]["run_attempt"] == "1"


def test_orchestrator_rejects_incomplete_github_provenance(
    tmp_path: Path,
):
    prepare_signing_and_trust(tmp_path)

    provenance = {
        **PROVENANCE,
        "source": "github-actions-claimed",
    }

    root = make_artifacts(tmp_path / "source-artifacts")
    _write_valid_terraform_json(root)
    result = make_orchestrator(
        tmp_path,
        root=root,
        provenance=provenance,
        artifact_metadata=_sanitized_artifact_metadata(),
    ).run()

    assert result.success is False
    assert result.error == "manifest-creation-failed"

def test_orchestrator_requires_artifact_metadata_for_github_provenance(
    tmp_path: Path,
):
    prepare_signing_and_trust(tmp_path)
    provenance = {
        **PROVENANCE,
        "source": "github-actions-claimed",
        "ref": "refs/heads/main",
        "workflow_ref": "example-org/example-repo/.github/workflows/ci.yml@refs/heads/main",
        "run_number": "42",
        "run_attempt": "1",
        "stream_id": "terraform-production",
    }

    result = make_orchestrator(
        tmp_path,
        provenance=provenance,
    ).run()

    assert result.success is False
    assert result.error == "artifact-metadata-required"
    assert result.audit["stage"] == "manifest"

def _sanitized_artifact_metadata() -> dict[str, dict[str, Any]]:
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


def _write_valid_terraform_json(root: Path) -> tuple[bytes, bytes]:
    plan = {
        "format_version": "1.0",
        "terraform_version": "1.9.0",
        "planned_values": {"root_module": {"resources": []}},
        "resource_changes": [{
            "address": "example.db",
            "change": {
                "actions": ["update"],
                "before": {"opaque": "PLAN-CANARY-SECRET"},
                "before_sensitive": {"opaque": True},
                "after": {"opaque": "PLAN-CANARY-SECRET"},
                "after_sensitive": {"opaque": True},
            },
        }],
    }
    state = {
        "format_version": "1.0",
        "terraform_version": "1.9.0",
        "values": {"root_module": {"resources": [{
            "address": "example.db",
            "mode": "managed",
            "type": "example",
            "name": "db",
            "values": {"opaque": "STATE-CANARY-SECRET"},
            "sensitive_values": {"opaque": True},
        }]}},
    }
    plan_bytes = json.dumps(plan).encode("utf-8")
    state_bytes = json.dumps(state).encode("utf-8")
    (root / "plan.json").write_bytes(plan_bytes)
    (root / "state.json").write_bytes(state_bytes)
    return plan_bytes, state_bytes


def test_orchestrator_sanitizes_to_separate_root_and_hashes_retained_bytes(
    tmp_path: Path,
):
    prepare_signing_and_trust(tmp_path)
    root = make_artifacts(tmp_path / "source-artifacts")
    original_plan, original_state = _write_valid_terraform_json(root)

    result = make_orchestrator(
        tmp_path,
        root=root,
        artifact_metadata=_sanitized_artifact_metadata(),
    ).run()

    assert result.success is True
    stage_root = tmp_path / "bundle" / "artifacts"
    assert Path(result.data["receipt"]["artifacts_root"]) == stage_root
    assert (root / "plan.json").read_bytes() == original_plan
    assert (root / "state.json").read_bytes() == original_state

    staged_plan = (stage_root / "plan.json").read_bytes()
    staged_state = (stage_root / "state.json").read_bytes()
    assert b"PLAN-CANARY-SECRET" not in staged_plan
    assert b"STATE-CANARY-SECRET" not in staged_state
    assert b"PLAN-CANARY-SECRET" in original_plan
    assert b"STATE-CANARY-SECRET" in original_state

    manifest = json.loads(
        (tmp_path / "bundle" / "manifest.json").read_text(encoding="utf-8")
    )
    artifacts = {item["name"]: item for item in manifest["artifacts"]}
    for name in ("plan.json", "state.json"):
        assert artifacts[name]["representation"] == "sanitized"
        assert artifacts[name]["sanitization_rule_version"] == "1.1"
    for name in ("plan.json", "state.json", "commit.txt", "version.txt"):
        retained = (stage_root / name).read_bytes()
        assert artifacts[name]["sha256"] == hashlib.sha256(retained).hexdigest()
    assert "artifact-sanitization" in result.audit["stages"]


def test_orchestrator_fails_closed_on_invalid_sanitized_terraform_json(
    tmp_path: Path,
):
    prepare_signing_and_trust(tmp_path)
    root = make_artifacts(tmp_path / "source-artifacts")
    (root / "plan.json").write_text("not valid JSON", encoding="utf-8")

    result = make_orchestrator(
        tmp_path,
        root=root,
        artifact_metadata=_sanitized_artifact_metadata(),
    ).run()

    assert result.success is False
    assert result.error == "artifact-sanitization-failed"
    assert result.audit["stage"] == "artifact-sanitization"
    assert not (tmp_path / "bundle" / "manifest.sig").exists()


def test_orchestrator_rejects_partial_sanitization_declarations(
    tmp_path: Path,
):
    prepare_signing_and_trust(tmp_path)
    metadata = _sanitized_artifact_metadata()
    metadata["state.json"] = {
        "representation": "raw",
        "sanitization_rule_version": None,
    }

    result = make_orchestrator(
        tmp_path,
        artifact_metadata=metadata,
    ).run()

    assert result.success is False
    assert result.error == "artifact-sanitization-failed"
    assert result.audit["stage"] == "artifact-sanitization"
    assert not (tmp_path / "bundle" / "manifest.sig").exists()


def test_github_actions_rejects_sample_terraform_artifacts_before_signing(
    tmp_path: Path,
):
    prepare_signing_and_trust(tmp_path)
    provenance = {
        **PROVENANCE,
        "source": "github-actions-claimed",
        "ref": "refs/heads/main",
        "workflow_ref": "example-org/example-repo/.github/workflows/ci.yml@refs/heads/main",
        "run_number": "42",
        "run_attempt": "1",
        "stream_id": "terraform-production",
    }

    result = make_orchestrator(
        tmp_path,
        provenance=provenance,
        artifact_metadata=sample_artifact_metadata(),
    ).run()

    assert result.success is False
    assert result.error == "artifact-sanitization-failed"
    assert result.audit["stage"] == "artifact-sanitization"
    assert not (tmp_path / "bundle" / "manifest.sig").exists()


def test_s3_publication_rejects_sample_terraform_artifacts_before_upload(
    tmp_path: Path,
):
    prepare_signing_and_trust(tmp_path)
    storage = FakeBundleStorage()

    result = make_orchestrator(
        tmp_path,
        bundle_storage=storage,
        bundle_prefix="runs/unsanitized-sample",
        require_remote_storage=True,
        artifact_metadata=sample_artifact_metadata(),
    ).run()

    assert result.success is False
    assert result.error == "artifact-sanitization-failed"
    assert result.audit["stage"] == "artifact-sanitization"
    assert storage.calls == []
    assert not (tmp_path / "bundle" / "manifest.sig").exists()
