from __future__ import annotations
import hashlib
import json
from pathlib import Path
from typing import Any
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from evidence_engine.agents.base import AgentResult
from evidence_engine.agents.orchestrator import Orchestrator
from evidence_engine.aws.reference import BundleReference
from evidence_engine.bundle_publication import resolve_current_generation
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
_DEFAULT_PRIVATE_KEY = object()


def sample_artifact_metadata() -> dict[str, dict[str, Any]]:
    """Explicitly classify synthetic artifacts used by orchestration tests."""
    return {
        name: {
            "representation": "sample",
            "sanitization_rule_version": None,
        }
        for name in ARTIFACT_NAMES
    }


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


def _write_valid_terraform_json(root: Path) -> tuple[bytes, bytes]:
    plan = {
        "format_version": "1.0",
        "terraform_version": "1.9.0",
        "planned_values": {
            "root_module": {
                "resources": [],
            },
        },
        "resource_changes": [
            {
                "address": "example.db",
                "change": {
                    "actions": ["update"],
                    "before": {
                        "opaque": "PLAN-CANARY-SECRET",
                    },
                    "before_sensitive": {
                        "opaque": True,
                    },
                    "after": {
                        "opaque": "PLAN-CANARY-SECRET",
                    },
                    "after_sensitive": {
                        "opaque": True,
                    },
                },
            },
        ],
    }
    state = {
        "format_version": "1.0",
        "terraform_version": "1.9.0",
        "values": {
            "root_module": {
                "resources": [
                    {
                        "address": "example.db",
                        "mode": "managed",
                        "type": "example",
                        "name": "db",
                        "values": {
                            "opaque": "STATE-CANARY-SECRET",
                        },
                        "sensitive_values": {
                            "opaque": True,
                        },
                    },
                ],
            },
        },
    }
    plan_bytes = json.dumps(plan).encode("utf-8")
    state_bytes = json.dumps(state).encode("utf-8")
    (root / "plan.json").write_bytes(plan_bytes)
    (root / "state.json").write_bytes(state_bytes)
    return plan_bytes, state_bytes


def test_orchestrator_success_creates_bundle_and_receipt(
    tmp_path: Path,
):
    prepare_signing_and_trust(tmp_path)
    result = make_orchestrator(tmp_path).run()
    assert result.success is True
    assert result.error is None
    assert result.data is not None
    assert result.data["key_id"] == KEY_ID
    assert result.data["mode"] == "local"
    bundle = tmp_path / "bundle"
    paths = resolve_current_generation(bundle)
    assert (bundle / "CURRENT").is_file()
    assert paths.manifest_path.is_file()
    assert paths.signature_path.is_file()
    assert paths.signature_path.stat().st_size > 0
    assert {p.name for p in paths.artifacts_root.iterdir()} == ARTIFACT_NAMES
    assert Path(result.data["manifest_path"]) == paths.manifest_path
    assert Path(result.data["signature_path"]) == paths.signature_path
    assert Path(result.data["receipt"]["artifacts_root"]) == paths.artifacts_root
    assert Path(result.data["receipt"]["manifest_path"]) == paths.manifest_path
    assert Path(result.data["receipt"]["signature_path"]) == paths.signature_path
    assert result.data["receipt"]["signature_key_id"] == KEY_ID
    assert result.data["receipt"]["source"] == "local-claimed"


def test_orchestrator_passes_explicit_artifact_metadata(
    tmp_path: Path,
):
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
        resolve_current_generation(tmp_path / "bundle").manifest_path.read_text(
            encoding="utf-8"
        )
    )
    assert {
        item["name"]: item["representation"]
        for item in manifest["artifacts"]
    } == {
        name: "raw"
        for name in ARTIFACT_NAMES
    }


def test_orchestrator_rejects_incomplete_artifact_metadata(
    tmp_path: Path,
):
    prepare_signing_and_trust(tmp_path)
    metadata = {
        "plan.json": {
            "representation": "raw",
            "sanitization_rule_version": None,
        },
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
    assert not (tmp_path / "bundle" / "CURRENT").exists()


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
    provenance = {
        **PROVENANCE,
        "source": "untrusted-source",
    }
    result = make_orchestrator(
        tmp_path,
        provenance=provenance,
    ).run()
    assert result.success is False
    assert result.error == "provenance-source-invalid"


@pytest.mark.parametrize("output_inside", ["same", "child"])


def test_orchestrator_rejects_output_inside_artifacts(
    tmp_path: Path,
    output_inside: str,
):
    root = make_artifacts(tmp_path / "artifacts")
    output = root if output_inside == "same" else root / "bundle"
    result = make_orchestrator(
        tmp_path,
        root=root,
        output=output,
    ).run()
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
    result = make_orchestrator(
        tmp_path,
        root=root,
    ).run()
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
    assert not (tmp_path / "bundle" / "CURRENT").exists()


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
    assert not (tmp_path / "bundle" / "CURRENT").exists()


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
    result = make_orchestrator(
        tmp_path,
        output=bundle,
    ).run()
    assert result.success is False
    assert result.error == "signature-output-invalid"
    assert not (bundle / "CURRENT").exists()
    assert not list((bundle / "generations").iterdir())


def test_orchestrator_requires_s3_when_remote_storage_is_mandatory(
    tmp_path: Path,
):
    result = make_orchestrator(
        tmp_path,
        require_remote_storage=True,
    ).run()
    assert result.success is False
    assert result.error == "s3-storage-required"


def test_orchestrator_rejects_s3_prefix_without_storage(
    tmp_path: Path,
):
    result = make_orchestrator(
        tmp_path,
        bundle_prefix="runs/test-123",
    ).run()
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
                "payloads": None,
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
        self.calls[-1]["payloads"] = payloads
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
    paths = resolve_current_generation(tmp_path / "bundle")
    uploaded = storage.calls[0]["payloads"]
    assert uploaded["runs/test-123/manifest.json"] == paths.manifest_path.read_bytes()
    assert uploaded["runs/test-123/manifest.sig"] == paths.signature_path.read_bytes()
    for name in ARTIFACT_NAMES:
        assert uploaded[f"runs/test-123/artifacts/{name}"] == (
            paths.artifacts_root / name
        ).read_bytes()
    # The upload used staging paths, which are renamed during publication.
    assert ".staging-" in str(storage.calls[0]["manifest_path"])
    assert not storage.calls[0]["manifest_path"].exists()
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
    trust["keys"][0]["allowed_sources"] = [
        "github-actions-claimed",
    ]
    trust_path.write_text(
        json.dumps(trust),
        encoding="utf-8",
    )
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
        Path(result.data["manifest_path"]).read_text(
            encoding="utf-8"
        )
    )
    assert manifest["schema_version"] == "1.3"
    assert manifest["provenance"]["stream_id"] == "terraform-production"
    assert manifest["provenance"]["run_number"] == "42"
    assert manifest["provenance"]["run_attempt"] == "1"
    assert manifest["provenance"]["terraform_version"] == "1.9.0"


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
        "workflow_ref": (
            "example-org/example-repo/"
            ".github/workflows/ci.yml@refs/heads/main"
        ),
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
    stage_root = resolve_current_generation(tmp_path / "bundle").artifacts_root
    assert Path(result.data["receipt"]["artifacts_root"]) == stage_root
    # Source artifacts must remain unchanged.
    assert (root / "plan.json").read_bytes() == original_plan
    assert (root / "state.json").read_bytes() == original_state
    staged_plan = (stage_root / "plan.json").read_bytes()
    staged_state = (stage_root / "state.json").read_bytes()
    assert b"PLAN-CANARY-SECRET" not in staged_plan
    assert b"STATE-CANARY-SECRET" not in staged_state
    assert b"PLAN-CANARY-SECRET" in original_plan
    assert b"STATE-CANARY-SECRET" in original_state
    manifest = json.loads(
        resolve_current_generation(tmp_path / "bundle").manifest_path.read_text(
            encoding="utf-8"
        )
    )
    artifacts = {
        item["name"]: item
        for item in manifest["artifacts"]
    }
    for name in ("plan.json", "state.json"):
        assert artifacts[name]["representation"] == "sanitized"
        assert artifacts[name]["sanitization_rule_version"] == "1.1"
    for name in (
        "plan.json",
        "state.json",
        "commit.txt",
        "version.txt",
    ):
        retained = (stage_root / name).read_bytes()
        assert artifacts[name]["sha256"] == hashlib.sha256(
            retained
        ).hexdigest()
    assert "artifact-sanitization" in result.audit["stages"]


def test_manifest_uses_terraform_version_from_staged_artifacts(
    tmp_path: Path,
):
    prepare_signing_and_trust(tmp_path)
    root = make_artifacts(tmp_path / "source-artifacts")
    _write_valid_terraform_json(root)
    # Deliberately supply an incorrect version. The staged artifacts
    # must be the source of truth for manifest Terraform provenance.
    provenance = {
        **PROVENANCE,
        "terraform_version": "0.0.0",
    }
    result = make_orchestrator(
        tmp_path,
        root=root,
        provenance=provenance,
        artifact_metadata=_sanitized_artifact_metadata(),
    ).run()
    assert result.success is True
    manifest = json.loads(
        resolve_current_generation(tmp_path / "bundle").manifest_path.read_text(
            encoding="utf-8"
        )
    )
    assert manifest["provenance"]["terraform_version"] == "1.9.0"
    # The orchestrator must not mutate caller-owned provenance.
    assert provenance["terraform_version"] == "0.0.0"


def test_orchestrator_rejects_plan_state_terraform_version_mismatch(
    tmp_path: Path,
):
    prepare_signing_and_trust(tmp_path)
    root = make_artifacts(tmp_path / "source-artifacts")
    _write_valid_terraform_json(root)
    state_path = root / "state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["terraform_version"] = "1.8.0"
    state_path.write_text(
        json.dumps(state),
        encoding="utf-8",
    )
    result = make_orchestrator(
        tmp_path,
        root=root,
        artifact_metadata=_sanitized_artifact_metadata(),
    ).run()
    assert result.success is False
    assert result.error == "artifact-sanitization-failed"
    assert result.audit["stage"] == "artifact-sanitization"
    assert not (tmp_path / "bundle" / "CURRENT").exists()


def test_orchestrator_fails_closed_on_invalid_sanitized_terraform_json(
    tmp_path: Path,
):
    prepare_signing_and_trust(tmp_path)
    root = make_artifacts(tmp_path / "source-artifacts")
    (root / "plan.json").write_text(
        "not valid JSON",
        encoding="utf-8",
    )
    result = make_orchestrator(
        tmp_path,
        root=root,
        artifact_metadata=_sanitized_artifact_metadata(),
    ).run()
    assert result.success is False
    assert result.error == "artifact-sanitization-failed"
    assert result.audit["stage"] == "artifact-sanitization"
    assert not (tmp_path / "bundle" / "CURRENT").exists()


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
    assert not (tmp_path / "bundle" / "CURRENT").exists()


def test_github_actions_rejects_sample_terraform_artifacts_before_signing(
    tmp_path: Path,
):
    prepare_signing_and_trust(tmp_path)
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
    result = make_orchestrator(
        tmp_path,
        provenance=provenance,
        artifact_metadata=sample_artifact_metadata(),
    ).run()
    assert result.success is False
    assert result.error == "artifact-sanitization-failed"
    assert result.audit["stage"] == "artifact-sanitization"
    assert not (tmp_path / "bundle" / "CURRENT").exists()


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
    assert not (tmp_path / "bundle" / "CURRENT").exists()


@pytest.mark.parametrize(
    "symlink_target",
    ["artifacts_root", "output_dir"],
)


def test_orchestrator_rejects_symlinked_root(
    tmp_path,
    monkeypatch,
    symlink_target,
):
    from pathlib import Path
    from evidence_engine.agents.orchestrator import Orchestrator
    artifacts_root = tmp_path / "artifacts"
    artifacts_root.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    link = tmp_path / f"{symlink_target}-link"
    target = (
        artifacts_root
        if symlink_target == "artifacts_root"
        else output_dir
    )
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"Symlinks unavailable: {exc}")
    if symlink_target == "artifacts_root":
        artifacts_root_arg = link
        output_dir_arg = tmp_path / "new-output"
    else:
        artifacts_root_arg = artifacts_root
        output_dir_arg = link
    orchestrator = Orchestrator(
        artifacts_root=Path(artifacts_root_arg),
        output_dir=Path(output_dir_arg),
        provenance={"source": "local-claimed"},
        trust_registry_path=tmp_path / "trust-registry.json",
        signing_mode="local",
        private_key=tmp_path / "private.pem",
    )
    result = orchestrator.run()
    assert not result.success
    expected_error = (
        "artifacts-root-symlink"
        if symlink_target == "artifacts_root"
        else "output-directory-symlink"
    )
    assert result.error == expected_error


def test_orchestrator_rejects_output_inside_resolved_artifacts_root(
    tmp_path,
):
    from evidence_engine.agents.orchestrator import Orchestrator
    artifacts_root = tmp_path / "artifacts"
    artifacts_root.mkdir()
    output_dir = artifacts_root / "output"
    orchestrator = Orchestrator(
        artifacts_root=artifacts_root,
        output_dir=output_dir,
        provenance={"source": "local-claimed"},
        trust_registry_path=tmp_path / "trust-registry.json",
        signing_mode="local",
        private_key=tmp_path / "private.pem",
    )
    result = orchestrator.run()
    assert not result.success
    assert result.error == "output-inside-artifacts-root"


@pytest.mark.parametrize("failure_stage", ["signing", "receipt", "s3-upload"])
def test_failed_republication_preserves_current_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str,
):
    prepare_signing_and_trust(tmp_path)
    bundle = tmp_path / "bundle"
    root = make_artifacts(tmp_path / "source-artifacts")
    _write_valid_terraform_json(root)
    metadata = _sanitized_artifact_metadata()

    first = make_orchestrator(
        tmp_path, root=root, output=bundle, artifact_metadata=metadata,
    ).run()
    assert first.success is True
    original_pointer = (bundle / "CURRENT").read_bytes()
    original_paths = resolve_current_generation(bundle)
    original_manifest = original_paths.manifest_path.read_bytes()
    original_signature = original_paths.signature_path.read_bytes()
    original_artifacts = {
        name: (original_paths.artifacts_root / name).read_bytes()
        for name in ARTIFACT_NAMES
    }

    if failure_stage == "signing":
        class FailedSigningAgent:
            def __init__(self, **kwargs):
                pass

            def run(self):
                return AgentResult(False, None, "test-signing-failure", {})

        monkeypatch.setattr(
            "evidence_engine.agents.orchestrator.SigningAgent",
            FailedSigningAgent,
        )
        options = {}
        expected_error = "test-signing-failure"
    elif failure_stage == "receipt":
        class FailedReceiptAgent:
            def __init__(self, **kwargs):
                pass

            def run(self):
                return AgentResult(False, None, "test-receipt-failure", {})

        monkeypatch.setattr(
            "evidence_engine.agents.orchestrator.ReceiptAgent",
            FailedReceiptAgent,
        )
        options = {}
        expected_error = "test-receipt-failure"
    else:
        class FailedStorage:
            def upload_bundle(self, **kwargs):
                raise RuntimeError("simulated S3 failure")

        options = {
            "bundle_storage": FailedStorage(),
            "bundle_prefix": "runs/republication-failure",
            "require_remote_storage": True,
        }
        expected_error = "bundle-upload-failed"

    second = make_orchestrator(
        tmp_path,
        root=root,
        output=bundle,
        artifact_metadata=metadata,
        **options,
    ).run()
    assert second.success is False
    assert second.error == expected_error
    assert (bundle / "CURRENT").read_bytes() == original_pointer
    assert resolve_current_generation(bundle) == original_paths
    assert original_paths.manifest_path.read_bytes() == original_manifest
    assert original_paths.signature_path.read_bytes() == original_signature
    for name, content in original_artifacts.items():
        assert (original_paths.artifacts_root / name).read_bytes() == content
    assert not any(
        p.name.startswith(".staging-")
        for p in (bundle / "generations").iterdir()
    )


def test_successful_republication_retains_prior_generation(tmp_path: Path):
    prepare_signing_and_trust(tmp_path)
    root = make_artifacts(tmp_path / "artifacts")
    bundle = tmp_path / "bundle"
    first = make_orchestrator(tmp_path, root=root, output=bundle).run()
    assert first.success is True
    first_paths = resolve_current_generation(bundle)
    first_manifest = first_paths.manifest_path.read_bytes()
    (root / "commit.txt").write_text("new commit\n", encoding="utf-8")

    second = make_orchestrator(tmp_path, root=root, output=bundle).run()
    assert second.success is True
    second_paths = resolve_current_generation(bundle)
    assert second_paths.generation_id != first_paths.generation_id
    assert first_paths.manifest_path.read_bytes() == first_manifest
    assert first_paths.signature_path.is_file()
    assert (first_paths.artifacts_root / "commit.txt").read_text(
        encoding="utf-8"
    ) != (second_paths.artifacts_root / "commit.txt").read_text(
        encoding="utf-8"
    )
    assert Path(second.data["manifest_path"]) == second_paths.manifest_path


def test_s3_upload_success_local_publication_failure_preserves_current(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """A remote upload may succeed even when local publication fails."""
    prepare_signing_and_trust(tmp_path)

    root = make_artifacts(tmp_path / "source-artifacts")
    _write_valid_terraform_json(root)

    bundle = tmp_path / "bundle"
    metadata = _sanitized_artifact_metadata()

    # Establish the previously committed local generation.
    first = make_orchestrator(
        tmp_path,
        root=root,
        output=bundle,
        artifact_metadata=metadata,
    ).run()

    assert first.success is True

    previous = resolve_current_generation(bundle)
    original_pointer = (bundle / "CURRENT").read_bytes()

    storage = FakeBundleStorage()

    def fail_local_publication(paths):
        raise OSError("Simulated local publication failure")

    monkeypatch.setattr(
        "evidence_engine.agents.orchestrator.publish_generation",
        fail_local_publication,
    )

    second = make_orchestrator(
        tmp_path,
        root=root,
        output=bundle,
        bundle_storage=storage,
        bundle_prefix="runs/remote-before-local-failure",
        require_remote_storage=True,
        artifact_metadata=metadata,
    ).run()

    # The remote upload completed before local publication was attempted.
    assert len(storage.calls) == 1
    assert storage.calls[0]["payloads"]

    # The orchestrator must not report overall success.
    assert second.success is False
    assert second.error == "bundle-publication-failed"
    assert second.audit["stage"] == "bundle-publication"
    assert second.audit["exception_type"] == "OSError"

    # The previously committed local generation remains selected.
    assert (bundle / "CURRENT").read_bytes() == original_pointer
    assert resolve_current_generation(bundle) == previous

    # Failed staging must be cleaned up.
    assert not any(
        path.name.startswith(".staging-")
        for path in (bundle / "generations").iterdir()
    )