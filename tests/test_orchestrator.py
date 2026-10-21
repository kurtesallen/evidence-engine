from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

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
