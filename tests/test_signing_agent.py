
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from evidence_engine.agents.signing import SigningAgent
from evidence_engine.canonical import canonical_json_bytes
from evidence_engine.sanitization import TERRAFORM_JSON_CONTENT_RULE_VERSION
from evidence_engine.signing import KEY_ID


def write_valid_manifest(
    path: Path,
    plan_representation: str = "raw",
    state_representation: str = "raw",
) -> None:
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
                "representation": (
                    plan_representation
                    if name == "plan.json"
                    else state_representation
                    if name == "state.json"
                    else "raw"
                ),
                "sanitization_rule_version": (
                    TERRAFORM_JSON_CONTENT_RULE_VERSION
                    if name in ("plan.json", "state.json")
                    and (
                        plan_representation
                        if name == "plan.json"
                        else state_representation
                    ) == "sanitized"
                    else None
                ),
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

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    private_key = tmp_path / "key.pem"
    private_key.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

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


def test_signing_agent_rejects_mixed_representations_before_local_signing(
    tmp_path: Path,
    monkeypatch,
):
    manifest = tmp_path / "manifest.json"
    write_valid_manifest(
        manifest,
        plan_representation="raw",
        state_representation="sample",
    )

    signing_called = False

    def unexpected_sign(*args, **kwargs):
        nonlocal signing_called
        signing_called = True
        raise AssertionError("Local signing must not be called")

    monkeypatch.setattr(
        "evidence_engine.agents.signing.local_sign_bytes",
        unexpected_sign,
    )

    agent = SigningAgent(
        manifest_path=manifest,
        signing_mode="local",
        private_key=tmp_path / "key.pem",
    )

    result = agent.run()

    assert result.success is False
    assert result.error is not None
    assert signing_called is False


def test_signing_agent_rejects_mixed_representations_before_kms_signing(
    tmp_path: Path,
    monkeypatch,
):
    manifest = tmp_path / "manifest.json"
    write_valid_manifest(
        manifest,
        plan_representation="raw",
        state_representation="sample",
    )

    kms_called = False

    def unexpected_kms_call(*args, **kwargs):
        nonlocal kms_called
        kms_called = True
        raise AssertionError("KMS signing must not be called")

    monkeypatch.setattr(
        "evidence_engine.kms_signing.create_kms_client",
        unexpected_kms_call,
    )
    monkeypatch.setattr(
        "evidence_engine.kms_signing.sign_bytes",
        unexpected_kms_call,
    )

    agent = SigningAgent(
        manifest_path=manifest,
        signing_mode="kms",
        kms_key_id="kms-key",
    )

    result = agent.run()

    assert result.success is False
    assert result.error is not None
    assert kms_called is False


def test_signing_agent_accepts_sanitized_manifest_for_local_signing(
    tmp_path: Path,
):
    manifest = tmp_path / "manifest.json"
    write_valid_manifest(
        manifest,
        plan_representation="sanitized",
        state_representation="sanitized",
    )

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    private_key = tmp_path / "key.pem"
    private_key.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    agent = SigningAgent(
        manifest_path=manifest,
        signing_mode="local",
        private_key=private_key,
    )

    result = agent.run()

    assert result.success is True
    assert result.error is None
    assert result.data["mode"] == "local"
    assert isinstance(result.data["signature"], bytes)


def test_signing_agent_accepts_sanitized_manifest_for_kms_signing(
    tmp_path: Path,
    monkeypatch,
):
    manifest = tmp_path / "manifest.json"
    write_valid_manifest(
        manifest,
        plan_representation="sanitized",
        state_representation="sanitized",
    )

    monkeypatch.setattr(
        "evidence_engine.kms_signing.create_kms_client",
        lambda region: "client",
    )
    monkeypatch.setattr(
        "evidence_engine.kms_signing.sign_bytes",
        lambda client, key_id, data: b"sanitized-signature",
    )

    agent = SigningAgent(
        manifest_path=manifest,
        signing_mode="kms",
        kms_key_id="kms-key",
    )

    result = agent.run()

    assert result.success is True
    assert result.error is None
    assert result.data["mode"] == "kms"
    assert result.data["signature"] == b"sanitized-signature"



def test_signing_agent_fails_closed_on_policy_exception_before_local_signing(
    tmp_path: Path,
    monkeypatch,
):
    manifest = tmp_path / "manifest.json"
    write_valid_manifest(manifest)

    signing_called = False

    def unexpected_sign(*args, **kwargs):
        nonlocal signing_called
        signing_called = True
        raise AssertionError("Local signing must not be called")

    def policy_failure(*args, **kwargs):
        raise RuntimeError("policy evaluation failed")

    monkeypatch.setattr(
        "evidence_engine.agents.signing.local_sign_bytes",
        unexpected_sign,
    )

    agent = SigningAgent(
        manifest_path=manifest,
        signing_mode="local",
        private_key=tmp_path / "key.pem",
    )
    monkeypatch.setattr(
        agent._policy_engine,
        "evaluate_integrity",
        policy_failure,
    )

    result = agent.run()

    assert result.success is False
    assert result.error == "integrity-policy-evaluation-failed"
    assert signing_called is False


def test_signing_agent_fails_closed_on_policy_exception_before_kms_signing(
    tmp_path: Path,
    monkeypatch,
):
    manifest = tmp_path / "manifest.json"
    write_valid_manifest(manifest)

    kms_called = False

    def unexpected_kms_call(*args, **kwargs):
        nonlocal kms_called
        kms_called = True
        raise AssertionError("KMS must not be called")

    def policy_failure(*args, **kwargs):
        raise RuntimeError("policy evaluation failed")

    monkeypatch.setattr(
        "evidence_engine.agents.signing.kms.create_kms_client",
        unexpected_kms_call,
    )
    monkeypatch.setattr(
        "evidence_engine.agents.signing.kms.sign_bytes",
        unexpected_kms_call,
    )

    agent = SigningAgent(
        manifest_path=manifest,
        signing_mode="kms",
        kms_key_id="kms-key",
    )
    monkeypatch.setattr(
        agent._policy_engine,
        "evaluate_integrity",
        policy_failure,
    )

    result = agent.run()

    assert result.success is False
    assert result.error == "integrity-policy-evaluation-failed"
    assert kms_called is False


def test_signing_agent_rejects_explicit_policy_denial_before_local_signing(
    tmp_path: Path,
    monkeypatch,
):
    manifest = tmp_path / "manifest.json"
    write_valid_manifest(manifest)

    signing_called = False

    def unexpected_sign(*args, **kwargs):
        nonlocal signing_called
        signing_called = True
        raise AssertionError("Local signing must not be called")

    monkeypatch.setattr(
        "evidence_engine.agents.signing.local_sign_bytes",
        unexpected_sign,
    )

    agent = SigningAgent(
        manifest_path=manifest,
        signing_mode="local",
        private_key=tmp_path / "key.pem",
    )

    from evidence_engine.policy import PolicyDecision

    monkeypatch.setattr(
        agent._policy_engine,
        "evaluate_integrity",
        lambda **kwargs: PolicyDecision(
            allowed=False,
            reason="integrity-policy-denied",
            details={"reason": "test denial"},
        ),
    )

    result = agent.run()

    assert result.success is False
    assert result.error == "integrity-policy-denied"
    assert signing_called is False
