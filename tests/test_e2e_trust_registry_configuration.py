
from pathlib import Path

import pytest

from scripts.e2e_synthetic_aws import (
    TRUST_REGISTRY_ENV,
    configured_trust_registry,
)

def test_registry_requires_explicit_configuration(monkeypatch):
    """Missing configuration must never select repository trust."""

    monkeypatch.delenv(
        TRUST_REGISTRY_ENV,
        raising=False,
    )

    with pytest.raises(
        ValueError,
        match=TRUST_REGISTRY_ENV,
    ):
        configured_trust_registry()


def test_consumer_registry_accepts_absolute_override(
    monkeypatch,
    tmp_path: Path,
):
    registry = tmp_path / "trust" / "registry.json"
    monkeypatch.setenv(TRUST_REGISTRY_ENV, str(registry))

    assert configured_trust_registry() == registry


@pytest.mark.parametrize("value", ["", " ", "\t"])
def test_consumer_registry_rejects_empty_override(
    monkeypatch,
    value,
):
    monkeypatch.setenv(TRUST_REGISTRY_ENV, value)

    with pytest.raises(
        ValueError,
        match="must not be empty",
    ):
        configured_trust_registry()


def test_consumer_registry_rejects_relative_override(monkeypatch):
    monkeypatch.setenv(
        TRUST_REGISTRY_ENV,
        "trust/registry.json",
    )

    with pytest.raises(ValueError, match="absolute path"):
        configured_trust_registry()


def test_consume_propagates_configured_registry(
    monkeypatch,
    tmp_path: Path,
):
    import json
    from types import SimpleNamespace

    from scripts import e2e_synthetic_aws as e2e

    registry = tmp_path / "trust" / "registry.json"
    reference = tmp_path / "bundle-reference.json"
    payload = {"bundle_reference": {}}
    reference.write_text(json.dumps(payload), encoding="utf-8")

    monkeypatch.setenv(TRUST_REGISTRY_ENV, str(registry))

    for name in (
        "AWS_REGION",
        "EVIDENCE_ENGINE_S3_BUCKET",
        "EVIDENCE_ENGINE_S3_KMS_KEY_ID",
        "EVIDENCE_ENGINE_SIGNING_KEY_ID",
        "EVIDENCE_ENGINE_CONSUMER_ID",
        "EVIDENCE_ENGINE_EXPECTED_STREAM_ID",
    ):
        monkeypatch.setenv(name, "test-value")

    monkeypatch.setattr(e2e, "REFERENCE_FILE", reference)

    captured = {}
    calls = []

    class FakeConsumer:
        def run(self, received_payload):
            calls.append(received_payload)

            if len(calls) == 1:
                return SimpleNamespace(
                    success=True,
                    error=None,
                    data={"verified": True},
                    audit={"bundle_digest": "test-digest"},
                )

            return SimpleNamespace(
                success=False,
                error="bundle-replay-detected",
                data={},
                audit={},
            )

    def fake_create_consumer(**kwargs):
        captured["factory"] = kwargs
        return FakeConsumer()

    def fake_negative_paths(
        received_payload,
        consumer,
        expected_key_id,
        trust_registry,
    ):
        captured["negative_registry"] = trust_registry
        captured["negative_key_id"] = expected_key_id
        assert received_payload == payload

    monkeypatch.setattr(e2e, "create_consumer", fake_create_consumer)
    monkeypatch.setattr(e2e, "assert_negative_paths", fake_negative_paths)
    monkeypatch.setattr(
        e2e,
        "assert_dynamodb_rollback_protection",
        lambda: None,
    )
    monkeypatch.setattr(
        e2e,
        "assert_dynamodb_concurrent_acceptance",
        lambda: None,
    )

    e2e.consume()

    assert captured["factory"]["trust_registry_path"] == registry
    assert captured["factory"]["expected_source"] == "github-actions-claimed"
    assert captured["factory"]["expected_key_id"] == "test-value"
    assert captured["negative_registry"] == registry
    assert captured["negative_key_id"] == "test-value"
    assert calls == [payload, payload]


@pytest.mark.parametrize(
    "value",
    [None, "", " ", "\t", "trust/registry.json"],
)
def test_consume_rejects_invalid_override_before_factory(
    monkeypatch,
    value,
):
    """Invalid explicit configuration must not reach consumer creation."""
    from scripts import e2e_synthetic_aws as e2e

    for name in (
        "AWS_REGION",
        "EVIDENCE_ENGINE_S3_BUCKET",
        "EVIDENCE_ENGINE_S3_KMS_KEY_ID",
        "EVIDENCE_ENGINE_SIGNING_KEY_ID",
        "EVIDENCE_ENGINE_CONSUMER_ID",
        "EVIDENCE_ENGINE_EXPECTED_STREAM_ID",
    ):
        monkeypatch.setenv(name, "test-value")

    if value is None:
        monkeypatch.delenv(
            TRUST_REGISTRY_ENV,
            raising=False,
        )
    else:
        monkeypatch.setenv(
            TRUST_REGISTRY_ENV,
            value,
        )

    def unexpected_call(*args, **kwargs):
        pytest.fail(
            "Invalid trust configuration reached consumer execution"
        )

    monkeypatch.setattr(
        e2e,
        "create_consumer",
        unexpected_call,
    )
    monkeypatch.setattr(
        e2e,
        "assert_negative_paths",
        unexpected_call,
    )
    monkeypatch.setattr(
        e2e,
        "assert_dynamodb_rollback_protection",
        unexpected_call,
    )
    monkeypatch.setattr(
        e2e,
        "assert_dynamodb_concurrent_acceptance",
        unexpected_call,
    )

    with pytest.raises(ValueError, match=TRUST_REGISTRY_ENV):
        e2e.consume()


@pytest.mark.parametrize(
    "registry_kind",
    ["missing", "malformed", "directory"],
)
def test_invalid_absolute_override_never_selects_default(
    monkeypatch,
    tmp_path: Path,
    registry_kind,
):
    """An invalid absolute override must never select the default."""
    from scripts import e2e_synthetic_aws as e2e

    repository_root = tmp_path / "repository"
    default_registry = repository_root / "trust" / "registry.json"
    default_registry.parent.mkdir(parents=True)
    default_registry.write_text(
        '{"schema_version":"1.0","keys":[]}',
        encoding="utf-8",
    )

    monkeypatch.setattr(
        e2e,
        "ROOT",
        repository_root,
    )

    configured_registry = tmp_path / "configured" / "registry.json"
    configured_registry.parent.mkdir()

    if registry_kind == "malformed":
        configured_registry.write_text(
            "{invalid-json",
            encoding="utf-8",
        )
    elif registry_kind == "directory":
        configured_registry.mkdir()

    monkeypatch.setenv(
        TRUST_REGISTRY_ENV,
        str(configured_registry),
    )

    selected = configured_trust_registry()

    assert selected == configured_registry
    assert selected != default_registry


def test_registry_rejects_absolute_parent_traversal(
    monkeypatch,
    tmp_path: Path,
):
    """Absolute paths must not contain parent traversal."""

    registry = (
        tmp_path
        / "trust"
        / ".."
        / "outside"
        / "registry.json"
    )

    monkeypatch.setenv(
        TRUST_REGISTRY_ENV,
        str(registry),
    )

    with pytest.raises(
        ValueError,
        match="parent traversal",
    ):
        configured_trust_registry()


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        " ",
        "\t",
        "trust/registry.json",
    ],
)
def test_produce_rejects_invalid_registry_before_execution(
    monkeypatch,
    value,
):
    """Invalid trust configuration must block producer execution."""

    from scripts import e2e_synthetic_aws as e2e

    if value is None:
        monkeypatch.delenv(
            TRUST_REGISTRY_ENV,
            raising=False,
        )
    else:
        monkeypatch.setenv(
            TRUST_REGISTRY_ENV,
            value,
        )

    def unexpected_call(*args, **kwargs):
        pytest.fail(
            "Invalid trust configuration reached "
            "producer execution"
        )

    monkeypatch.setattr(
        e2e,
        "capture_and_check_ci_context",
        unexpected_call,
    )

    monkeypatch.setattr(
        e2e,
        "create_producer",
        unexpected_call,
    )

    with pytest.raises(
        ValueError,
        match=TRUST_REGISTRY_ENV,
    ):
        e2e.produce()


@pytest.mark.parametrize(
    "mode",
    ["produce", "consume"],
)
def test_execution_rejects_registry_parent_traversal(
    monkeypatch,
    tmp_path: Path,
    mode,
):
    """Neither execution mode may accept parent traversal."""

    from scripts import e2e_synthetic_aws as e2e

    registry = (
        tmp_path
        / "trust"
        / ".."
        / "outside"
        / "registry.json"
    )

    monkeypatch.setenv(
        TRUST_REGISTRY_ENV,
        str(registry),
    )

    for name in (
        "AWS_REGION",
        "EVIDENCE_ENGINE_S3_BUCKET",
        "EVIDENCE_ENGINE_S3_KMS_KEY_ID",
        "EVIDENCE_ENGINE_SIGNING_KEY_ID",
        "EVIDENCE_ENGINE_CONSUMER_ID",
        "EVIDENCE_ENGINE_EXPECTED_STREAM_ID",
    ):
        monkeypatch.setenv(name, "test-value")

    def unexpected_call(*args, **kwargs):
        pytest.fail(
            "Parent traversal reached evidence execution"
        )

    monkeypatch.setattr(
        e2e,
        "capture_and_check_ci_context",
        unexpected_call,
    )

    monkeypatch.setattr(
        e2e,
        "create_producer",
        unexpected_call,
    )

    monkeypatch.setattr(
        e2e,
        "create_consumer",
        unexpected_call,
    )

    execute = getattr(e2e, mode)

    with pytest.raises(
        ValueError,
        match="parent traversal",
    ):
        execute()


def test_produce_propagates_configured_registry(
    monkeypatch,
    tmp_path: Path,
):
    """The producer must use explicitly configured trust material."""

    import json
    from types import SimpleNamespace

    from scripts import e2e_synthetic_aws as e2e

    registry = tmp_path / "trust" / "registry.json"
    reference = tmp_path / "bundle-reference.json"

    artifacts = tmp_path / "published-artifacts"
    artifacts.mkdir()

    (artifacts / "plan.json").write_bytes(
        b'{"value":"[REDACTED]"}'
    )

    (artifacts / "state.json").write_bytes(
        b'{"value":"[REDACTED]"}'
    )

    monkeypatch.setenv(
        TRUST_REGISTRY_ENV,
        str(registry),
    )

    for name in (
        "AWS_REGION",
        "EVIDENCE_ENGINE_S3_BUCKET",
        "EVIDENCE_ENGINE_S3_KMS_KEY_ID",
        "EVIDENCE_ENGINE_SIGNING_KEY_ID",
    ):
        monkeypatch.setenv(name, "test-value")

    context = {
        "run_id": "12345",
        "run_attempt": "1",
        "commit_sha": "a" * 40,
    }

    provenance = {
        "source": "github-actions-claimed",
    }

    bundle_reference = {
        "test-reference": True,
    }

    receipt = {
        "signature_key_id": "test-value",
    }

    captured = {}
    calls = []

    class FakeProducer:
        def run(self):
            calls.append("produce")

            return SimpleNamespace(
                success=True,
                error=None,
                data={
                    "bundle_reference": bundle_reference,
                    "receipt": receipt,
                },
                audit={},
            )

    def fake_create_producer(**kwargs):
        captured.update(kwargs)
        return FakeProducer()

    def fake_write_artifacts(source, commit_sha):
        assert commit_sha == context["commit_sha"]
        source.mkdir()

    def fake_build_provenance(supplied_context):
        assert supplied_context == context
        return provenance

    def fake_resolve_generation(output):
        assert output == captured["output_dir"]

        return SimpleNamespace(
            artifacts_root=artifacts,
        )

    monkeypatch.setattr(
        e2e,
        "REFERENCE_FILE",
        reference,
    )

    monkeypatch.setattr(
        e2e,
        "capture_and_check_ci_context",
        lambda: context,
    )

    monkeypatch.setattr(
        e2e,
        "build_ci_provenance",
        fake_build_provenance,
    )

    monkeypatch.setattr(
        e2e,
        "write_synthetic_artifacts",
        fake_write_artifacts,
    )

    monkeypatch.setattr(
        e2e,
        "create_producer",
        fake_create_producer,
    )

    monkeypatch.setattr(
        e2e,
        "resolve_current_generation",
        fake_resolve_generation,
    )

    e2e.produce()

    assert captured["trust_registry_path"] == registry
    assert captured["signing_mode"] == "kms"
    assert captured["kms_key_id"] == "test-value"
    assert captured["aws_region"] == "test-value"
    assert captured["provenance"] == provenance

    assert captured["bundle_prefix"] == (
        "evidence-engine/integration-tests/12345/1"
    )

    assert calls == ["produce"]

    assert json.loads(
        reference.read_text(encoding="utf-8")
    ) == {
        "receipt": receipt,
        "bundle_reference": bundle_reference,
    }
