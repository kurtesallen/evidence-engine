
from pathlib import Path

import pytest

from scripts.e2e_synthetic_aws import (
    TRUST_REGISTRY,
    TRUST_REGISTRY_ENV,
    configured_trust_registry,
)


def test_consumer_registry_defaults_to_repository_registry(monkeypatch):
    monkeypatch.delenv(TRUST_REGISTRY_ENV, raising=False)

    assert configured_trust_registry() == TRUST_REGISTRY


def test_consumer_registry_accepts_absolute_override(
    monkeypatch,
    tmp_path: Path,
):
    registry = tmp_path / "trust" / "registry.json"
    monkeypatch.setenv(TRUST_REGISTRY_ENV, str(registry))

    assert configured_trust_registry() == registry


@pytest.mark.parametrize("value", ["", " ", "\t"])
def test_consumer_registry_rejects_empty_override(monkeypatch, value):
    monkeypatch.setenv(TRUST_REGISTRY_ENV, value)

    with pytest.raises(ValueError, match="must not be empty"):
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
