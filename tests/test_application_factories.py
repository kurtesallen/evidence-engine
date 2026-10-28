"""Tests for application-level producer and consumer construction."""

from pathlib import Path

import pytest

import evidence_engine.agents.consumer_factory as consumer_factory
import evidence_engine.agents.producer_factory as producer_factory
from evidence_engine.aws.config import BACKEND_ENV
from evidence_engine.aws.storage import S3BundleStorage
from evidence_engine.aws.storage_config import BUCKET_ENV, KMS_KEY_ID_ENV


class FakeS3Client:
    def put_object(self, **kwargs):
        return {}

    def get_object(self, **kwargs):
        return {}


def test_create_producer_configures_required_s3_storage(monkeypatch):
    captured = {}

    class FakeOrchestrator:
        def __init__(self, *args, **kwargs):
            captured["args"] = args
            captured["kwargs"] = kwargs

    monkeypatch.setattr(
        producer_factory,
        "Orchestrator",
        FakeOrchestrator,
    )

    client = FakeS3Client()
    producer_factory.create_producer(
        Path("artifacts"),
        bundle_prefix="evidence/ci",
        environ={
            BUCKET_ENV: "test-evidence-bucket",
            KMS_KEY_ID_ENV: "alias/test-evidence-key",
        },
        s3_client=client,
    )

    options = captured["kwargs"]

    assert captured["args"] == (Path("artifacts"),)
    assert isinstance(options["bundle_storage"], S3BundleStorage)
    assert options["bundle_prefix"] == "evidence/ci"
    assert options["require_remote_storage"] is True


def test_create_producer_fails_without_s3_configuration(monkeypatch):
    def unexpected_construction(*args, **kwargs):
        pytest.fail(
            "Producer must not be constructed without S3 configuration"
        )

    monkeypatch.setattr(
        producer_factory,
        "Orchestrator",
        unexpected_construction,
    )

    with pytest.raises(ValueError, match=BUCKET_ENV):
        producer_factory.create_producer(
            Path("artifacts"),
            bundle_prefix="evidence/ci",
            environ={},
        )


def test_create_producer_rejects_overridden_storage_policy():
    with pytest.raises(ValueError, match="bundle_storage"):
        producer_factory.create_producer(
            Path("artifacts"),
            bundle_prefix="evidence/ci",
            bundle_storage=object(),
        )


def test_create_consumer_configures_s3_when_requested(
    tmp_path,
    monkeypatch,
):
    storage = object()
    captured = {}

    def fake_create_s3_bundle_storage(**kwargs):
        captured.update(kwargs)
        return storage

    class FakeConsumerAgent:
        def __init__(self, *args, **kwargs):
            self.args = args
            self.kwargs = kwargs

    monkeypatch.setattr(
        consumer_factory,
        "create_s3_bundle_storage",
        fake_create_s3_bundle_storage,
    )
    monkeypatch.setattr(
        consumer_factory,
        "ConsumerAgent",
        FakeConsumerAgent,
    )

    s3_client = FakeS3Client()
    trust_path = tmp_path / "trusted-keys.json"

    consumer = consumer_factory.create_consumer(
        tmp_path,
        environ={BACKEND_ENV: "memory"},
        configure_remote_storage=True,
        require_remote_bundle=True,
        s3_client=s3_client,
        trust_registry_path=trust_path,
    )

    assert captured["client"] is s3_client
    assert consumer.kwargs["bundle_storage"] is storage
    assert consumer.kwargs["trust_registry_path"] == trust_path
    assert consumer.kwargs["require_remote_bundle"] is True


def test_create_consumer_requires_trust_registry_for_remote_storage(
    tmp_path,
):
    with pytest.raises(ValueError, match="trust_registry_path"):
        consumer_factory.create_consumer(
            tmp_path,
            environ={BACKEND_ENV: "memory"},
            configure_remote_storage=True,
        )


def test_create_consumer_requires_trust_registry_when_remote_bundle_required(
    tmp_path,
):
    with pytest.raises(ValueError, match="trust_registry_path"):
        consumer_factory.create_consumer(
            tmp_path,
            environ={BACKEND_ENV: "memory"},
            require_remote_bundle=True,
        )


def test_create_consumer_requires_storage_when_remote_bundle_required(
    tmp_path,
):
    with pytest.raises(
        ValueError,
        match="bundle_storage or configure_remote_storage",
    ):
        consumer_factory.create_consumer(
            tmp_path,
            environ={BACKEND_ENV: "memory"},
            require_remote_bundle=True,
            trust_registry_path=tmp_path / "trusted-keys.json",
        )


def test_create_consumer_rejects_unused_s3_client_arguments(tmp_path):
    with pytest.raises(ValueError, match="configure_remote_storage"):
        consumer_factory.create_consumer(
            tmp_path,
            environ={BACKEND_ENV: "memory"},
            s3_client=FakeS3Client(),
        )