from __future__ import annotations

import pytest

from evidence_engine.aws.storage_config import AWS_DEFAULT_REGION_ENV
from evidence_engine.aws.storage_config import (
    AWS_REGION_ENV,
    BUCKET_ENV,
    KMS_KEY_ID_ENV,
    create_s3_bundle_storage,
)


class FakeS3Client:
    def put_object(self, **kwargs):
        return {"VersionId": "test-version"}

    def get_object(self, **kwargs):
        raise NotImplementedError


@pytest.fixture
def settings():
    return {
        BUCKET_ENV: "evidence-test-bucket",
        KMS_KEY_ID_ENV: "test-s3-encryption-key",
    }


def test_factory_constructs_storage_with_injected_client(settings):
    client = FakeS3Client()

    storage = create_s3_bundle_storage(
        environ=settings,
        client=client,
    )

    assert storage._client is client
    assert storage._bucket == "evidence-test-bucket"
    assert storage._kms_key_id == "test-s3-encryption-key"


@pytest.mark.parametrize(
    ("variable", "message"),
    [
        (BUCKET_ENV, BUCKET_ENV),
        (KMS_KEY_ID_ENV, KMS_KEY_ID_ENV),
    ],
)
def test_factory_requires_explicit_s3_configuration(
    settings, variable, message
):
    settings.pop(variable)

    with pytest.raises(ValueError, match=message):
        create_s3_bundle_storage(
            environ=settings,
            client=FakeS3Client(),
        )


def test_factory_uses_aws_region_when_configured(settings):
    settings[AWS_REGION_ENV] = "us-west-2"
    settings[AWS_DEFAULT_REGION_ENV] = "us-east-1"
    calls = []
    client = FakeS3Client()

    def factory(service, **kwargs):
        calls.append((service, kwargs))
        return client

    storage = create_s3_bundle_storage(
        environ=settings,
        client_factory=factory,
    )

    assert storage._client is client
    assert calls == [
        ("s3", {"region_name": "us-west-2"}),
    ]


def test_factory_falls_back_to_aws_default_region(settings):
    settings[AWS_DEFAULT_REGION_ENV] = "us-east-2"
    calls = []
    client = FakeS3Client()

    def factory(service, **kwargs):
        calls.append((service, kwargs))
        return client

    create_s3_bundle_storage(
        environ=settings,
        client_factory=factory,
    )

    assert calls == [
        ("s3", {"region_name": "us-east-2"}),
    ]


def test_factory_uses_client_default_region_if_unset(settings):
    calls = []
    client = FakeS3Client()

    def factory(service, **kwargs):
        calls.append((service, kwargs))
        return client

    create_s3_bundle_storage(
        environ=settings,
        client_factory=factory,
    )

    assert calls == [("s3", {})]


def test_factory_rejects_client_and_factory_together(settings):
    with pytest.raises(ValueError, match="both"):
        create_s3_bundle_storage(
            environ=settings,
            client=FakeS3Client(),
            client_factory=lambda *args, **kwargs: FakeS3Client(),
        )


def test_factory_propagates_client_creation_errors(settings):
    def broken_factory(*args, **kwargs):
        raise RuntimeError("simulated S3 client creation failure")

    with pytest.raises(RuntimeError, match="client creation failure"):
        create_s3_bundle_storage(
            environ=settings,
            client_factory=broken_factory,
        )


def test_factory_rejects_client_without_required_methods(settings):
    with pytest.raises(TypeError, match="put_object"):
        create_s3_bundle_storage(
            environ=settings,
            client=object(),
        )