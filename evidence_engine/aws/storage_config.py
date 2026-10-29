"""Explicit configuration for S3 evidence-bundle storage."""

from __future__ import annotations

import importlib
import os
from collections.abc import Callable, Mapping
from typing import Any

from evidence_engine.aws.storage import S3BundleStorage


BUCKET_ENV = "EVIDENCE_ENGINE_S3_BUCKET"
KMS_KEY_ID_ENV = "EVIDENCE_ENGINE_S3_KMS_KEY_ID"
AWS_REGION_ENV = "AWS_REGION"
AWS_DEFAULT_REGION_ENV = "AWS_DEFAULT_REGION"


def create_s3_bundle_storage(
    *,
    environ: Mapping[str, str] | None = None,
    client: Any | None = None,
    client_factory: Callable[..., Any] | None = None,
) -> S3BundleStorage:
    """Construct S3 storage using explicit configuration.

    The S3 bucket and SSE-KMS encryption key must be configured explicitly.
    An injected client or client factory allows unit tests to run without
    AWS credentials or resources.

    If no client is supplied, boto3 is imported lazily and uses the normal
    AWS credential chain. AWS_REGION takes precedence over
    AWS_DEFAULT_REGION. If neither is set, boto3 resolves its configured
    default region.

    Configuration and client-construction errors propagate. This function
    never substitutes a different bucket, encryption key, or local backend.
    """
    settings = os.environ if environ is None else environ

    raw_bucket = settings.get(BUCKET_ENV, "")
    if not isinstance(raw_bucket, str) or not raw_bucket.strip():
        raise ValueError(f"{BUCKET_ENV} is required")

    bucket = raw_bucket.strip()

    raw_kms_key_id = settings.get(KMS_KEY_ID_ENV, "")
    if not isinstance(raw_kms_key_id, str) or not raw_kms_key_id.strip():
        raise ValueError(f"{KMS_KEY_ID_ENV} is required")

    kms_key_id = raw_kms_key_id.strip()

    if client is not None and client_factory is not None:
        raise ValueError("Provide client or client_factory, not both")

    if client is None:
        if client_factory is None:
            try:
                boto3 = importlib.import_module("boto3")
            except ImportError as exc:
                raise RuntimeError(
                    "S3 storage requires boto3; install with "
                    "'pip install -e \".[aws]\""
                ) from exc

            client_factory = boto3.client

        region = (
            settings.get(AWS_REGION_ENV, "").strip()
            or settings.get(AWS_DEFAULT_REGION_ENV, "").strip()
        )

        if region:
            client = client_factory("s3", region_name=region)
        else:
            client = client_factory("s3")

    return S3BundleStorage(
        client=client,
        bucket=bucket,
        kms_key_id=kms_key_id,
    )