"""Application-level construction for configured consumer agents."""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from evidence_engine.acceptance import AcceptanceState
from evidence_engine.agents.consumer import ConsumerAgent
from evidence_engine.aws.config import create_acceptance_state
from evidence_engine.aws.storage import S3BundleStorage
from evidence_engine.aws.storage_config import create_s3_bundle_storage


def create_consumer(
    artifacts_root: Path,
    expected_source: str | None = None,
    expected_key_id: str | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    client: Any | None = None,
    client_factory: Callable[..., Any] | None = None,
    bundle_storage: S3BundleStorage | None = None,
    trust_registry_path: Path | None = None,
    configure_remote_storage: bool = False,
    require_remote_bundle: bool = False,
    consumer_id: str | None = None,
    expected_stream_id: str | None = None,
    s3_client: Any | None = None,
    s3_client_factory: Callable[..., Any] | None = None,
) -> ConsumerAgent:
    """Construct a consumer with explicit acceptance and trust configuration.

    The acceptance backend must be explicitly configured.

    Set configure_remote_storage=True to construct the S3 storage adapter
    from the configured bucket and KMS key, unless an adapter is injected.

    Set require_remote_bundle=True to reject local receipts. This policy
    requires both a trusted-key registry and an S3 storage adapter, either
    injected directly or constructed from configuration.

    The DynamoDB client options (client/client_factory) are separate from
    the S3 client options (s3_client/s3_client_factory).

    No in-memory acceptance fallback occurs when DynamoDB initialization
    or configuration fails.
    """
    settings = os.environ if environ is None else environ

    if not isinstance(require_remote_bundle, bool):
        raise TypeError("require_remote_bundle must be a boolean")

    if consumer_id is None:
        consumer_id = settings.get("EVIDENCE_ENGINE_CONSUMER_ID", "").strip() or None
    if expected_stream_id is None:
        expected_stream_id = settings.get("EVIDENCE_ENGINE_EXPECTED_STREAM_ID", "").strip() or None

    if require_remote_bundle:
        if trust_registry_path is None:
            raise ValueError(
                "trust_registry_path is required when "
                "require_remote_bundle=True"
            )

        if bundle_storage is None and not configure_remote_storage:
            raise ValueError(
                "require_remote_bundle=True requires bundle_storage "
                "or configure_remote_storage=True"
            )

    s3_client_options_supplied = (
        s3_client is not None or s3_client_factory is not None
    )

    if configure_remote_storage:
        if trust_registry_path is None:
            raise ValueError(
                "trust_registry_path is required when remote storage "
                "is configured"
            )

        if bundle_storage is not None and s3_client_options_supplied:
            raise ValueError(
                "Provide bundle_storage or S3 client arguments, not both"
            )

        if bundle_storage is None:
            bundle_storage = create_s3_bundle_storage(
                environ=settings,
                client=s3_client,
                client_factory=s3_client_factory,
            )
    elif s3_client_options_supplied:
        raise ValueError(
            "S3 client arguments require configure_remote_storage=True"
        )

    acceptance_state: AcceptanceState = create_acceptance_state(
        environ=settings,
        client=client,
        client_factory=client_factory,
    )

    return ConsumerAgent(
        artifacts_root,
        expected_source=expected_source,
        expected_key_id=expected_key_id,
        acceptance_state=acceptance_state,
        bundle_storage=bundle_storage,
        trust_registry_path=trust_registry_path,
        require_remote_bundle=require_remote_bundle,
        consumer_id=consumer_id,
        expected_stream_id=expected_stream_id,
    )