"""Explicit configuration for acceptance-state backends."""

from __future__ import annotations

import importlib
import os
from collections.abc import Callable, Mapping
from typing import Any

from evidence_engine.acceptance import (
    AcceptanceState,
    InMemoryAcceptanceState,
)
from evidence_engine.aws.acceptance import DynamoDBAcceptanceState


BACKEND_ENV = "EVIDENCE_ENGINE_ACCEPTANCE_BACKEND"
TABLE_ENV = "EVIDENCE_ENGINE_DYNAMODB_TABLE"


def create_acceptance_state(
    *,
    environ: Mapping[str, str] | None = None,
    client: Any | None = None,
    client_factory: Callable[..., Any] | None = None,
) -> AcceptanceState:
    """Build the explicitly configured acceptance-state adapter.

    Supported backends:
      - memory: development and tests only
      - dynamodb: shared, durable replay detection

    An unset backend is an error. DynamoDB failures never trigger a
    fallback to in-memory state.

    ``client`` and ``client_factory`` are injectable for tests. The
    default AWS client is created lazily, using the standard boto3
    credential and region configuration chain.
    """
    settings = os.environ if environ is None else environ
    backend = settings.get(BACKEND_ENV, "").strip().lower()

    if backend not in {"memory", "dynamodb"}:
        raise ValueError(
            f"{BACKEND_ENV} must explicitly be 'memory' or 'dynamodb'"
        )

    if backend == "memory":
        if client is not None or client_factory is not None:
            raise ValueError(
                "AWS client arguments cannot be used with the memory backend"
            )
        return InMemoryAcceptanceState()

    table_name = settings.get(TABLE_ENV, "").strip()
    if not table_name:
        raise ValueError(
            f"{TABLE_ENV} is required when the DynamoDB backend is selected"
        )

    if client is not None and client_factory is not None:
        raise ValueError("Provide client or client_factory, not both")

    if client is None:
        if client_factory is None:
            try:
                boto3 = importlib.import_module("boto3")
            except ImportError as exc:
                raise RuntimeError(
                    "DynamoDB requires boto3; install with "
                    "'pip install -e \".[aws]\"'"
                ) from exc
            client_factory = boto3.client

        region = (
            settings.get("AWS_REGION", "").strip()
            or settings.get("AWS_DEFAULT_REGION", "").strip()
        )

        if region:
            client = client_factory("dynamodb", region_name=region)
        else:
            # Let boto3 resolve region from its normal configuration chain.
            client = client_factory("dynamodb")

    return DynamoDBAcceptanceState(client, table_name)
