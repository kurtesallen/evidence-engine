"""Application-level construction for an S3-backed producer."""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from typing import Any

from evidence_engine.agents.orchestrator import Orchestrator
from evidence_engine.aws.storage import S3BundleStorage
from evidence_engine.aws.storage_config import create_s3_bundle_storage


def create_producer(
    *args: Any,
    bundle_prefix: str,
    environ: Mapping[str, str] | None = None,
    s3_client: Any | None = None,
    s3_client_factory: Callable[..., Any] | None = None,
    **orchestrator_kwargs: Any,
) -> Orchestrator:
    """Construct a producer that requires successful remote bundle storage.

    Existing Orchestrator constructor arguments can be passed positionally
    or by keyword. S3 configuration is explicit and independently
    injectable for tests.

    Direct Orchestrator construction remains available for local workflows.
    This factory always enables the remote-storage requirement.
    """
    reserved = {
        "bundle_storage",
        "bundle_prefix",
        "require_remote_storage",
    }
    conflicts = reserved.intersection(orchestrator_kwargs)
    if conflicts:
        names = ", ".join(sorted(conflicts))
        raise ValueError(
            f"These options are controlled by create_producer: {names}"
        )

    if not isinstance(bundle_prefix, str) or not bundle_prefix.strip():
        raise ValueError("bundle_prefix must be a non-empty string")

    settings = os.environ if environ is None else environ

    storage: S3BundleStorage = create_s3_bundle_storage(
        environ=settings,
        client=s3_client,
        client_factory=s3_client_factory,
    )

    options = dict(orchestrator_kwargs)
    options.update(
        bundle_storage=storage,
        bundle_prefix=bundle_prefix,
        require_remote_storage=True,
    )

    return Orchestrator(*args, **options)
