"""Run a real Terraform collection and publish it through EvidenceEngine."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from evidence_engine.agents.base import AgentResult
from evidence_engine.agents.producer_factory import create_producer
from evidence_engine.schema import REQUIRED_ARTIFACTS
from evidence_engine.terraform_collect import collect_terraform


def _validate_prepared_artifact_root(artifacts_root: Path) -> Path:
    """Require commit.txt and version.txt before collecting Terraform files."""
    root = Path(artifacts_root)

    if root.is_symlink():
        raise ValueError("Artifact root must not be a symlink")

    if not root.is_dir():
        raise ValueError("Artifact root must be an existing directory")

    root = root.resolve()

    names: set[str] = set()

    for path in root.iterdir():
        if path.is_symlink():
            raise ValueError(
                f"Artifact entry must not be a symlink: {path.name}"
            )

        if not path.is_file():
            raise ValueError(
                f"Artifact entry must be a regular file: {path.name}"
            )

        names.add(path.name)

    required_metadata_files = {"commit.txt", "version.txt"}

    if not required_metadata_files.issubset(names):
        missing = sorted(required_metadata_files - names)
        raise ValueError(
            f"Prepared artifact root is missing required files: {missing}"
        )

    # Permit either a fresh prepared directory or a complete prior
    # collection. Reject partial pairs and unrelated files.
    if (
        names != required_metadata_files
        and names != REQUIRED_ARTIFACTS
    ):
        raise ValueError(
            "Artifact root must contain commit.txt and version.txt, "
            "optionally alongside both plan.json and state.json; "
            f"found={sorted(names)}"
        )

    return root


def run_terraform_producer(
    *,
    terraform_root: Path,
    artifacts_root: Path,
    provenance: Mapping[str, str],
    terraform_executable: str = "terraform",
    timeout_seconds: int = 300,
    allow_remote_backend: bool = False,
    **producer_kwargs: Any,
) -> AgentResult:
    """Collect real Terraform evidence, seal it, and publish it to S3.

    The artifact directory must already contain commit.txt and version.txt.
    The collector creates or replaces plan.json and state.json.

    Terraform version and provider lock digest are taken from the collection
    result, not trusted from caller-supplied provenance.
    """
    if not isinstance(provenance, Mapping):
        raise TypeError("provenance must be a mapping")

    if not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in provenance.items()
    ):
        raise ValueError("Provenance keys and values must be strings")

    prepared_root = _validate_prepared_artifact_root(artifacts_root)

    collection = collect_terraform(
        terraform_root=Path(terraform_root),
        output_dir=prepared_root,
        terraform_executable=terraform_executable,
        timeout_seconds=timeout_seconds,
        allow_remote_backend=allow_remote_backend,
    )

    # Use observed collection metadata rather than environment or caller
    # claims for these two provenance fields.
    trusted_provenance = dict(provenance)
    trusted_provenance["terraform_version"] = (
        collection.terraform_version
    )
    trusted_provenance["provider_lock_sha256"] = (
        collection.provider_lock_sha256
    )

    producer = create_producer(
        artifacts_root=prepared_root,
        provenance=trusted_provenance,
        **producer_kwargs,
    )

    return producer.run()
