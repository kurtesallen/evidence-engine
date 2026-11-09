"""Coordinate evidence creation, signing, receipt, and optional S3 upload."""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, Mapping

from evidence_engine.agents.artifact_staging import stage_sanitized_artifacts
from evidence_engine.agents.base import Agent, AgentResult
from evidence_engine.agents.collection import CollectionAgent
from evidence_engine.agents.integrity import IntegrityAgent
from evidence_engine.agents.signing import SigningAgent
from evidence_engine.aws.reference import BundleReference
from evidence_engine.bundle_publication import (
    BundlePaths,
    cleanup_staging_generation,
    create_staging_generation,
    publish_generation,
)
from evidence_engine.aws.storage import S3BundleStorage
from evidence_engine.manifest import write_manifest
from evidence_engine.receipt import ReceiptAgent
from evidence_engine.schema import REQUIRED_ARTIFACTS
from evidence_engine.signing import KEY_ID


class Orchestrator(Agent):
    """Coordinate evidence creation, signing, receipt, and optional S3 upload."""

    def __init__(
        self,
        artifacts_root: Path,
        output_dir: Path,
        provenance: Mapping[str, str],
        trust_registry_path: Path,
        *,
        signing_mode: str = "local",
        private_key: Path | None = None,
        kms_key_id: str | None = None,
        aws_region: str = "us-east-1",
        bundle_storage: S3BundleStorage | None = None,
        bundle_prefix: str | None = None,
        require_remote_storage: bool = False,
        artifact_metadata: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> None:
        super().__init__("evidence-orchestrator")
        self._root = Path(artifacts_root)
        self._output = Path(output_dir)
        self._provenance = dict(provenance)
        self._trust_registry = Path(trust_registry_path)
        self._mode = signing_mode
        self._private_key = private_key
        self._kms_key_id = kms_key_id
        self._region = aws_region
        self._bundle_storage = bundle_storage
        self._bundle_prefix = bundle_prefix
        self._require_remote_storage = require_remote_storage
        self._artifact_metadata = artifact_metadata

    def run(self, **kwargs: Any) -> AgentResult:
        if self._mode not in ("local", "kms"):
            return AgentResult(
                False, None, "signing-mode-invalid", {}
            )

        if self._mode == "local":
            if self._private_key is None:
                return AgentResult(
                    False, None, "local-signing-missing-key", {}
                )
            key_id = KEY_ID
        else:
            if (
                not isinstance(self._kms_key_id, str)
                or not self._kms_key_id.strip()
            ):
                return AgentResult(
                    False, None, "kms-signing-missing-key-id", {}
                )
            key_id = self._kms_key_id

        # Require explicit remote storage in production configurations.
        if self._require_remote_storage and self._bundle_storage is None:
            return AgentResult(
                False, None, "s3-storage-required", {}
            )

        if self._bundle_storage is None:
            if self._bundle_prefix is not None:
                return AgentResult(
                    False, None, "s3-storage-missing", {}
                )
        elif (
            not isinstance(self._bundle_prefix, str)
            or not self._bundle_prefix.strip()
        ):
            return AgentResult(
                False, None, "s3-prefix-missing", {}
            )

        # Reject direct symlinks before resolving either path. This prevents
        # the caller from supplying a symlink as either trust boundary.
        if self._root.is_symlink():
            return AgentResult(
                False, None, "artifacts-root-symlink", {}
            )

        if self._output.is_symlink():
            return AgentResult(
                False, None, "output-directory-symlink", {}
            )

        # Resolve paths once and use these canonical paths throughout run().
        try:
            root = self._root.resolve()
            output = self._output.resolve()
        except OSError as exc:
            return AgentResult(
                False,
                None,
                "path-resolution-failed",
                {
                    "stage": "path-validation",
                    "exception_type": type(exc).__name__,
                },
            )

        if not root.is_dir():
            return AgentResult(
                False, None, "artifacts-root-not-directory", {}
            )

        # Never put generated bundle files inside source artifacts.
        if output == root or root in output.parents:
            return AgentResult(
                False, None, "output-inside-artifacts-root", {}
            )

        source = self._provenance.get("source")
        if source not in ("local-claimed", "github-actions-claimed"):
            return AgentResult(
                False, None, "provenance-source-invalid", {}
            )

        # CI and every S3 publication require explicit artifact metadata.
        # The content-sanitization staging step below enforces that both
        # Terraform JSON artifacts are actually declared sanitized.
        if (
            (
                source == "github-actions-claimed"
                or self._bundle_storage is not None
            )
            and self._artifact_metadata is None
        ):
            return AgentResult(
                False,
                None,
                "artifact-metadata-required",
                {"stage": "manifest"},
            )

        collection = CollectionAgent(root).run()
        if not collection.success:
            return AgentResult(
                False,
                None,
                collection.error,
                {"stage": "collection", **dict(collection.audit)},
            )

        names = {path.name for path in collection.data["files"]}
        if names != REQUIRED_ARTIFACTS:
            return AgentResult(
                False,
                None,
                "artifact-set-mismatch",
                {
                    "stage": "collection",
                    "missing": sorted(REQUIRED_ARTIFACTS - names),
                    "unexpected": sorted(names - REQUIRED_ARTIFACTS),
                },
            )

        try:
            paths = create_staging_generation(output)
        except (OSError, ValueError) as exc:
            return AgentResult(
                False,
                None,
                "bundle-staging-failed",
                {
                    "stage": "bundle-staging",
                    "exception_type": type(exc).__name__,
                    "exception": str(exc),
                },
            )

        try:
            result = self._build_generation(
                root=root,
                paths=paths,
                source=source,
                key_id=key_id,
                collected_files=collection.data["files"],
            )
            if not result.success:
                return result

            try:
                published = publish_generation(paths)
            except (OSError, ValueError) as exc:
                return AgentResult(
                    False,
                    None,
                    "bundle-publication-failed",
                    {
                        "stage": "bundle-publication",
                        "exception_type": type(exc).__name__,
                        "exception": str(exc),
                    },
                )

            data = dict(result.data)
            receipt_data = dict(data["receipt"])
            receipt_data["artifacts_root"] = str(published.artifacts_root)
            receipt_data["manifest_path"] = str(published.manifest_path)
            receipt_data["signature_path"] = str(published.signature_path)
            data["receipt"] = receipt_data
            data["manifest_path"] = str(published.manifest_path)
            data["signature_path"] = str(published.signature_path)

            audit = dict(result.audit)
            audit["publication"] = "committed"
            audit["generation_id"] = published.generation_id
            return AgentResult(True, data, None, audit)
        finally:
            # Published generations cannot be removed by this cleanup.
            # A cleanup error must never mask the original outcome.
            try:
                cleanup_staging_generation(paths)
            except (OSError, ValueError):
                pass

    def _build_generation(
        self,
        *,
        root: Path,
        paths: BundlePaths,
        source: str,
        key_id: str,
        collected_files: Any,
    ) -> AgentResult:
        """Build, verify, and optionally upload an unpublished generation."""
        manifest_path = paths.manifest_path
        signature_path = paths.signature_path
        temporary_signature = signature_path.with_name(
            signature_path.name + ".tmp"
        )

        artifact_root = paths.artifacts_root
        artifact_sanitization_applied = False

        # Keep manifest provenance separate from the caller's provenance.
        # The Terraform version is replaced only after it is validated
        # against the staged plan and state artifacts.
        manifest_provenance = dict(self._provenance)

        metadata_requests_sanitization = (
            isinstance(self._artifact_metadata, Mapping)
            and any(
                isinstance(entry, Mapping)
                and entry.get("representation") == "sanitized"
                for entry in self._artifact_metadata.values()
            )
        )

        # CI provenance and configured remote publication must never bypass
        # content sanitization just because metadata says raw or sample.
        publication_requires_sanitization = (
            source == "github-actions-claimed"
            or self._bundle_storage is not None
        )

        if publication_requires_sanitization or metadata_requests_sanitization:
            try:
                artifact_root = stage_sanitized_artifacts(
                    source_root=root,
                    destination_root=paths.artifacts_root,
                    artifact_metadata=self._artifact_metadata,
                )
                artifact_sanitization_applied = True

                # Read the version from the exact staged artifacts that will
                # be hashed, signed, and included in the evidence bundle.
                plan_document = json.loads(
                    (artifact_root / "plan.json").read_text(
                        encoding="utf-8"
                    )
                )
                state_document = json.loads(
                    (artifact_root / "state.json").read_text(
                        encoding="utf-8"
                    )
                )

                if (
                    not isinstance(plan_document, dict)
                    or not isinstance(state_document, dict)
                ):
                    raise ValueError(
                        "Terraform plan and state artifacts must be JSON objects"
                    )

                plan_version = plan_document.get("terraform_version")
                state_version = state_document.get("terraform_version")

                if (
                    not isinstance(plan_version, str)
                    or not plan_version.strip()
                    or not isinstance(state_version, str)
                    or not state_version.strip()
                ):
                    raise ValueError(
                        "Terraform version is missing from plan.json or state.json"
                    )

                if plan_version != state_version:
                    raise ValueError(
                        "Terraform version mismatch between plan.json and state.json"
                    )

                manifest_provenance["terraform_version"] = plan_version

            except (
                OSError,
                UnicodeDecodeError,
                json.JSONDecodeError,
                ValueError,
                TypeError,
                KeyError,
            ) as exc:
                return AgentResult(
                    False,
                    None,
                    "artifact-sanitization-failed",
                    {
                        "stage": "artifact-sanitization",
                        "exception_type": type(exc).__name__,
                        "exception": str(exc),
                    },
                )

        else:
            # Local raw bundles are also self-contained. Copy only the
            # four paths approved by CollectionAgent into this generation.
            try:
                artifact_root.mkdir(mode=0o700)
                for collected_path in collected_files:
                    collected_path = Path(collected_path)
                    if (
                        collected_path.is_symlink()
                        or not collected_path.is_file()
                        or collected_path.parent != root
                        or collected_path.name not in REQUIRED_ARTIFACTS
                    ):
                        raise ValueError(
                            f"Unsafe collected artifact: {collected_path}"
                        )
                    shutil.copyfile(
                        collected_path,
                        artifact_root / collected_path.name,
                    )
            except (OSError, ValueError) as exc:
                return AgentResult(
                    False,
                    None,
                    "artifact-staging-failed",
                    {
                        "stage": "artifact-staging",
                        "exception_type": type(exc).__name__,
                        "exception": str(exc),
                    },
                )

        # Local bundles retain schema v1.1. CI bundles require v1.3,
        # including ordered provenance and a stream identity.
        schema_version = (
            "1.3" if source == "github-actions-claimed" else "1.1"
        )

        try:
            write_manifest(
                artifact_root,
                manifest_path,
                manifest_provenance,
                key_id,
                schema_version=schema_version,
                artifact_metadata=self._artifact_metadata,
            )
        except (OSError, ValueError, TypeError, KeyError) as exc:
            return AgentResult(
                False,
                None,
                "manifest-creation-failed",
                {"stage": "manifest", "exception": str(exc)},
            )

        integrity = IntegrityAgent(artifact_root, manifest_path).run()
        if not integrity.success:
            return AgentResult(
                False,
                None,
                integrity.error,
                {"stage": "integrity", **dict(integrity.audit)},
            )

        signing = SigningAgent(
            manifest_path=manifest_path,
            signing_mode=self._mode,
            private_key=self._private_key,
            kms_key_id=self._kms_key_id,
            aws_region=self._region,
        ).run()
        if not signing.success:
            return AgentResult(
                False,
                None,
                signing.error,
                {"stage": "signing", **dict(signing.audit)},
            )

        signature = signing.data["signature"]
        if not isinstance(signature, bytes) or not signature:
            return AgentResult(
                False, None, "signature-output-invalid", {}
            )

        try:
            temporary_signature.write_bytes(signature)
            temporary_signature.replace(signature_path)
        except OSError as exc:
            try:
                temporary_signature.unlink(missing_ok=True)
            except OSError:
                pass
            return AgentResult(
                False,
                None,
                "signature-persistence-failed",
                {
                    "stage": "signature-persistence",
                    "exception": str(exc),
                },
            )

        receipt = ReceiptAgent(
            artifacts_root=artifact_root,
            manifest_path=manifest_path,
            signature_path=signature_path,
            trust_registry_path=self._trust_registry,
            source=source,
        ).run()
        if not receipt.success:
            return AgentResult(
                False,
                None,
                receipt.error,
                {"stage": "receipt", **dict(receipt.audit)},
            )

        # Only upload after local integrity, signing, and receipt verification
        # have succeeded. No successful result is returned if required S3
        # publication or reference validation fails.
        bundle_reference: dict[str, Any] | None = None

        if self._bundle_storage is not None:
            try:
                uploaded = self._bundle_storage.upload_bundle(
                    prefix=self._bundle_prefix,
                    artifacts_root=artifact_root,
                    manifest_path=manifest_path,
                    signature_path=signature_path,
                )

                if not isinstance(uploaded, dict):
                    raise ValueError("Invalid S3 upload result")

                raw_reference = uploaded.get("reference")
                if not isinstance(raw_reference, dict):
                    raise ValueError("S3 upload returned no bundle reference")

                validated_reference = BundleReference.from_dict(
                    raw_reference
                )

                expected_prefix = self._bundle_prefix.strip("/")
                if validated_reference.prefix != expected_prefix:
                    raise ValueError("S3 reference prefix mismatch")

                if (
                    uploaded.get("bucket") != validated_reference.bucket
                    or uploaded.get("prefix") != validated_reference.prefix
                ):
                    raise ValueError("S3 reference location mismatch")

                bundle_reference = validated_reference.to_dict()

            except Exception as exc:
                # Avoid presenting a partially published bundle as success.
                return AgentResult(
                    False,
                    None,
                    "bundle-upload-failed",
                    {
                        "stage": "s3-upload",
                        "exception_type": type(exc).__name__,
                    },
                )

        data: dict[str, Any] = {
            "receipt": receipt.data["receipt"],
            "manifest_path": str(manifest_path),
            "signature_path": str(signature_path),
            "key_id": key_id,
            "mode": self._mode,
            "storage_mode": (
                "s3" if bundle_reference is not None else "local"
            ),
        }

        if bundle_reference is not None:
            data["bundle_reference"] = bundle_reference

        stages = ["collection"]
        if artifact_sanitization_applied:
            stages.append("artifact-sanitization")

        stages.extend([
            "manifest",
            "integrity",
            "signing",
            "signature-persistence",
            "receipt",
        ])

        if bundle_reference is not None:
            stages.append("s3-upload")

        return AgentResult(
            True,
            data,
            None,
            {"stages": stages},
        )
