from __future__ import annotations

import hashlib
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from evidence_engine.acceptance import AcceptanceState
from evidence_engine.agents.base import Agent, AgentResult
from evidence_engine.aws.reference import BundleReference
from evidence_engine.aws.storage import S3BundleStorage
from evidence_engine.canonical import canonical_json_bytes, parse_json_strict
from evidence_engine.schema import validate_manifest
from evidence_engine.verify import verify_bundle


class ConsumerAgent(Agent):
    """Verify evidence bundles and atomically record accepted manifests.

    Local mode consumes an existing local receipt.

    Remote mode consumes a producer result or receipt containing a
    BundleReference, downloads the referenced S3 object versions, and
    verifies the downloaded bundle using a locally configured trust registry.

    When require_remote_bundle is enabled, local receipts are rejected.
    """

    def __init__(
        self,
        artifacts_root: Path,
        expected_source: str | None = None,
        expected_key_id: str | None = None,
        *,
        acceptance_state: AcceptanceState,
        bundle_storage: S3BundleStorage | None = None,
        trust_registry_path: Path | None = None,
        require_remote_bundle: bool = False,
        consumer_id: str | None = None,
        expected_stream_id: str | None = None,
    ) -> None:
        super().__init__("consumer-agent")

        if not isinstance(require_remote_bundle, bool):
            raise TypeError("require_remote_bundle must be a boolean")
        if consumer_id is not None and (
            not isinstance(consumer_id, str) or not consumer_id.strip()
        ):
            raise ValueError("consumer_id must be a non-empty string")
        if expected_stream_id is not None and (
            not isinstance(expected_stream_id, str)
            or not expected_stream_id.strip()
        ):
            raise ValueError("expected_stream_id must be a non-empty string")

        self._root = Path(artifacts_root)
        self._expected_source = expected_source
        self._expected_key_id = expected_key_id
        self._acceptance_state = acceptance_state
        self._bundle_storage = bundle_storage
        self._trust_registry_path = (
            Path(trust_registry_path)
            if trust_registry_path is not None
            else None
        )
        self._require_remote_bundle = require_remote_bundle
        self._consumer_id = consumer_id.strip() if consumer_id else None
        self._expected_stream_id = (
            expected_stream_id.strip() if expected_stream_id else None
        )

    def run(
        self,
        receipt: Mapping[str, Any],
        **kwargs: Any,
    ) -> AgentResult:
        """Process a local receipt or a remote bundle reference."""
        if not isinstance(receipt, Mapping):
            return AgentResult(False, None, "receipt-invalid", {})

        # Enforce remote-only consumption when explicitly configured.
        if (
            self._require_remote_bundle
            and "bundle_reference" not in receipt
        ):
            return AgentResult(
                False,
                None,
                "remote-bundle-required",
                {},
            )

        if (
            not isinstance(self._expected_key_id, str)
            or not self._expected_key_id.strip()
        ):
            return AgentResult(
                False,
                None,
                "expected-key-id-missing",
                {},
            )

        if "bundle_reference" in receipt:
            return self._run_remote(receipt)

        return self._process_receipt(
            receipt,
            expected_root=self._root,
        )

    def _run_remote(
        self,
        receipt: Mapping[str, Any],
    ) -> AgentResult:
        """Download and verify a referenced remote bundle."""
        if self._bundle_storage is None:
            return AgentResult(
                False,
                None,
                "bundle-storage-unavailable",
                {},
            )

        # Never allow remote input to select the trusted-key registry.
        if self._trust_registry_path is None:
            return AgentResult(
                False,
                None,
                "trusted-registry-missing",
                {},
            )

        try:
            raw_reference = receipt["bundle_reference"]

            if isinstance(raw_reference, BundleReference):
                reference = BundleReference.from_dict(
                    raw_reference.to_dict()
                )
            elif isinstance(raw_reference, dict):
                reference = BundleReference.from_dict(raw_reference)
            else:
                raise ValueError("Bundle reference must be an object")

        except (ValueError, TypeError, KeyError):
            return AgentResult(
                False,
                None,
                "bundle-reference-invalid",
                {},
            )

        # The orchestrator returns a mapping containing "receipt" and
        # "bundle_reference". Also support a flat receipt with the
        # bundle reference attached directly.
        raw_metadata = receipt.get("receipt", receipt)

        if not isinstance(raw_metadata, Mapping):
            return AgentResult(
                False,
                None,
                "receipt-invalid",
                {},
            )

        try:
            with tempfile.TemporaryDirectory(
                prefix="evidence-engine-consumer-"
            ) as temporary_directory:
                bundle_dir = Path(temporary_directory) / "bundle"
                downloaded_artifacts = bundle_dir / "artifacts"

                try:
                    self._bundle_storage.download_bundle(
                        prefix=reference.prefix,
                        destination=bundle_dir,
                        reference=reference,
                    )
                except Exception as exc:
                    # Avoid exposing backend exception details.
                    return AgentResult(
                        False,
                        None,
                        "bundle-download-failed",
                        {"exception_type": type(exc).__name__},
                    )

                # Keep the producer's receipt metadata, but replace bundle
                # paths with paths inside the downloaded bundle.
                # The trust registry always comes from local configuration.
                normalized_receipt = dict(raw_metadata)
                normalized_receipt["artifacts_root"] = str(
                    downloaded_artifacts
                )
                normalized_receipt["manifest_path"] = str(
                    bundle_dir / "manifest.json"
                )
                normalized_receipt["signature_path"] = str(
                    bundle_dir / "manifest.sig"
                )
                normalized_receipt["trust_registry_path"] = str(
                    self._trust_registry_path
                )

                # Verify and record acceptance before temporary files
                # are removed.
                return self._process_receipt(
                    normalized_receipt,
                    expected_root=downloaded_artifacts,
                )

        except OSError as exc:
            return AgentResult(
                False,
                None,
                "bundle-download-failed",
                {"exception_type": type(exc).__name__},
            )

    def _process_receipt(
        self,
        receipt: Mapping[str, Any],
        *,
        expected_root: Path,
    ) -> AgentResult:
        """Validate receipt metadata, verify evidence, then record acceptance."""
        if (
            not isinstance(self._expected_key_id, str)
            or not self._expected_key_id.strip()
        ):
            return AgentResult(
                False,
                None,
                "expected-key-id-missing",
                {},
            )

        try:
            manifest_path = Path(receipt["manifest_path"])
            signature_path = Path(receipt["signature_path"])
            source = receipt["source"]
            receipt_root = Path(receipt["artifacts_root"])
            receipt_artifacts = receipt["artifacts"]
            receipt_key_id = receipt["signature_key_id"]

            if self._trust_registry_path is not None:
                trust_registry_path = self._trust_registry_path
            else:
                # Backward compatibility for local receipts.
                # Remote mode requires a locally configured registry.
                trust_registry_path = Path(
                    receipt["trust_registry_path"]
                )

        except (KeyError, TypeError, ValueError):
            return AgentResult(
                False,
                None,
                "receipt-invalid",
                {},
            )

        if not isinstance(source, str):
            return AgentResult(
                False,
                None,
                "receipt-invalid",
                {},
            )

        if (
            self._expected_source is not None
            and source != self._expected_source
        ):
            return AgentResult(
                False,
                None,
                "source-mismatch",
                {
                    "expected": self._expected_source,
                    "actual": source,
                },
            )

        try:
            if receipt_root.resolve() != expected_root.resolve():
                return AgentResult(
                    False,
                    None,
                    "receipt-artifacts-root-mismatch",
                    {},
                )

            manifest_bytes = manifest_path.read_bytes()
            manifest = parse_json_strict(manifest_bytes)

            if canonical_json_bytes(manifest) != manifest_bytes:
                return AgentResult(
                    False,
                    None,
                    "manifest-not-canonical",
                    {},
                )

            validate_manifest(manifest)

        except OSError as exc:
            return AgentResult(
                False,
                None,
                "manifest-read-failed",
                {"exception_type": type(exc).__name__},
            )
        except (ValueError, TypeError, KeyError):
            return AgentResult(
                False,
                None,
                "manifest-invalid",
                {},
            )

        manifest_source = manifest["provenance"]["source"]
        manifest_key_id = manifest["key_id"]
        manifest_artifacts = [
            artifact["name"]
            for artifact in manifest["artifacts"]
        ]

        if source != manifest_source:
            return AgentResult(
                False,
                None,
                "receipt-source-mismatch",
                {},
            )

        if receipt_key_id != manifest_key_id:
            return AgentResult(
                False,
                None,
                "receipt-key-id-mismatch",
                {},
            )

        if manifest_key_id != self._expected_key_id:
            return AgentResult(
                False,
                None,
                "key-id-mismatch",
                {
                    "expected": self._expected_key_id,
                    "actual": manifest_key_id,
                },
            )

        if (
            not isinstance(receipt_artifacts, (list, tuple))
            or receipt_artifacts != manifest_artifacts
        ):
            return AgentResult(
                False,
                None,
                "receipt-artifacts-mismatch",
                {},
            )

        try:
            verified = verify_bundle(
                expected_root,
                manifest_path,
                signature_path,
                trust_registry_path,
                self._expected_key_id,
            )
        except Exception as exc:
            return AgentResult(
                False,
                None,
                "verification-error",
                {"exception_type": type(exc).__name__},
            )

        if not verified:
            return AgentResult(
                False,
                {"verified": False},
                "verification-failed",
                {},
            )

        # Acceptance state is changed only after successful verification.
        bundle_digest = hashlib.sha256(manifest_bytes).hexdigest()
        provenance = manifest["provenance"]

        if manifest["schema_version"] == "1.3":
            if not self._consumer_id or not self._expected_stream_id:
                return AgentResult(
                    False,
                    {"verified": True, "key_id": manifest_key_id},
                    "ordered-acceptance-config-missing",
                    {"bundle_digest": bundle_digest},
                )

            actual_stream_id = provenance["stream_id"]
            if actual_stream_id != self._expected_stream_id:
                return AgentResult(
                    False,
                    {"verified": True, "key_id": manifest_key_id},
                    "stream-id-mismatch",
                    {
                        "expected_stream_id": self._expected_stream_id,
                        "actual_stream_id": actual_stream_id,
                    },
                )

            try:
                outcome = self._acceptance_state.accept_ordered(
                    bundle_digest,
                    consumer_id=self._consumer_id,
                    stream_id=actual_stream_id,
                    run_number=int(provenance["run_number"]),
                    run_attempt=int(provenance["run_attempt"]),
                )
            except Exception:
                return AgentResult(
                    False,
                    {"verified": True, "key_id": manifest_key_id},
                    "acceptance-state-error",
                    {"bundle_digest": bundle_digest},
                )

            if outcome == "replay":
                return AgentResult(
                    False,
                    {"verified": True, "key_id": manifest_key_id},
                    "bundle-replay-detected",
                    {"bundle_digest": bundle_digest},
                )

            if outcome == "stale":
                return AgentResult(
                    False,
                    {"verified": True, "key_id": manifest_key_id},
                    "bundle-rollback-detected",
                    {
                        "bundle_digest": bundle_digest,
                        "stream_id": actual_stream_id,
                        "run_number": provenance["run_number"],
                        "run_attempt": provenance["run_attempt"],
                    },
                )

            if outcome != "accepted":
                return AgentResult(
                    False,
                    {"verified": True, "key_id": manifest_key_id},
                    "acceptance-state-error",
                    {"bundle_digest": bundle_digest},
                )
        else:
            # Preserve the legacy path for local and v1.2 evidence.
            try:
                accepted = self._acceptance_state.accept_once(bundle_digest)
            except Exception:
                return AgentResult(
                    False,
                    {"verified": True, "key_id": manifest_key_id},
                    "acceptance-state-error",
                    {"bundle_digest": bundle_digest},
                )

            if not accepted:
                return AgentResult(
                    False,
                    {"verified": True, "key_id": manifest_key_id},
                    "bundle-replay-detected",
                    {"bundle_digest": bundle_digest},
                )

        return AgentResult(
            True,
            {"verified": True, "key_id": manifest_key_id},
            None,
            {
                "source": manifest_source,
                "bundle_digest": bundle_digest,
            },
        )