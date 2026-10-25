from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from evidence_engine.agents.base import Agent, AgentResult
from evidence_engine.canonical import canonical_json_bytes, parse_json_strict
from evidence_engine.schema import validate_manifest
from evidence_engine.verify import verify_bundle


class ConsumerAgent(Agent):
    def __init__(
        self,
        artifacts_root: Path,
        expected_source: str | None = None,
        expected_key_id: str | None = None,
    ) -> None:
        super().__init__("consumer-agent")
        self._root = Path(artifacts_root)
        self._expected_source = expected_source
        self._expected_key_id = expected_key_id

    def run(
        self, receipt: Mapping[str, Any], **kwargs: Any
    ) -> AgentResult:
        if not isinstance(receipt, Mapping):
            return AgentResult(False, None, "receipt-invalid", {})

        if (
            not isinstance(self._expected_key_id, str)
            or not self._expected_key_id.strip()
        ):
            return AgentResult(
                False, None, "expected-key-id-missing", {},
            )

        try:
            manifest_path = Path(receipt["manifest_path"])
            signature_path = Path(receipt["signature_path"])
            trust_registry_path = Path(receipt["trust_registry_path"])
            source = receipt["source"]
            receipt_root = Path(receipt["artifacts_root"])
            receipt_artifacts = receipt["artifacts"]
            receipt_key_id = receipt["signature_key_id"]
        except (KeyError, TypeError, ValueError) as exc:
            return AgentResult(
                False, None, "receipt-invalid",
                {"exception": str(exc)},
            )

        if not isinstance(source, str):
            return AgentResult(False, None, "receipt-invalid", {})

        if self._expected_source is not None and source != self._expected_source:
            return AgentResult(
                False,
                None,
                "source-mismatch",
                {"expected": self._expected_source, "actual": source},
            )

        try:
            if receipt_root.resolve() != self._root.resolve():
                return AgentResult(
                    False, None, "receipt-artifacts-root-mismatch", {},
                )
            manifest_bytes = manifest_path.read_bytes()
            manifest = parse_json_strict(manifest_bytes)
            if canonical_json_bytes(manifest) != manifest_bytes:
                return AgentResult(
                    False, None, "manifest-not-canonical", {},
                )
            validate_manifest(manifest)
        except OSError as exc:
            return AgentResult(
                False, None, "manifest-read-failed",
                {"exception": str(exc)},
            )
        except (ValueError, TypeError, KeyError) as exc:
            return AgentResult(
                False, None, "manifest-invalid",
                {"exception": str(exc)},
            )

        manifest_source = manifest["provenance"]["source"]
        manifest_key_id = manifest["key_id"]
        manifest_artifacts = [
            artifact["name"] for artifact in manifest["artifacts"]
        ]

        if source != manifest_source:
            return AgentResult(False, None, "receipt-source-mismatch", {})

        if receipt_key_id != manifest_key_id:
            return AgentResult(False, None, "receipt-key-id-mismatch", {})

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
                False, None, "receipt-artifacts-mismatch", {},
            )

        try:
            verified = verify_bundle(
                self._root,
                manifest_path,
                signature_path,
                trust_registry_path,
                self._expected_key_id,
            )
        except Exception as exc:
            return AgentResult(
                False, None, "verification-error",
                {"exception": str(exc)},
            )

        if not verified:
            return AgentResult(
                False, {"verified": False}, "verification-failed", {},
            )

        return AgentResult(
            True,
            {"verified": True, "key_id": manifest_key_id},
            None,
            {"source": manifest_source},
        )
