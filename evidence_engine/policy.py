from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class PolicyDecision:
    """
    Structured policy decision.

    - allowed: True if the action is permitted, False otherwise.
    - reason: short, machine-readable reason code.
    - details: structured context for auditing and debugging.
    """

    allowed: bool
    reason: str
    details: Mapping[str, Any]


class PolicyEngine:
    """
    Versioned policy engine for EvidenceEngine agents.

    Policies MUST fail closed:
    - malformed or missing required inputs → allowed=False
    - unexpected types or structures → allowed=False
    """

    def __init__(self, version: str = "1.0") -> None:
        if not isinstance(version, str) or not version.strip():
            raise ValueError("Policy version must be a non-empty string")
        self.version = version

    def _fail_closed(self, reason: str, details: Mapping[str, Any] | None = None) -> PolicyDecision:
        return PolicyDecision(
            allowed=False,
            reason=reason,
            details={"version": self.version, **(details or {})},
        )

    def evaluate_collection(self, metadata: Mapping[str, Any] | None) -> PolicyDecision:
        """
        Evaluate whether evidence collection is allowed.

        Required inputs:
        - metadata["root"]: non-empty string path
        - metadata["files"]: iterable of non-empty string filenames
        """
        if not isinstance(metadata, Mapping):
            return self._fail_closed("collection-metadata-invalid", {"metadata_type": type(metadata).__name__})

        root = metadata.get("root")
        files = metadata.get("files")

        if not isinstance(root, str) or not root.strip():
            return self._fail_closed("collection-root-missing", {"root": root})

        if not isinstance(files, (list, tuple)) or not files:
            return self._fail_closed("collection-files-missing", {"files": files})

        for name in files:
            if not isinstance(name, str) or not name.strip():
                return self._fail_closed("collection-file-name-invalid", {"file": name})

        return PolicyDecision(
            allowed=True,
            reason="collection-allowed",
            details={"version": self.version, "file_count": len(files)},
        )

    def evaluate_integrity(self, manifest: Mapping[str, Any] | None) -> PolicyDecision:
        """
        Evaluate whether manifest integrity is acceptable.

        Required inputs:
        - manifest["artifacts"]: iterable of dicts with "name" keys
        """
        if not isinstance(manifest, Mapping):
            return self._fail_closed("integrity-manifest-invalid", {"manifest_type": type(manifest).__name__})

        artifacts = manifest.get("artifacts")
        if not isinstance(artifacts, (list, tuple)) or not artifacts:
            return self._fail_closed("integrity-artifacts-missing", {"artifacts": artifacts})

        for entry in artifacts:
            if not isinstance(entry, Mapping):
                return self._fail_closed("integrity-artifact-entry-invalid", {"entry_type": type(entry).__name__})
            name = entry.get("name")
            if not isinstance(name, str) or not name.strip():
                return self._fail_closed("integrity-artifact-name-invalid", {"entry": entry})

        return PolicyDecision(
            allowed=True,
            reason="integrity-allowed",
            details={"version": self.version, "artifact_count": len(artifacts)},
        )

    def evaluate_consumption(self, receipt: Mapping[str, Any] | None) -> PolicyDecision:
        """
        Evaluate whether evidence consumption is allowed.

        Required inputs:
        - receipt["artifacts"]: iterable of non-empty string names
        - receipt["signature_key_id"]: non-empty string
        """
        if not isinstance(receipt, Mapping):
            return self._fail_closed("consumption-receipt-invalid", {"receipt_type": type(receipt).__name__})

        artifacts = receipt.get("artifacts")
        key_id = receipt.get("signature_key_id")

        if not isinstance(artifacts, (list, tuple)) or not artifacts:
            return self._fail_closed("consumption-artifacts-missing", {"artifacts": artifacts})

        for name in artifacts:
            if not isinstance(name, str) or not name.strip():
                return self._fail_closed("consumption-artifact-name-invalid", {"artifact": name})

        if not isinstance(key_id, str) or not key_id.strip():
            return self._fail_closed("consumption-key-id-missing", {"signature_key_id": key_id})

        return PolicyDecision(
            allowed=True,
            reason="consumption-allowed",
            details={"version": self.version, "artifact_count": len(artifacts)},
        )
