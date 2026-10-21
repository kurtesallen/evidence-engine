from __future__ import annotations

from pathlib import Path
from typing import Any

from evidence_engine.agents.base import Agent, AgentResult
from evidence_engine.canonical import canonical_json_bytes, parse_json_strict
from evidence_engine.schema import validate_manifest
from evidence_engine.verify import verify_bundle


class ReceiptAgent(Agent):
    def __init__(
        self,
        artifacts_root: Path,
        manifest_path: Path,
        signature_path: Path,
        trust_registry_path: Path,
        source: str = "local-claimed",
    ) -> None:
        super().__init__("receipt-agent")
        self._root = Path(artifacts_root)
        self._manifest_path = Path(manifest_path)
        self._signature_path = Path(signature_path)
        self._trust_registry_path = Path(trust_registry_path)
        self._source = source

    def run(self, **kwargs: Any) -> AgentResult:
        try:
            manifest_bytes = self._manifest_path.read_bytes()
        except OSError as exc:
            return AgentResult(
                False,
                None,
                "manifest-read-failed",
                {"exception": str(exc)},
            )

        try:
            signature_bytes = self._signature_path.read_bytes()
        except OSError as exc:
            return AgentResult(
                False,
                None,
                "signature-read-failed",
                {"exception": str(exc)},
            )

        try:
            manifest = parse_json_strict(manifest_bytes)
        except (ValueError, TypeError) as exc:
            return AgentResult(
                False,
                None,
                "manifest-json-invalid",
                {"exception": str(exc)},
            )

        try:
            if canonical_json_bytes(manifest) != manifest_bytes:
                return AgentResult(
                    False,
                    None,
                    "manifest-not-canonical",
                    {},
                )
        except (ValueError, TypeError) as exc:
            return AgentResult(
                False,
                None,
                "manifest-json-invalid",
                {"exception": str(exc)},
            )

        try:
            validate_manifest(manifest)
        except (ValueError, TypeError, KeyError) as exc:
            return AgentResult(
                False,
                None,
                "manifest-schema-invalid",
                {"exception": str(exc)},
            )

        manifest_source = manifest["provenance"]["source"]
        if self._source != manifest_source:
            return AgentResult(
                False,
                None,
                "source-mismatch",
                {
                    "expected": self._source,
                    "actual": manifest_source,
                },
            )

        # Verify the signature, trusted key, and artifact contents before
        # issuing receipt metadata. A valid manifest structure alone is
        # insufficient evidence that the bundle is authentic.
        try:
            verified = verify_bundle(
                self._root,
                self._manifest_path,
                self._signature_path,
                self._trust_registry_path,
                manifest["key_id"],
            )
        except (OSError, ValueError, TypeError, KeyError) as exc:
            return AgentResult(
                False,
                None,
                "bundle-verification-error",
                {"exception": str(exc)},
            )

        if not verified:
            return AgentResult(
                False,
                None,
                "bundle-verification-failed",
                {},
            )

        receipt = {
            "artifacts_root": str(self._root),
            "manifest_path": str(self._manifest_path),
            "signature_path": str(self._signature_path),
            "trust_registry_path": str(self._trust_registry_path),
            "source": manifest_source,
            "artifacts": [
                artifact["name"] for artifact in manifest["artifacts"]
            ],
            "signature_key_id": manifest["key_id"],
        }

        return AgentResult(
            True,
            {
                "receipt": receipt,
                "manifest": manifest,
                "manifest_bytes": manifest_bytes,
                "signature": signature_bytes,
            },
            None,
            {},
        )
