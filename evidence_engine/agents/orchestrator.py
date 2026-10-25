from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from evidence_engine.agents.base import Agent, AgentResult
from evidence_engine.agents.collection import CollectionAgent
from evidence_engine.agents.integrity import IntegrityAgent
from evidence_engine.agents.signing import SigningAgent
from evidence_engine.manifest import write_manifest
from evidence_engine.receipt import ReceiptAgent
from evidence_engine.schema import REQUIRED_ARTIFACTS
from evidence_engine.signing import KEY_ID


class Orchestrator(Agent):
    """Coordinate collection, manifest creation, integrity, signing and receipt."""

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

    def run(self, **kwargs: Any) -> AgentResult:
        if self._mode not in ("local", "kms"):
            return AgentResult(False, None, "signing-mode-invalid", {})

        if self._mode == "local":
            if self._private_key is None:
                return AgentResult(False, None, "local-signing-missing-key", {})
            key_id = KEY_ID
        else:
            if (
                not isinstance(self._kms_key_id, str)
                or not self._kms_key_id.strip()
            ):
                return AgentResult(False, None, "kms-signing-missing-key-id", {})
            key_id = self._kms_key_id

        if not self._root.is_dir():
            return AgentResult(False, None, "artifacts-root-not-directory", {})

        # Never put generated bundle files inside the source artifact directory.
        root = self._root.resolve()
        output = self._output.resolve()
        if output == root or root in output.parents:
            return AgentResult(False, None, "output-inside-artifacts-root", {})

        source = self._provenance.get("source")
        if source not in ("local-claimed", "github-actions-claimed"):
            return AgentResult(False, None, "provenance-source-invalid", {})

        collection = CollectionAgent(self._root).run()
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

        manifest_path = self._output / "manifest.json"
        signature_path = self._output / "manifest.sig"

        try:
            self._output.mkdir(parents=True, exist_ok=True)

            # Invalidate any prior signature before replacing the manifest.
            # unlink() removes a symlink itself, not its target.
            signature_path.unlink(missing_ok=True)
        except OSError as exc:
            return AgentResult(
                False,
                None,
                "signature-invalidation-failed",
                {
                    "stage": "signature-invalidation",
                    "exception": str(exc),
                },
            )

        try:
            write_manifest(
                self._root,
                manifest_path,
                self._provenance,
                key_id,
            )
        except (OSError, ValueError, TypeError, KeyError) as exc:
            return AgentResult(
                False,
                None,
                "manifest-creation-failed",
                {"stage": "manifest", "exception": str(exc)},
            )

        integrity = IntegrityAgent(self._root, manifest_path).run()
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
                False,
                None,
                "signature-output-invalid",
                {"stage": "signing"},
            )

        # Persist through a temporary file so a failed write does not leave
        # a partially written signature at the final path.
        temporary_signature = signature_path.with_name(
            signature_path.name + ".tmp"
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
            artifacts_root=self._root,
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

        return AgentResult(
            True,
            {
                "receipt": receipt.data["receipt"],
                "manifest_path": str(manifest_path),
                "signature_path": str(signature_path),
                "key_id": key_id,
                "mode": self._mode,
            },
            None,
            {
                "stages": [
                    "collection",
                    "manifest",
                    "integrity",
                    "signing",
                    "signature-persistence",
                    "receipt",
                ]
            },
        )
