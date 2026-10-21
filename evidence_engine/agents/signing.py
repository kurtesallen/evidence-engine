
from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from evidence_engine.agents.base import Agent, AgentResult
from evidence_engine.canonical import canonical_json_bytes, parse_json_strict
from evidence_engine.schema import validate_manifest
from evidence_engine.signing import sign_bytes as local_sign_bytes, KEY_ID
import evidence_engine.kms_signing as kms


SigningMode = Literal["local", "kms"]


class SigningAgent(Agent):
    def __init__(
        self,
        manifest_path: Path,
        signing_mode: SigningMode = "local",
        private_key: Path | None = None,
        kms_key_id: str | None = None,
        aws_region: str = "us-east-1",
    ) -> None:
        super().__init__("signing-agent")
        self._manifest_path = manifest_path
        self._mode = signing_mode
        self._private_key = private_key
        self._kms_key_id = kms_key_id
        self._aws_region = aws_region

    def run(self, **kwargs: Any) -> AgentResult:
        try:
            manifest_bytes = self._manifest_path.read_bytes()
        except OSError as exc:
            return AgentResult(
                False, None, "manifest-read-failed",
                {"exception": str(exc)},
            )

        # Preserve explicit configuration errors.
        if self._mode not in ("local", "kms"):
            return AgentResult(
                False, None, "signing-mode-invalid",
                {"mode": str(self._mode)},
            )

        if self._mode == "local" and self._private_key is None:
            return AgentResult(
                False, None, "local-signing-missing-key", {},
            )

        if self._mode == "kms" and (
            not isinstance(self._kms_key_id, str)
            or not self._kms_key_id.strip()
        ):
            return AgentResult(
                False, None, "kms-signing-missing-key-id", {},
            )

        # Validate the exact bytes that will be signed.
        try:
            manifest = parse_json_strict(manifest_bytes)
        except (ValueError, TypeError) as exc:
            return AgentResult(
                False, None, "manifest-json-invalid",
                {"exception": str(exc)},
            )

        try:
            if canonical_json_bytes(manifest) != manifest_bytes:
                return AgentResult(
                    False, None, "manifest-not-canonical", {},
                )
        except (ValueError, TypeError) as exc:
            return AgentResult(
                False, None, "manifest-json-invalid",
                {"exception": str(exc)},
            )

        try:
            validate_manifest(manifest)
        except (ValueError, TypeError, KeyError) as exc:
            return AgentResult(
                False, None, "manifest-schema-invalid",
                {"exception": str(exc)},
            )

        if self._mode == "local":
            try:
                signature = local_sign_bytes(
                    self._private_key, manifest_bytes
                )
            except Exception as exc:
                return AgentResult(
                    False, None, "local-signing-failed",
                    {"exception": str(exc)},
                )

            key_id = KEY_ID

        else:
            try:
                client = kms.create_kms_client(self._aws_region)
                signature = kms.sign_bytes(
                    client, self._kms_key_id, manifest_bytes
                )
            except Exception as exc:
                return AgentResult(
                    False, None, "kms-signing-failed",
                    {"exception": str(exc)},
                )

            key_id = self._kms_key_id

        return AgentResult(
            True,
            {"signature": signature, "key_id": key_id, "mode": self._mode},
            None,
            {"mode": self._mode},
        )
