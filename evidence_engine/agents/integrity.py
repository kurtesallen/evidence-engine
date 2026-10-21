from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from evidence_engine.agents.base import Agent, AgentResult
from evidence_engine.policy import PolicyEngine
from evidence_engine.canonical import canonical_json_bytes, parse_json_strict
from evidence_engine.schema import validate_manifest
from evidence_engine.manifest import sha256_file


class IntegrityAgent(Agent):
    def __init__(
        self,
        artifacts_root: Path,
        manifest_path: Path,
        policy: PolicyEngine | None = None,
    ) -> None:
        super().__init__("integrity-agent")
        self._root = artifacts_root
        self._manifest_path = manifest_path
        self._policy = policy or PolicyEngine()

    def run(self, **kwargs: Any) -> AgentResult:
        # Read manifest bytes
        try:
            manifest_bytes = self._manifest_path.read_bytes()
        except Exception as exc:
            return AgentResult(
                success=False,
                data=None,
                error="manifest-read-failed",
                audit={"exception": str(exc)},
            )

        # Parse strict JSON
        try:
            manifest = parse_json_strict(manifest_bytes)
        except Exception as exc:
            return AgentResult(
                success=False,
                data=None,
                error="manifest-json-invalid",
                audit={"exception": str(exc)},
            )

        # Canonical JSON check
        if canonical_json_bytes(manifest) != manifest_bytes:
            return AgentResult(
                success=False,
                data=None,
                error="manifest-not-canonical",
                audit={},
            )

        # Schema validation
        try:
            validate_manifest(manifest)
        except Exception as exc:
            return AgentResult(
                success=False,
                data=None,
                error="manifest-schema-invalid",
                audit={"exception": str(exc)},
            )

        # Artifact set validation
        entries = manifest["artifacts"]
        expected = {e["name"] for e in entries}

        actual = set()
        for path in self._root.iterdir():
            if path.is_symlink():
                return AgentResult(
                    success=False,
                    data=None,
                    error="symlink-rejected",
                    audit={"name": path.name},
                )
            if not path.is_file():
                return AgentResult(
                    success=False,
                    data=None,
                    error="non-file-entry-rejected",
                    audit={"name": path.name},
                )
            actual.add(path.name)

        if actual != expected:
            return AgentResult(
                success=False,
                data=None,
                error="artifact-set-mismatch",
                audit={"expected": sorted(expected), "actual": sorted(actual)},
            )

        # Size + digest validation
        for entry in entries:
            path = self._root / entry["name"]

            if path.stat().st_size != entry["size_bytes"]:
                return AgentResult(
                    success=False,
                    data=None,
                    error="size-mismatch",
                    audit={"name": entry["name"]},
                )

            if sha256_file(path) != entry["sha256"]:
                return AgentResult(
                    success=False,
                    data=None,
                    error="digest-mismatch",
                    audit={"name": entry["name"]},
                )

        # Policy enforcement
        decision = self._policy.evaluate_integrity(manifest)
        if not decision.allowed:
            return AgentResult(
                success=False,
                data=None,
                error=decision.reason,
                audit={"details": dict(decision.details)},
            )

        return AgentResult(
            success=True,
            data={
                "manifest": manifest,
                "manifest_bytes": manifest_bytes,
                "artifacts": entries,
            },
            error=None,
            audit={"policy_reason": decision.reason},
        )
