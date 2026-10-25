from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Sequence

from evidence_engine.agents.base import Agent, AgentResult
from evidence_engine.policy import PolicyEngine
from evidence_engine.sanitization import Sanitizer, SanitizationRule


class CollectionAgent(Agent):
    """
    Collect only approved evidence files and metadata.

    - Reject symlinks, directories, and unsafe entries.
    - Fail closed on invalid root or policy denial.
    """

    def __init__(
        self,
        root: Path,
        policy: PolicyEngine | None = None,
        sanitizer: Sanitizer | None = None,
    ) -> None:
        super().__init__("collection-agent")
        self._root = root
        self._policy = policy or PolicyEngine()
        self._sanitizer = sanitizer or Sanitizer(
            rules=[
                SanitizationRule(
                    name="normalize_paths",
                    description="Trim whitespace from root path.",
                    version="1.0",
                )
            ]
        )

    def _collect_files(self) -> Sequence[Path]:
        files: list[Path] = []
        for path in sorted(self._root.iterdir(), key=lambda p: p.name):
            if path.is_symlink():
                raise ValueError(f"symlink-rejected:{path.name}")
            if not path.is_file():
                raise ValueError(f"non-file-entry-rejected:{path.name}")
            files.append(path)
        return files

    def run(self, **kwargs: Any) -> AgentResult:
        if not self._root.is_dir():
            return AgentResult(
                success=False,
                data=None,
                error="artifacts-root-not-directory",
                audit={"root": str(self._root)},
            )

        try:
            files = self._collect_files()
        except ValueError as exc:
            return AgentResult(
                success=False,
                data=None,
                error=str(exc),
                audit={"root": str(self._root)},
            )

        raw_metadata: Mapping[str, Any] = {
            "root": str(self._root),
            "files": [p.name for p in files],
        }

        sanitization = self._sanitizer.sanitize_metadata(raw_metadata)
        metadata = sanitization.sanitized

        decision = self._policy.evaluate_collection(metadata)
        if not decision.allowed:
            return AgentResult(
                success=False,
                data=None,
                error=decision.reason,
                audit={
                    "policy_version": self._policy.version,
                    "details": dict(decision.details),
                    "sanitization_rules": list(sanitization.applied_rules),
                },
            )

        return AgentResult(
            success=True,
            data={
                "files": files,
                "metadata": metadata,
                "sanitization_rules": list(sanitization.applied_rules),
            },
            error=None,
            audit={
                "policy_version": self._policy.version,
                "policy_reason": decision.reason,
            },
        )
