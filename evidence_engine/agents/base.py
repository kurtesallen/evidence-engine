from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class AgentResult:
    """
    Standard result contract for all EvidenceEngine agents.

    - success: True for successful execution, False for any failure.
    - data: structured output on success; None or minimal on failure.
    - error: machine-readable error code on failure; None on success.
    - audit: structured audit metadata (inputs, decisions, context).
    """

    success: bool
    data: Mapping[str, Any] | None
    error: str | None
    audit: Mapping[str, Any]


class Agent:
    """
    Base interface for all EvidenceEngine agents.

    Each agent has:
    - a stable, machine-readable name
    - a run() method that returns AgentResult
    """

    name: str

    def __init__(self, name: str) -> None:
        # Fail fast on invalid names BEFORE any other checks
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Agent name must be a non-empty string")
        self.name = name

    def run(self, **kwargs: Any) -> AgentResult:
        """
        Default implementation: agents must override this method.

        The base class provides a predictable failure so tests can
        instantiate Agent safely without triggering ABC TypeError.
        """
        return AgentResult(
            success=False,
            data=None,
            error="agent-run-not-implemented",
            audit={"agent": self.name},
        )
