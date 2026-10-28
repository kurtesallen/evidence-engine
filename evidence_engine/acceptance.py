
"""Acceptance-state contract and development-only implementation."""

from __future__ import annotations

from threading import Lock
from typing import Literal, Protocol
import re


_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
AcceptanceOutcome = Literal["accepted", "replay", "stale"]


class AcceptanceState(Protocol):
    """Atomic record of whether a bundle digest was already accepted."""

    def accept_once(self, bundle_digest: str) -> bool:
        """Return True for first acceptance; False if already recorded."""
        ...

    def accept_ordered(
        self,
        bundle_digest: str,
        *,
        consumer_id: str,
        stream_id: str,
        run_number: int,
        run_attempt: int,
    ) -> AcceptanceOutcome:
        """Accept a new digest only when its run position advances."""
        ...


class InMemoryAcceptanceState:
    """Thread-safe development/test adapter; not durable or production-safe."""

    def __init__(self) -> None:
        self._accepted: set[str] = set()
        self._ordered_accepted: set[tuple[str, str]] = set()
        self._checkpoints: dict[tuple[str, str], tuple[int, int]] = {}
        self._lock = Lock()

    def accept_once(self, bundle_digest: str) -> bool:
        if not isinstance(bundle_digest, str) or not _DIGEST_RE.fullmatch(
            bundle_digest
        ):
            raise ValueError("Invalid bundle digest")

        with self._lock:
            if bundle_digest in self._accepted:
                return False

            self._accepted.add(bundle_digest)
            return True

    def accept_ordered(
        self,
        bundle_digest: str,
        *,
        consumer_id: str,
        stream_id: str,
        run_number: int,
        run_attempt: int,
    ) -> AcceptanceOutcome:
        """Atomically record a digest and advance its stream checkpoint."""
        if not isinstance(bundle_digest, str) or not _DIGEST_RE.fullmatch(
            bundle_digest
        ):
            raise ValueError("Invalid bundle digest")

        if not isinstance(consumer_id, str) or not _IDENTIFIER_RE.fullmatch(
            consumer_id
        ):
            raise ValueError("Invalid consumer ID")

        if not isinstance(stream_id, str) or not _IDENTIFIER_RE.fullmatch(
            stream_id
        ):
            raise ValueError("Invalid stream ID")

        for name, value in (
            ("run_number", run_number),
            ("run_attempt", run_attempt),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"Invalid {name}")

        digest_key = (consumer_id, bundle_digest)
        checkpoint_key = (consumer_id, stream_id)
        position = (run_number, run_attempt)

        with self._lock:
            if digest_key in self._ordered_accepted:
                return "replay"

            current = self._checkpoints.get(checkpoint_key)
            if current is not None and position <= current:
                return "stale"

            self._ordered_accepted.add(digest_key)
            self._checkpoints[checkpoint_key] = position
            return "accepted"
