"""Deterministic JSON serialization for EvidenceEngine."""

import json
from typing import Any


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize JSON data deterministically for this prototype.

    This is a constrained teaching format, not a complete
    implementation of RFC 8785 JSON Canonicalization Scheme.
    """
    text = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return text.encode("utf-8")