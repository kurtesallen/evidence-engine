"""RFC 8785 canonical JSON serialization."""

import json
from typing import Any

import rfc8785


def canonical_json_bytes(value: Any) -> bytes:
    """Return RFC 8785 canonical JSON bytes."""
    return rfc8785.dumps(value)


def parse_json_strict(data: bytes) -> Any:
    """Parse UTF-8 JSON while rejecting duplicate object keys."""
    def reject_duplicates(pairs):
        result = {}

        for key, value in pairs:
            if key in result:
                raise ValueError(f"Duplicate JSON key: {key}")
            result[key] = value

        return result

    def reject_nonstandard_constant(value):
        raise ValueError(f"Invalid JSON constant: {value}")

    try:
        text = data.decode("utf-8")

        return json.loads(
            text,
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_nonstandard_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid UTF-8 JSON") from exc