"""Read-only deployment preflight for production trust material."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from evidence_engine.trust import load_trusted_key_bytes


def validate_trust_deployment(
    registry_path: Path,
    expected_key_id: str,
    expected_source: str,
) -> None:
    """Validate one configured trust identity using the production loader."""
    if not expected_key_id:
        raise ValueError("Expected key ID must not be empty")

    if not expected_source:
        raise ValueError("Expected source must not be empty")

    load_trusted_key_bytes(
        registry_path,
        expected_key_id,
        expected_source,
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Return zero only when the selected trust identity is valid."""
    parser = argparse.ArgumentParser(
        description=(
            "Validate deployed trust material using the "
            "production Evidence Engine trust loader."
        )
    )
    parser.add_argument(
        "--trust-registry",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--expected-key-id",
        required=True,
    )
    parser.add_argument(
        "--expected-source",
        required=True,
    )

    args = parser.parse_args(argv)

    try:
        validate_trust_deployment(
            args.trust_registry,
            args.expected_key_id,
            args.expected_source,
        )
    except (OSError, ValueError, TypeError) as exc:
        print(
            f"FAIL: trust deployment validation failed: {exc}",
            file=sys.stderr,
        )
        return 1

    print("PASS: trust deployment validation succeeded")
    return 0


if __name__ == "__main__":
    sys.exit(main())
