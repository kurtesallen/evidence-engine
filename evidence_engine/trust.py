"""Load and enforce the local EvidenceEngine trust registry."""

import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


ALLOWED_STATUSES = {"active", "revoked", "retired"}
ALLOWED_SOURCES = {
    "local-claimed",
    "github-actions-claimed",
}


def load_trust_registry(registry_path: Path) -> dict[str, Any]:
    """Load a trust registry and reject malformed structures."""
    try:
        registry = json.loads(registry_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot load trust registry: {exc}") from exc

    if not isinstance(registry, dict):
        raise ValueError("Trust registry must be a JSON object")

    if set(registry) != {"schema_version", "keys"}:
        raise ValueError("Trust registry has missing or unknown fields")

    if registry["schema_version"] != "1.0":
        raise ValueError("Unsupported trust registry schema")

    entries = registry["keys"]

    if not isinstance(entries, list):
        raise ValueError("Trust registry keys must be a list")

    seen_ids = set()

    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Trust registry key entry must be an object")

        if set(entry) != {
            "key_id",
            "public_key",
            "status",
            "allowed_sources",
        }:
            raise ValueError("Trust registry key has missing or unknown fields")

        key_id = entry["key_id"]
        public_key = entry["public_key"]
        status = entry["status"]
        allowed_sources = entry["allowed_sources"]

        if not isinstance(key_id, str) or not key_id or len(key_id) > 128:
            raise ValueError("Invalid trust registry key ID")

        if key_id in seen_ids:
            raise ValueError(f"Duplicate trust registry key ID: {key_id}")

        seen_ids.add(key_id)

        if not isinstance(public_key, str) or not public_key:
            raise ValueError(f"Invalid public key path: {key_id}")

        if status not in ALLOWED_STATUSES:
            raise ValueError(f"Invalid key status: {key_id}")

        if (
            not isinstance(allowed_sources, list)
            or any(
                not isinstance(source, str)
                or source not in ALLOWED_SOURCES
                for source in allowed_sources
            )
            or len(allowed_sources) != len(set(allowed_sources))
        ):
            raise ValueError(f"Invalid allowed_sources: {key_id}")

    return registry


def resolve_trusted_key(
    registry_path: Path,
    key_id: str,
    source: str,
) -> Path:
    """Return a public key only if registry policy authorizes it."""
    registry = load_trust_registry(registry_path)

    matches = [
        entry for entry in registry["keys"]
        if entry["key_id"] == key_id
    ]

    if len(matches) != 1:
        raise ValueError("Unknown or ambiguous signing key ID")

    entry = matches[0]

    if entry["status"] != "active":
        raise ValueError("Signing key is not active")

    if source not in entry["allowed_sources"]:
        raise ValueError("Signing key is not authorized for this source")

    registry_dir = registry_path.resolve().parent
    public_key_path = (registry_dir / entry["public_key"]).resolve()

    # Keep key files within the project directory containing the registry.
    if not public_key_path.is_relative_to(registry_dir.parent):
        raise ValueError("Public key path escapes the configured project")

    if not public_key_path.is_file():
        raise ValueError("Trusted public key file does not exist")

    try:
        key = serialization.load_pem_public_key(public_key_path.read_bytes())
    except (OSError, ValueError) as exc:
        raise ValueError("Trusted public key cannot be loaded") from exc

    if not isinstance(key, rsa.RSAPublicKey) or key.key_size != 2048:
        raise ValueError("Trusted key must be RSA-2048")

    return public_key_path