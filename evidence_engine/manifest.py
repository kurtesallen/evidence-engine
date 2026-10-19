"""Build and serialize EvidenceEngine manifest v1.1."""

import hashlib
from pathlib import Path

from evidence_engine.canonical import canonical_json_bytes
from evidence_engine.schema import validate_manifest


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def build_manifest(
    artifact_dir: Path,
    provenance: dict,
    key_id: str,
) -> dict:
    if not artifact_dir.is_dir():
        raise ValueError("Artifact directory does not exist")

    artifacts = []

    for path in sorted(artifact_dir.iterdir()):
        if path.is_symlink():
            raise ValueError(f"Symlinks are not allowed: {path.name}")

        if not path.is_file():
            raise ValueError(f"Unexpected directory or special entry: {path.name}")

        artifacts.append(
            {
                "name": path.name,
                "size_bytes": path.stat().st_size,
                "representation": "sample",
                "sanitization_rule_version": None,
                "sha256": sha256_file(path),
            }
        )

    manifest = {
        "schema_version": "1.1",
        "hash_algorithm": "SHA-256",
        "signature_algorithm": "RSA-PSS-SHA256",
        "key_id": key_id,
        "provenance": provenance,
        "artifacts": artifacts,
    }

    validate_manifest(manifest)
    return manifest


def write_manifest(
    artifact_dir: Path,
    destination: Path,
    provenance: dict,
    key_id: str,
) -> dict:
    manifest = build_manifest(artifact_dir, provenance, key_id)

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(canonical_json_bytes(manifest))

    return manifest