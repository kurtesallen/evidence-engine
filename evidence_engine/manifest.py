"""Create SHA-256 manifests for evidence artifacts."""

import hashlib
from pathlib import Path

from evidence_engine.canonical import canonical_json_bytes


def sha256_file(path: Path) -> str:
    """Hash the exact bytes of a file."""
    digest = hashlib.sha256()

    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def build_manifest(artifact_dir: Path) -> dict:
    """Build a manifest from regular files in one artifact directory."""
    if not artifact_dir.is_dir():
        raise ValueError(f"Artifact directory does not exist: {artifact_dir}")

    artifacts = []

    for path in sorted(artifact_dir.iterdir()):
        if path.is_symlink():
            raise ValueError(f"Symlinks are not allowed: {path.name}")

        if not path.is_file():
            continue

        artifacts.append(
            {
                "name": path.name,
                "size_bytes": path.stat().st_size,
                "representation": "sample",
                "sanitization_rule_version": None,
                "sha256": sha256_file(path),
            }
        )

    if not artifacts:
        raise ValueError("Cannot create an empty evidence manifest")

    return {
        "schema_version": "1.0",
        "hash_algorithm": "SHA-256",
        "artifacts": artifacts,
    }


def write_manifest(artifact_dir: Path, destination: Path) -> dict:
    """Write canonical manifest bytes to a separate destination."""
    manifest = build_manifest(artifact_dir)

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(canonical_json_bytes(manifest))

    return manifest