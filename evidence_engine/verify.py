"""Seal and independently verify an EvidenceEngine bundle."""

import argparse
import json
import sys
from pathlib import Path

from evidence_engine.canonical import canonical_json_bytes
from evidence_engine.manifest import write_manifest, sha256_file
from evidence_engine.signing import sign_bytes, verify_bytes


def seal(
    artifacts: Path,
    output: Path,
    private_key: Path,
) -> None:
    """Create a manifest and detached signature."""
    output.mkdir(parents=True, exist_ok=True)

    manifest_path = output / "manifest.json"
    signature_path = output / "manifest.sig"

    manifest = write_manifest(artifacts, manifest_path)
    manifest_bytes = canonical_json_bytes(manifest)

    # Confirm the stored manifest contains the exact signed bytes.
    if manifest_path.read_bytes() != manifest_bytes:
        raise ValueError("Manifest serialization mismatch")

    signature = sign_bytes(private_key, manifest_bytes)
    signature_path.write_bytes(signature)

    print(f"Manifest: {manifest_path}")
    print(f"Signature: {signature_path}")
    print(f"Artifacts: {len(manifest['artifacts'])}")


def verify_bundle(
    artifacts: Path,
    manifest_path: Path,
    signature_path: Path,
    public_key: Path,
) -> bool:
    """Verify signature, schema, completeness, and artifact digests."""
    manifest_bytes = manifest_path.read_bytes()
    signature = signature_path.read_bytes()

    # First authenticate the exact manifest bytes.
    if not verify_bytes(public_key, manifest_bytes, signature):
        print("FAIL: manifest signature is invalid")
        return False

    try:
        manifest = json.loads(manifest_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError):
        print("FAIL: manifest is not valid JSON")
        return False

    # Require the format used by this lesson.
    if not isinstance(manifest, dict):
        print("FAIL: manifest must be a JSON object")
        return False

    if manifest.get("schema_version") != "1.0":
        print("FAIL: unsupported manifest schema")
        return False

    if manifest.get("hash_algorithm") != "SHA-256":
        print("FAIL: unsupported hash algorithm")
        return False

    entries = manifest.get("artifacts")
    if not isinstance(entries, list) or not entries:
        print("FAIL: manifest has no artifacts")
        return False

    seen_names = set()

    for entry in entries:
        if not isinstance(entry, dict):
            print("FAIL: malformed artifact entry")
            return False

        name = entry.get("name")

        # Only accept a plain filename, never a path supplied by a manifest.
        if (
            not isinstance(name, str)
            or not name
            or Path(name).name != name
            or name in {".", ".."}
        ):
            print("FAIL: invalid artifact name")
            return False

        if name in seen_names:
            print(f"FAIL: duplicate artifact entry: {name}")
            return False

        seen_names.add(name)

        path = artifacts / name

        if path.is_symlink() or not path.is_file():
            print(f"FAIL: artifact missing or unsafe: {name}")
            return False

        if path.stat().st_size != entry.get("size_bytes"):
            print(f"FAIL: size mismatch: {name}")
            return False

        if sha256_file(path) != entry.get("sha256"):
            print(f"FAIL: digest mismatch: {name}")
            return False

    # Reject unlisted regular files: the bundle must match the manifest.
    actual_names = set()

    for path in artifacts.iterdir():
        if path.is_symlink():
            print(f"FAIL: unexpected symlink: {path.name}")
            return False
        if path.is_file():
            actual_names.add(path.name)

    if actual_names != seen_names:
        print("FAIL: artifact set differs from manifest")
        return False

    print("PASS: manifest signature is valid")
    print(f"PASS: verified {len(seen_names)} artifacts")
    print("PASS: artifact sizes and SHA-256 digests match")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Seal or verify an EvidenceEngine evidence bundle."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    seal_parser = subparsers.add_parser("seal")
    seal_parser.add_argument("--artifacts", type=Path, required=True)
    seal_parser.add_argument("--output", type=Path, required=True)
    seal_parser.add_argument("--private-key", type=Path, required=True)

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--artifacts", type=Path, required=True)
    verify_parser.add_argument("--manifest", type=Path, required=True)
    verify_parser.add_argument("--signature", type=Path, required=True)
    verify_parser.add_argument("--public-key", type=Path, required=True)

    args = parser.parse_args()

    try:
        if args.command == "seal":
            seal(args.artifacts, args.output, args.private_key)
            return

        success = verify_bundle(
            args.artifacts,
            args.manifest,
            args.signature,
            args.public_key,
        )
        if not success:
            sys.exit(1)

    except (OSError, ValueError, TypeError) as exc:
        print(f"FAIL: verification or sealing error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()