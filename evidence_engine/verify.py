"""Seal and verify hardened EvidenceEngine bundles."""

import argparse
import sys
from pathlib import Path

from evidence_engine.canonical import (
    canonical_json_bytes,
    parse_json_strict,
)
from evidence_engine.collect import provenance_for
from evidence_engine.manifest import write_manifest, sha256_file
from evidence_engine.schema import validate_manifest
from evidence_engine.signing import (
    KEY_ID,
    sign_bytes,
    verify_bytes,
)


def seal(artifacts: Path, output: Path, private_key: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)

    manifest_path = output / "manifest.json"
    signature_path = output / "manifest.sig"

    write_manifest(
        artifacts,
        manifest_path,
        provenance_for(Path.cwd()),
        KEY_ID,
    )

    signed_bytes = manifest_path.read_bytes()
    signature_path.write_bytes(sign_bytes(private_key, signed_bytes))

    print(f"Sealed {artifacts} with key ID {KEY_ID}")


def verify_bundle(
    artifacts: Path,
    manifest_path: Path,
    signature_path: Path,
    public_key: Path,
    expected_key_id: str,
) -> bool:
    try:
        manifest_bytes = manifest_path.read_bytes()
        signature = signature_path.read_bytes()

        # Reject noncanonical signed JSON rather than silently normalizing it.
        manifest = parse_json_strict(manifest_bytes)

        if canonical_json_bytes(manifest) != manifest_bytes:
            print("FAIL: manifest is not canonical JSON")
            return False

        # Validate the signed data before using any of its fields.
        validate_manifest(manifest)

        if manifest["key_id"] != expected_key_id:
            print("FAIL: unexpected signing key ID")
            return False

        if not verify_bytes(public_key, manifest_bytes, signature):
            print("FAIL: manifest signature is invalid")
            return False

        entries = manifest["artifacts"]
        expected_names = {entry["name"] for entry in entries}
        actual_names = set()

        for path in artifacts.iterdir():
            if path.is_symlink():
                print(f"FAIL: symbolic link found: {path.name}")
                return False

            if not path.is_file():
                print(f"FAIL: unexpected directory or special entry: {path.name}")
                return False

            actual_names.add(path.name)

        if actual_names != expected_names:
            print("FAIL: artifact set differs from manifest")
            return False

        for entry in entries:
            path = artifacts / entry["name"]

            if path.stat().st_size != entry["size_bytes"]:
                print(f"FAIL: size mismatch: {entry['name']}")
                return False

            if sha256_file(path) != entry["sha256"]:
                print(f"FAIL: digest mismatch: {entry['name']}")
                return False

        print("PASS: manifest is canonical and schema-valid")
        print(f"PASS: signature verified with expected key ID {expected_key_id}")
        print(f"PASS: verified {len(entries)} required artifacts")
        return True

    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(f"FAIL: verification error: {exc}")
        return False


def main() -> None:
    parser = argparse.ArgumentParser()
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
    verify_parser.add_argument("--expected-key-id", required=True)

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
            args.expected_key_id,
        )
        if not success:
            sys.exit(1)

    except (OSError, ValueError, TypeError) as exc:
        print(f"FAIL: operation error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()