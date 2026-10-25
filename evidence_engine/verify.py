"""
Seal and verify hardened EvidenceEngine bundles.
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from evidence_engine.canonical import (
    canonical_json_bytes,
    parse_json_strict,
)
from evidence_engine.ci_provenance import capture_ci_context
from evidence_engine.collect import provenance_for
from evidence_engine.kms_signing import (
    create_kms_client,
    sign_bytes as kms_sign_bytes,
    verify_bytes as kms_verify_bytes,
)
from evidence_engine.manifest import sha256_file, write_manifest
from evidence_engine.schema import validate_manifest
from evidence_engine.signing import KEY_ID, sign_bytes, verify_bytes
from evidence_engine.trust import resolve_trusted_key


# ---------------------------------------------------------------------------
# Sealing
# ---------------------------------------------------------------------------

def seal(
    artifacts: Path,
    output: Path,
    private_key: Path | None = None,
    *,
    signing_mode: str = "local",
    kms_key_id: str | None = None,
    aws_region: str = "us-east-1",
) -> None:
    """
    Create a canonical, signed evidence manifest.

    Local mode uses an RSA private-key file.
    KMS mode uses an AWS KMS asymmetric signing key.
    """
    repository = Path.cwd().resolve()

    if not artifacts.is_dir():
        raise ValueError(f"Artifacts directory does not exist: {artifacts}")

    if signing_mode not in {"local", "kms"}:
        raise ValueError("Signing mode must be 'local' or 'kms'")

    if signing_mode == "local":
        if private_key is None:
            raise ValueError("A private-key path is required for local signing")
        key_id = KEY_ID
    else:
        if not isinstance(kms_key_id, str) or not kms_key_id.strip():
            raise ValueError("A KMS key ID or ARN is required for KMS signing")
        key_id = kms_key_id

    # ----------------------------------------------------------------------
    # CI provenance validation
    # ----------------------------------------------------------------------
    if os.environ.get("GITHUB_ACTIONS", "").lower() == "true":
        context = capture_ci_context()

        try:
            result = subprocess.run(
                ["git", "-C", str(repository), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            raise ValueError("Cannot verify checked-out Git commit in CI") from exc

        checked_out_sha = result.stdout.strip().lower()

        if checked_out_sha != context["commit_sha"]:
            raise ValueError("CI commit SHA does not match checked-out Git commit")

        provenance = provenance_for(repository)
        provenance["repository"] = context["repository"]
        provenance["commit_sha"] = context["commit_sha"]
        provenance["workflow_run_id"] = context["run_id"]
        provenance["source"] = "github-actions-claimed"

    else:
        provenance = provenance_for(repository)

    # ----------------------------------------------------------------------
    # Output directory + manifest creation
    # ----------------------------------------------------------------------
    output.mkdir(parents=True, exist_ok=True)

    manifest_path = output / "manifest.json"
    signature_path = output / "manifest.sig"

    write_manifest(artifacts, manifest_path, provenance, key_id)

    manifest_bytes = manifest_path.read_bytes()

    # ----------------------------------------------------------------------
    # Signing
    # ----------------------------------------------------------------------
    if signing_mode == "local":
        signature = sign_bytes(private_key, manifest_bytes)
    else:
        client = create_kms_client(aws_region)
        signature = kms_sign_bytes(client, key_id, manifest_bytes)

    signature_path.write_bytes(signature)

    print(f"Sealed {artifacts} with key ID {key_id} using {signing_mode} signing")


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify_bundle(
    artifacts: Path,
    manifest_path: Path,
    signature_path: Path,
    trust_registry: Path,
    expected_key_id: str,
) -> bool:
    """Verify manifest authenticity and artifact integrity."""
    try:
        manifest_bytes = manifest_path.read_bytes()
        signature = signature_path.read_bytes()

        manifest = parse_json_strict(manifest_bytes)

        if canonical_json_bytes(manifest) != manifest_bytes:
            print("FAIL: manifest is not canonical JSON")
            return False

        validate_manifest(manifest)

        if manifest["key_id"] != expected_key_id:
            print("FAIL: unexpected signing key ID")
            return False

        # Resolve trusted key
        trusted_key_path = resolve_trusted_key(
            trust_registry,
            expected_key_id,
            manifest["provenance"]["source"],
        )

        public_key_pem = trusted_key_path.read_bytes()

        # Load PEM or DER
        try:
            public_key = serialization.load_pem_public_key(public_key_pem)
        except ValueError:
            public_key = serialization.load_der_public_key(public_key_pem)

        public_key_der = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        if not kms_verify_bytes(public_key_der, manifest_bytes, signature):
            print("FAIL: manifest signature is invalid")
            return False

        if not artifacts.is_dir():
            print("FAIL: artifacts path is not a directory")
            return False

        entries = manifest["artifacts"]
        expected_names = {entry["name"] for entry in entries}
        actual_names = set()

        # Reject symlinks, directories, unexpected entries
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

        # Validate size + digest
        for entry in entries:
            path = artifacts / entry["name"]

            if path.stat().st_size != entry["size_bytes"]:
                print(f"FAIL: size mismatch: {entry['name']}")
                return False

            if sha256_file(path) != entry["sha256"]:
                print(f"FAIL: digest mismatch: {entry['name']}")
                return False

        print("PASS: manifest is canonical and schema-valid")
        print(f"PASS: trusted key authorized: {expected_key_id}")
        print("PASS: manifest signature verified")
        print(f"PASS: verified {len(entries)} required artifacts")
        return True

    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(f"FAIL: verification error: {exc}")
        return False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    """Parse CLI arguments and run the requested operation."""
    parser = argparse.ArgumentParser(
        description="Seal and verify EvidenceEngine bundles."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # ----------------------------------------------------------------------
    # Seal command
    # ----------------------------------------------------------------------
    seal_parser = subparsers.add_parser("seal", help="Create a signed evidence manifest.")
    seal_parser.add_argument("--artifacts", type=Path, required=True)
    seal_parser.add_argument("--output", type=Path, required=True)
    seal_parser.add_argument(
        "--signing-mode",
        choices=["local", "kms"],
        default="local",
        help="Choose local RSA signing or AWS KMS signing.",
    )
    seal_parser.add_argument("--private-key", type=Path, help="Private-key path for local signing.")
    seal_parser.add_argument("--kms-key-id", help="AWS KMS asymmetric key ID or ARN.")
    seal_parser.add_argument("--aws-region", default="us-east-1", help="AWS region containing the KMS key.")

    # ----------------------------------------------------------------------
    # Verify command
    # ----------------------------------------------------------------------
    verify_parser = subparsers.add_parser("verify", help="Verify a signed evidence bundle.")
    verify_parser.add_argument("--artifacts", type=Path, required=True)
    verify_parser.add_argument("--manifest", type=Path, required=True)
    verify_parser.add_argument("--signature", type=Path, required=True)
    verify_parser.add_argument(
        "--trust-registry",
        type=Path,
        default=Path("config/trust_registry.json"),
    )
    verify_parser.add_argument("--expected-key-id", required=True)

    args = parser.parse_args()

    try:
        if args.command == "seal":
            seal(
                args.artifacts,
                args.output,
                args.private_key,
                signing_mode=args.signing_mode,
                kms_key_id=args.kms_key_id,
                aws_region=args.aws_region,
            )
            return

        success = verify_bundle(
            args.artifacts,
            args.manifest,
            args.signature,
            args.trust_registry,
            args.expected_key_id,
        )

        if not success:
            sys.exit(1)

    except (OSError, ValueError, TypeError) as exc:
        print(f"FAIL: operation error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
