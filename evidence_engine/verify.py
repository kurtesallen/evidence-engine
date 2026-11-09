"""Seal and verify hardened EvidenceEngine bundles."""

import argparse
import os
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization

from evidence_engine.agents.artifact_staging import (
    stage_sanitized_artifacts,
)
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
from evidence_engine.policy import PolicyEngine
from evidence_engine.sanitization import (
    TERRAFORM_JSON_CONTENT_RULE_VERSION,
)
from evidence_engine.schema import validate_manifest
from evidence_engine.signing import KEY_ID, sign_bytes
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
    terraform_root: Path | None = None,
    require_provider_lock: bool = False,
    artifact_metadata: Mapping[str, Mapping[str, Any]] | None = None,
) -> None:
    """
    Create a canonical, signed evidence manifest.

    Local mode uses an RSA private-key file.
    KMS mode uses an AWS KMS asymmetric signing key.

    Local manifests use schema v1.1.
    GitHub Actions manifests use schema v1.3 and include
    CI ordering and workflow provenance claims.

    GitHub Actions sealing requires explicit artifact metadata.
    Both plan.json and state.json must be sanitized using the
    configured Terraform JSON sanitization rule.

    When metadata is supplied locally, the same staging and
    sanitization policy is applied.

    The Terraform version in provenance is derived from the
    staged plan.json and state.json documents.
    """
    repository = Path.cwd().resolve()

    # Determine the execution environment before validating metadata.
    is_ci = os.environ.get("GITHUB_ACTIONS", "").lower() == "true"

    # Invalidate any previous signature before attempting a reseal.
    # A failed reseal must not leave an old signature alongside a
    # potentially updated manifest or artifact set.
    output.mkdir(parents=True, exist_ok=True)

    manifest_path = output / "manifest.json"
    signature_path = output / "manifest.sig"

    signature_path.unlink(missing_ok=True)

    if not artifacts.is_dir() or artifacts.is_symlink():
        raise ValueError(
            "Artifacts path must be an existing, non-symlink directory"
        )

    if signing_mode not in {"local", "kms"}:
        raise ValueError("Signing mode must be 'local' or 'kms'")

    if signing_mode == "local":
        if private_key is None:
            raise ValueError(
                "A private-key path is required for local signing"
            )
        key_id = KEY_ID
    else:
        if not isinstance(kms_key_id, str) or not kms_key_id.strip():
            raise ValueError(
                "A KMS key ID or ARN is required for KMS signing"
            )
        key_id = kms_key_id

    # Local sealing remains on schema v1.1.
    # CI sealing uses schema v1.3 with ordered provenance and stream ID.
    schema_version = "1.1"

    # ----------------------------------------------------------------------
    # Provenance
    # ----------------------------------------------------------------------
    if is_ci:
        context = capture_ci_context()

        try:
            result = subprocess.run(
                [
                    "git",
                    "-C",
                    str(repository),
                    "rev-parse",
                    "HEAD",
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (
            OSError,
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
        ) as exc:
            raise ValueError(
                "Cannot verify checked-out Git commit in CI"
            ) from exc

        checked_out_sha = result.stdout.strip().lower()

        if checked_out_sha != context["commit_sha"]:
            raise ValueError(
                "CI commit SHA does not match checked-out Git commit"
            )

        # CI must explicitly declare how every required artifact
        # is represented and which sanitization rule was applied.
        if artifact_metadata is None:
            raise ValueError(
                "Explicit artifact metadata is required in GitHub Actions"
            )

        if terraform_root is None:
            raise ValueError(
                "A Terraform root is required when sealing in GitHub Actions"
            )

        require_provider_lock = True

        provenance = provenance_for(
            repository,
            terraform_root=terraform_root,
            require_provider_lock=require_provider_lock,
        )

        provenance["repository"] = context["repository"]
        provenance["commit_sha"] = context["commit_sha"]
        provenance["workflow_run_id"] = context["run_id"]
        provenance["source"] = "github-actions-claimed"

        # Schema v1.3 ordered CI fields and stream identity.
        provenance["ref"] = context["ref"]
        provenance["workflow_ref"] = context["workflow_ref"]
        provenance["run_number"] = context["run_number"]
        provenance["run_attempt"] = context["run_attempt"]
        provenance["stream_id"] = context["stream_id"]

        schema_version = "1.3"

    else:
        provenance = provenance_for(
            repository,
            terraform_root=terraform_root,
            require_provider_lock=require_provider_lock,
        )

    # ----------------------------------------------------------------------
    # Artifact staging and sanitization
    # ----------------------------------------------------------------------
    sealed_artifacts = artifacts

    # CI publication always requires staging and sanitization.
    # Local callers retain legacy behavior when metadata is omitted.
    if is_ci or artifact_metadata is not None:
        staged_artifacts = output / "artifacts"

        stage_sanitized_artifacts(
            source_root=artifacts,
            destination_root=staged_artifacts,
            artifact_metadata=artifact_metadata,
        )

        # Read the staged documents after sanitization. This ensures
        # the manifest records the version contained in the evidence
        # actually being sealed, rather than caller-supplied provenance.
        try:
            plan_document = parse_json_strict(
                (staged_artifacts / "plan.json").read_bytes()
            )
            state_document = parse_json_strict(
                (staged_artifacts / "state.json").read_bytes()
            )
        except (OSError, ValueError, TypeError) as exc:
            raise ValueError(
                "Unable to read staged Terraform plan/state documents"
            ) from exc

        if not isinstance(plan_document, dict) or not isinstance(
            state_document, dict
        ):
            raise ValueError(
                "Staged Terraform plan/state must be JSON objects"
            )

        plan_version = plan_document.get("terraform_version")
        state_version = state_document.get("terraform_version")

        if (
            not isinstance(plan_version, str)
            or not plan_version.strip()
            or not isinstance(state_version, str)
            or not state_version.strip()
        ):
            raise ValueError(
                "Staged Terraform documents must contain terraform_version"
            )

        if plan_version != state_version:
            raise ValueError(
                "Terraform version mismatch between staged plan and state"
            )

        provenance["terraform_version"] = plan_version
        sealed_artifacts = staged_artifacts

    # ----------------------------------------------------------------------
    # Manifest creation
    # ----------------------------------------------------------------------
    write_manifest(
        sealed_artifacts,
        manifest_path,
        provenance,
        key_id,
        schema_version=schema_version,
        artifact_metadata=artifact_metadata,
    )

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

    print(
        f"Sealed {sealed_artifacts} with key ID {key_id} "
        f"using {signing_mode} signing (schema v{schema_version})"
    )


# ---------------------------------------------------------------------------
# Terraform provenance verification
# ---------------------------------------------------------------------------


def _verify_terraform_version_provenance(
    artifacts: Path,
    manifest: Mapping[str, Any],
) -> bool:
    """
    Verify Terraform artifact representation and version provenance.

    Legacy schema v1.1 bundles with both Terraform artifacts declared
    as raw or sample retain compatibility.

    All sanitized bundles must declare the currently supported
    sanitization rule version. Plan and state must both be sanitized,
    and their Terraform versions must match each other and the
    manifest provenance.

    Schemas v1.2 and v1.3 require both Terraform artifacts to be
    sanitized.
    """
    schema_version = manifest.get("schema_version")

    entries = {
        entry["name"]: entry
        for entry in manifest["artifacts"]
    }

    plan_entry = entries.get("plan.json")
    state_entry = entries.get("state.json")

    if not isinstance(plan_entry, Mapping) or not isinstance(
        state_entry, Mapping
    ):
        print("FAIL: Terraform artifact metadata is missing")
        return False

    plan_representation = plan_entry.get("representation")
    state_representation = state_entry.get("representation")

    plan_sanitized = plan_representation == "sanitized"
    state_sanitized = state_representation == "sanitized"

    modern_schema = schema_version in {"1.2", "1.3"}

    # Modern CI schemas must never accept raw or sample Terraform
    # artifacts, even when both artifacts use the same representation.
    if modern_schema and not (
        plan_sanitized and state_sanitized
    ):
        print(
            "FAIL: schema v1.2/v1.3 requires sanitized "
            "plan.json and state.json"
        )
        return False

    # Preserve compatibility for legacy v1.1 bundles.
    if not plan_sanitized and not state_sanitized:
        return True

    if not plan_sanitized or not state_sanitized:
        print(
            "FAIL: plan and state must both declare "
            "sanitized representation"
        )
        return False

    # Both sanitized artifacts must identify the same supported
    # sanitization rules.
    expected_rule_version = (
        TERRAFORM_JSON_CONTENT_RULE_VERSION
    )

    for name, entry in (
        ("plan.json", plan_entry),
        ("state.json", state_entry),
    ):
        rule_version = entry.get("sanitization_rule_version")

        if rule_version != expected_rule_version:
            print(
                f"FAIL: unsupported sanitization rule version "
                f"for {name}: {rule_version!r}"
            )
            return False

    provenance = manifest["provenance"]
    provenance_version = provenance.get("terraform_version")

    if (
        not isinstance(provenance_version, str)
        or not provenance_version.strip()
    ):
        print(
            "FAIL: sanitized Terraform bundle lacks "
            "provenance version"
        )
        return False

    try:
        plan_document = parse_json_strict(
            (artifacts / "plan.json").read_bytes()
        )
        state_document = parse_json_strict(
            (artifacts / "state.json").read_bytes()
        )
    except (OSError, ValueError, TypeError):
        print(
            "FAIL: unable to parse Terraform plan/state evidence"
        )
        return False

    if not isinstance(plan_document, dict) or not isinstance(
        state_document, dict
    ):
        print(
            "FAIL: Terraform plan/state evidence "
            "must be JSON objects"
        )
        return False

    plan_version = plan_document.get("terraform_version")
    state_version = state_document.get("terraform_version")

    if (
        not isinstance(plan_version, str)
        or not plan_version.strip()
        or not isinstance(state_version, str)
        or not state_version.strip()
    ):
        print(
            "FAIL: Terraform plan/state version is missing"
        )
        return False

    if plan_version != state_version:
        print(
            "FAIL: Terraform plan/state versions do not match"
        )
        return False

    if provenance_version != plan_version:
        print(
            "FAIL: Terraform provenance version "
            "does not match evidence"
        )
        return False

    return True


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

        # Apply the same fail-closed integrity policy used during signing.
        # Reject invalid representation metadata before trust resolution
        # or signature verification.
        decision = PolicyEngine().evaluate_integrity(
            manifest=manifest,
        )

        if not decision.allowed:
            print(
                "FAIL: integrity policy rejected manifest: "
                f"{decision.reason}"
            )
            return False

        if manifest["key_id"] != expected_key_id:
            print("FAIL: unexpected signing key ID")
            return False

        # Resolve the trusted public key authorized for this source.
        trusted_key_path = resolve_trusted_key(
            trust_registry,
            expected_key_id,
            manifest["provenance"]["source"],
        )

        public_key_pem = trusted_key_path.read_bytes()

        # Load PEM or DER public key material.
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem
            )
        except ValueError:
            public_key = serialization.load_der_public_key(
                public_key_pem
            )

        public_key_der = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Verify the signature over the exact canonical manifest bytes.
        if not kms_verify_bytes(
            public_key_der,
            manifest_bytes,
            signature,
        ):
            print("FAIL: manifest signature is invalid")
            return False

        if not artifacts.is_dir():
            print("FAIL: artifacts path is not a directory")
            return False

        entries = manifest["artifacts"]
        expected_names = {entry["name"] for entry in entries}
        actual_names = set()

        # Reject symlinks, directories, and unexpected entries.
        for path in artifacts.iterdir():
            if path.is_symlink():
                print(f"FAIL: symbolic link found: {path.name}")
                return False

            if not path.is_file():
                print(
                    "FAIL: unexpected directory or special entry: "
                    f"{path.name}"
                )
                return False

            actual_names.add(path.name)

        if actual_names != expected_names:
            print("FAIL: artifact set differs from manifest")
            return False

        # Validate artifact sizes and SHA-256 digests.
        for entry in entries:
            path = artifacts / entry["name"]

            if path.stat().st_size != entry["size_bytes"]:
                print(f"FAIL: size mismatch: {entry['name']}")
                return False

            if sha256_file(path) != entry["sha256"]:
                print(f"FAIL: digest mismatch: {entry['name']}")
                return False

        # Independently verify Terraform representation and version
        # provenance after confirming files match the signed manifest.
        if not _verify_terraform_version_provenance(
            artifacts,
            manifest,
        ):
            return False

        print(
            "PASS: manifest is canonical and schema-valid "
            f"(v{manifest['schema_version']})"
        )
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
    """Parse command-line arguments and run the requested operation."""
    parser = argparse.ArgumentParser(
        description="Seal and verify EvidenceEngine bundles."
    )
    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    # ----------------------------------------------------------------------
    # Seal command
    # ----------------------------------------------------------------------
    seal_parser = subparsers.add_parser(
        "seal",
        help="Create a signed evidence manifest.",
    )
    seal_parser.add_argument(
        "--artifacts",
        type=Path,
        required=True,
    )
    seal_parser.add_argument(
        "--output",
        type=Path,
        required=True,
    )
    seal_parser.add_argument(
        "--signing-mode",
        choices=["local", "kms"],
        default="local",
        help="Choose local RSA signing or AWS KMS signing.",
    )
    seal_parser.add_argument(
        "--private-key",
        type=Path,
        help="Private-key path for local signing.",
    )
    seal_parser.add_argument(
        "--kms-key-id",
        help="AWS KMS asymmetric key ID or ARN.",
    )
    seal_parser.add_argument(
        "--aws-region",
        default="us-east-1",
        help="AWS region containing the KMS key.",
    )
    seal_parser.add_argument(
        "--terraform-root",
        type=Path,
        help="Terraform configuration root containing .terraform.lock.hcl.",
    )
    seal_parser.add_argument(
        "--require-provider-lock",
        action="store_true",
        help="Fail if the Terraform root or provider lockfile is missing.",
    )
    seal_parser.add_argument(
        "--artifact-metadata",
        type=Path,
        help=(
            "JSON file describing the representation and sanitization "
            "rule version of each artifact."
        ),
    )

    # ----------------------------------------------------------------------
    # Verify command
    # ----------------------------------------------------------------------
    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify a signed evidence bundle.",
    )
    verify_parser.add_argument(
        "--artifacts",
        type=Path,
        required=True,
    )
    verify_parser.add_argument(
        "--manifest",
        type=Path,
        required=True,
    )
    verify_parser.add_argument(
        "--signature",
        type=Path,
        required=True,
    )
    verify_parser.add_argument(
        "--trust-registry",
        type=Path,
        default=Path("config/trust_registry.json"),
    )
    verify_parser.add_argument(
        "--expected-key-id",
        required=True,
    )

    args = parser.parse_args()

    try:
        if args.command == "seal":
            artifact_metadata = None

            if args.artifact_metadata is not None:
                artifact_metadata = parse_json_strict(
                    args.artifact_metadata.read_bytes()
                )

                if not isinstance(artifact_metadata, dict):
                    raise ValueError(
                        "Artifact metadata file must contain a JSON object"
                    )

            seal(
                args.artifacts,
                args.output,
                args.private_key,
                signing_mode=args.signing_mode,
                kms_key_id=args.kms_key_id,
                aws_region=args.aws_region,
                terraform_root=args.terraform_root,
                require_provider_lock=args.require_provider_lock,
                artifact_metadata=artifact_metadata,
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