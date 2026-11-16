
"""Independent verification of experimental restricted Terraform evidence.

Verification authenticates the signed bundle and validates restricted
representation. It does not authorize production consumption or record
replay/rollback acceptance.
"""

import hashlib
import os
import stat
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from evidence_engine.canonical import (
    canonical_json_bytes,
    parse_json_strict,
)
from evidence_engine.kms_signing import verify_bytes as kms_verify_bytes
from evidence_engine.restricted_contract import (
    PROFILE_20,
    PROFILE_21,
    validate_restricted_bytes,
)
from evidence_engine.schema import REQUIRED_ARTIFACTS, validate_manifest
from evidence_engine.trust import load_bounded_trusted_key


_SUPPORTED_PROFILES = frozenset({PROFILE_20, PROFILE_21})

_RESTRICTED_ARTIFACT_LIMITS = {
    "plan.json": 64 * 1024,
    "state.json": 64 * 1024,
    "commit.txt": 4 * 1024,
    "version.txt": 4 * 1024,
}

_RESTRICTED_METADATA_LIMITS = {
    "manifest": 256 * 1024,
    "signature": 4 * 1024,
}


def _reject_symlink_components(path: Path, label: str) -> None:
    """Reject symlinks in every existing component of a filesystem path.

    Convert to an absolute lexical path without resolving symlinks.
    This preserves symlinked ancestors for inspection.
    """
    absolute = Path(os.path.abspath(os.fspath(path)))

    for component in (*reversed(absolute.parents), absolute):
        try:
            if component.is_symlink():
                raise ValueError(
                    f"{label} contains a symlink: {component}"
                )
        except OSError as exc:
            raise ValueError(
                f"Unable to inspect {label}: {component}"
            ) from exc



def _read_restricted_metadata(
    path: Path,
    label: str,
    maximum: int,
) -> bytes:
    """Read a regular metadata file with an explicit size limit."""
    if type(maximum) is not int or maximum < 0:
        raise ValueError(f"Invalid restricted {label} size limit")

    _reject_symlink_components(path, f"Restricted {label}")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)

    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    descriptor = os.open(path, flags)

    try:
        with os.fdopen(descriptor, "rb", buffering=0) as stream:
            metadata = os.fstat(stream.fileno())

            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(
                    f"Restricted {label} is not a regular file"
                )

            if metadata.st_size > maximum:
                raise ValueError(
                    f"Restricted {label} exceeds size limit"
                )

            chunks = []
            remaining = maximum + 1

            while remaining > 0:
                chunk = stream.read(remaining)

                if not chunk:
                    break

                chunks.append(chunk)
                remaining -= len(chunk)

            content = b"".join(chunks)

            if len(content) > maximum:
                raise ValueError(
                    f"Restricted {label} exceeds size limit"
                )

            return content

    except BaseException:
        # os.fdopen() normally transfers descriptor ownership to
        # the stream. If it fails before ownership transfers,
        # ensure the descriptor is not leaked.
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _read_restricted_artifact(
    path: Path,
    name: str,
    expected_size: int,
) -> bytes:
    """Read one regular artifact with a strict size bound.

    Reject excessive signed sizes before opening the artifact.
    Validate the opened descriptor, then read at most the signed
    size plus one byte to detect unexpected additional content.
    """
    maximum = _RESTRICTED_ARTIFACT_LIMITS.get(name)

    if maximum is None:
        raise ValueError("Unknown restricted artifact")

    if (
        type(expected_size) is not int
        or expected_size < 0
        or expected_size > maximum
    ):
        raise ValueError(
            f"Restricted artifact size exceeds policy: {name}"
        )

    _reject_symlink_components(
        path,
        f"Restricted artifact {name}",
    )

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)

    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    descriptor = os.open(path, flags)

    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())

        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(
                f"Restricted artifact is not a regular file: {name}"
            )

        if metadata.st_size != expected_size:
            raise ValueError(
                f"Restricted artifact size mismatch: {name}"
            )

        if metadata.st_size > maximum:
            raise ValueError(
                f"Restricted artifact exceeds size limit: {name}"
            )

        content = stream.read(expected_size + 1)

        if len(content) != expected_size:
            raise ValueError(
                f"Restricted artifact content size mismatch: {name}"
            )

        return content


def verify_restricted_bundle(
    artifacts: Path,
    manifest_path: Path,
    signature_path: Path,
    trust_registry: Path,
    expected_key_id: str,
    *,
    allowed_profiles: frozenset[str],
) -> bool:
    """Verify an explicitly authorized experimental restricted bundle."""
    try:
        if (
            not isinstance(allowed_profiles, frozenset)
            or not all(
                isinstance(profile, str)
                and profile in _SUPPORTED_PROFILES
                for profile in allowed_profiles
            )
        ):
            print("FAIL: invalid restricted profile authorization")
            return False

        if (
            not isinstance(expected_key_id, str)
            or not expected_key_id.strip()
        ):
            print("FAIL: expected signing key ID is missing")
            return False

        manifest_path = Path(manifest_path)
        signature_path = Path(signature_path)


        manifest_bytes = _read_restricted_metadata(
            manifest_path,
            "manifest",
            _RESTRICTED_METADATA_LIMITS["manifest"],
        )

        signature = _read_restricted_metadata(
            signature_path,
            "signature",
            _RESTRICTED_METADATA_LIMITS["signature"],
        )

        manifest = parse_json_strict(manifest_bytes)

        if canonical_json_bytes(manifest) != manifest_bytes:
            print("FAIL: restricted manifest is not canonical JSON")
            return False

        validate_manifest(manifest)

        if manifest["schema_version"] != "1.4":
            print("FAIL: restricted verifier requires schema v1.4")
            return False

        profile = manifest["evidence_profile"]

        if profile not in allowed_profiles:
            print("FAIL: restricted evidence profile is not authorized")
            return False

        if manifest["key_id"] != expected_key_id:
            print("FAIL: unexpected restricted signing key ID")
            return False

        public_key_bytes = load_bounded_trusted_key(
            Path(trust_registry),
            expected_key_id,
            manifest["provenance"]["source"],
        )

        # Convert the already validated bytes to DER.
        # Do not reopen the trusted public-key file.
        public_key = serialization.load_pem_public_key(
            public_key_bytes
        )

        public_key_der = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        if not kms_verify_bytes(
            public_key_der,
            manifest_bytes,
            signature,
        ):
            print("FAIL: restricted manifest signature is invalid")
            return False

        artifacts = Path(artifacts)

        _reject_symlink_components(
            artifacts,
            "Restricted artifacts",
        )

        if not artifacts.is_dir() or artifacts.is_symlink():
            print("FAIL: restricted artifacts directory is invalid")
            return False

        entries = {
            entry["name"]: entry
            for entry in manifest["artifacts"]
        }

        if set(entries) != REQUIRED_ARTIFACTS:
            print("FAIL: restricted manifest artifact set mismatch")
            return False

        # Reject unexpected files, directories, and direct symlinks.
        actual_names = set()

        for path in artifacts.iterdir():
            if path.is_symlink() or not path.is_file():
                print("FAIL: invalid restricted artifact entry")
                return False

            actual_names.add(path.name)

        if actual_names != set(entries):
            print("FAIL: restricted artifact set differs from manifest")
            return False

        # Read each artifact once. Authenticate the exact bytes before
        # using them for restricted-document validation.
        restricted_contents: dict[str, bytes] = {}

        for name, entry in entries.items():
            path = artifacts / name

            content = _read_restricted_artifact(
                path,
                name,
                entry["size_bytes"],
            )

            digest = hashlib.sha256(content).hexdigest()

            if digest != entry["sha256"]:
                print(
                    f"FAIL: restricted artifact digest mismatch: {name}"
                )
                return False

            if name in {"plan.json", "state.json"}:
                restricted_contents[name] = content

        provenance_version = manifest["provenance"]["terraform_version"]

        for name in ("plan.json", "state.json"):
            content = restricted_contents[name]

            validate_restricted_bytes(name, content)
            document = parse_json_strict(content)

            if document["evidence_profile"] != profile:
                print(f"FAIL: restricted profile mismatch: {name}")
                return False

            if document["terraform_version"] != provenance_version:
                print(f"FAIL: Terraform provenance mismatch: {name}")
                return False

        print(
            "PASS: explicitly authorized restricted evidence "
            f"verified ({profile})"
        )
        return True

    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        print(
            "FAIL: restricted verification error: "
            f"{type(exc).__name__}"
        )
        return False
