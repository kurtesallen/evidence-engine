
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


def _supports_secure_restricted_traversal() -> bool:
    """Require POSIX descriptor-relative directory and file operations."""
    return (
        os.name == "posix"
        and hasattr(os, "O_NOFOLLOW")
        and hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_NONBLOCK")
        and os.open in os.supports_dir_fd
        and os.listdir in os.supports_fd
    )


def _open_secure_restricted_directory(path: Path) -> int:
    """Open an absolute directory without following symlink components.

    The returned descriptor belongs to the caller and must be closed.
    """
    if not _supports_secure_restricted_traversal():
        raise ValueError("Secure restricted traversal is unavailable")

    absolute = Path(os.path.abspath(os.fspath(path)))

    if ".." in Path(path).parts:
        raise ValueError("Restricted directory contains parent traversal")

    flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )

    descriptors = []

    try:
        parts = absolute.parts

        if not parts:
            raise ValueError("Invalid restricted directory path")

        current = os.open(parts[0], flags)
        descriptors.append(current)

        for part in parts[1:]:
            current = os.open(
                part,
                flags,
                dir_fd=current,
            )
            descriptors.append(current)

        result = descriptors.pop()
        return result

    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _read_restricted_metadata(
    path: Path,
    label: str,
    maximum: int,
) -> bytes:
    """Read bounded metadata through a securely opened parent directory."""
    if type(maximum) is not int or maximum < 0:
        raise ValueError(f"Invalid restricted {label} size limit")

    path = Path(path)

    if path.name in ("", ".", ".."):
        raise ValueError(f"Invalid restricted {label} filename")

    directory_fd = _open_secure_restricted_directory(path.parent)

    try:
        flags = (
            os.O_RDONLY
            | os.O_NOFOLLOW
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | os.O_NONBLOCK
        )

        descriptor = os.open(
            path.name,
            flags,
            dir_fd=directory_fd,
        )

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
            # fdopen normally owns the descriptor. Also handle failure
            # before ownership transfers.
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise

    finally:
        os.close(directory_fd)


def _read_restricted_artifact(
    directory_fd: int,
    name: str,
    expected_size: int,
) -> bytes:
    """Read one bounded artifact relative to a pinned directory."""
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

    flags = (
        os.O_RDONLY
        | os.O_NOFOLLOW
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )

    descriptor = os.open(name, flags, dir_fd=directory_fd)

    try:
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

    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


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

        entries = {
            entry["name"]: entry
            for entry in manifest["artifacts"]
        }

        if set(entries) != REQUIRED_ARTIFACTS:
            print("FAIL: restricted manifest artifact set mismatch")
            return False

        # Enumeration and all artifact opens use one pinned directory.
        directory_fd = _open_secure_restricted_directory(artifacts)

        try:
            actual_names = set(os.listdir(directory_fd))

            if actual_names != set(entries):
                print("FAIL: restricted artifact set differs from manifest")
                return False

            restricted_contents: dict[str, bytes] = {}

            for name, entry in entries.items():
                content = _read_restricted_artifact(
                    directory_fd,
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

        finally:
            os.close(directory_fd)

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
