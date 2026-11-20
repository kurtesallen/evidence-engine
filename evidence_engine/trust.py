"""Load and enforce the local EvidenceEngine trust registry."""

import json
import os
import stat
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


ALLOWED_STATUSES = {"active", "revoked", "retired"}
ALLOWED_SOURCES = {
    "local-claimed",
    "github-actions-claimed",
}

REGISTRY_FIELDS = {"schema_version", "keys"}
KEY_ENTRY_FIELDS = {
    "key_id",
    "public_key",
    "status",
    "allowed_sources",
}


def _validate_trust_registry(
    registry: Any,
) -> dict[str, Any]:
    """Validate an already-parsed trust registry.

    This helper performs validation only. It does not read
    files or resolve public-key paths.
    """
    if not isinstance(registry, dict):
        raise ValueError("Trust registry must be a JSON object")

    if set(registry) != REGISTRY_FIELDS:
        raise ValueError(
            "Trust registry has missing or unknown fields"
        )

    if registry["schema_version"] != "1.0":
        raise ValueError("Unsupported trust registry schema")

    entries = registry["keys"]

    if not isinstance(entries, list):
        raise ValueError("Trust registry keys must be a list")

    seen_ids: set[str] = set()

    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError(
                "Trust registry key entry must be an object"
            )

        if set(entry) != KEY_ENTRY_FIELDS:
            raise ValueError(
                "Trust registry key has missing or unknown fields"
            )

        key_id = entry["key_id"]
        public_key = entry["public_key"]
        status = entry["status"]
        allowed_sources = entry["allowed_sources"]

        if (
            not isinstance(key_id, str)
            or not key_id
            or len(key_id) > 128
        ):
            raise ValueError("Invalid trust registry key ID")

        if key_id in seen_ids:
            raise ValueError(
                f"Duplicate trust registry key ID: {key_id}"
            )

        seen_ids.add(key_id)

        if not isinstance(public_key, str) or not public_key.strip():
            raise ValueError(
                f"Invalid public key path: {key_id}"
            )

        # Require relative paths. Absolute paths must never be
        # accepted as registry-controlled public-key locations.
        if Path(public_key).is_absolute():
            raise ValueError(
                f"Public key path must be relative: {key_id}"
            )

        if not isinstance(status, str) or status not in ALLOWED_STATUSES:
            raise ValueError(
                f"Invalid key status: {key_id}"
            )

        if (
            not isinstance(allowed_sources, list)
            or any(
                not isinstance(source, str)
                or source not in ALLOWED_SOURCES
                for source in allowed_sources
            )
            or len(allowed_sources) != len(set(allowed_sources))
        ):
            raise ValueError(
                f"Invalid allowed_sources: {key_id}"
            )

    return registry


def load_trust_registry(registry_path: Path) -> dict[str, Any]:
    """Load a trust registry and reject malformed structures."""
    try:
        registry = json.loads(
            registry_path.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(
            f"Cannot load trust registry: {exc}"
        ) from exc

    return _validate_trust_registry(registry)



def _read_bounded_trust_file(
    path: Path,
    *,
    label: str,
    maximum: int,
) -> bytes:
    """Read a regular trust file with a strict byte limit."""
    if type(maximum) is not int or maximum < 0:
        raise ValueError(f"Invalid {label} size limit")

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

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)

    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    descriptor = os.open(path, flags)

    try:
        with os.fdopen(descriptor, "rb", buffering=0) as stream:
            metadata = os.fstat(stream.fileno())

            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(
                    f"{label} is not a regular file"
                )

            if metadata.st_size > maximum:
                raise ValueError(
                    f"{label} exceeds size limit"
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
                    f"{label} exceeds size limit"
                )

            return content

    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise

def _authorize_trusted_key(
    registry: dict[str, Any],
    key_id: str,
    source: str,
) -> dict[str, Any]:
    """Select a unique, active key authorized for the given source."""
    matches = [
        entry
        for entry in registry["keys"]
        if entry["key_id"] == key_id
    ]

    if len(matches) != 1:
        raise ValueError("Unknown or ambiguous signing key ID")

    entry = matches[0]

    if entry["status"] != "active":
        raise ValueError("Signing key is not active")

    if source not in entry["allowed_sources"]:
        raise ValueError(
            "Signing key is not authorized for this source"
        )

    return entry


def _resolve_trusted_key_path(
    registry_path: Path,
    entry: dict[str, Any],
) -> Path:
    """Resolve an authorized key path within the configured project."""
    registry_dir = registry_path.resolve().parent
    configured_key_path = Path(entry["public_key"])

    if configured_key_path.is_absolute():
        raise ValueError(
            "Trusted public key path must be relative"
        )

    public_key_path = (
        registry_dir / configured_key_path
    ).resolve()

    project_dir = registry_dir.parent.resolve()

    if not public_key_path.is_relative_to(project_dir):
        raise ValueError(
            "Public key path escapes the configured project"
        )

    if not public_key_path.is_file():
        raise ValueError(
            "Trusted public key file does not exist"
        )

    return public_key_path



def _restricted_project_relative_key_path(
    configured_path: str,
) -> Path:
    """Normalize a registry-relative key path within the project."""
    from pathlib import PurePosixPath, PureWindowsPath

    if (
        PurePosixPath(configured_path).is_absolute()
        or PureWindowsPath(configured_path).drive
        or PureWindowsPath(configured_path).root
        or "\\" in configured_path
    ):
        raise ValueError(
            "Trusted public key path must be relative"
        )

    components = ["config"]

    for part in PurePosixPath(configured_path).parts:
        if part in ("", "."):
            continue

        if part == "..":
            if not components:
                raise ValueError(
                    "Public key path escapes the configured project"
                )
            components.pop()
            continue

        components.append(part)

    if not components:
        raise ValueError("Trusted public key path is empty")

    return Path(*components)


def _supports_secure_trust_traversal() -> bool:
    """Report availability of descriptor-relative POSIX traversal.

    This checks platform capabilities only. It does not establish
    that a particular filesystem path has been traversed securely.
    """
    return (
        os.name == "posix"
        and hasattr(os, "O_NOFOLLOW")
        and hasattr(os, "O_DIRECTORY")
        and os.open in os.supports_dir_fd
    )


def _read_secure_project_file(
    project_root: Path,
    relative_path: Path,
    *,
    label: str,
    maximum: int,
) -> bytes:
    """Read a bounded regular file through POSIX directory descriptors."""
    if type(maximum) is not int or maximum < 0:
        raise ValueError(f"Invalid {label} size limit")

    project_root = Path(project_root)
    relative_path = Path(relative_path)

    if not project_root.is_absolute():
        raise ValueError("Secure project root must be absolute")

    if relative_path.is_absolute():
        raise ValueError("Secure trust file path must be relative")

    components = []

    for part in relative_path.parts:
        if part in ("", "."):
            continue

        if part == "..":
            raise ValueError(
                "Secure trust file path contains parent traversal"
            )

        components.append(part)

    if not components:
        raise ValueError("Secure trust file path is empty")

    if not _supports_secure_trust_traversal():
        raise ValueError("Secure trust traversal is unavailable")

    close_on_exec = getattr(os, "O_CLOEXEC", 0)

    directory_flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | close_on_exec
    )

    file_flags = (
        os.O_RDONLY
        | os.O_NOFOLLOW
        | getattr(os, "O_BINARY", 0)
        | close_on_exec
    )

    descriptors = []

    try:
        root_parts = project_root.parts

        if not root_parts:
            raise ValueError("Invalid secure project root")

        current = os.open(root_parts[0], directory_flags)
        descriptors.append(current)

        for part in root_parts[1:]:
            current = os.open(
                part,
                directory_flags,
                dir_fd=current,
            )
            descriptors.append(current)

        for part in components[:-1]:
            current = os.open(
                part,
                directory_flags,
                dir_fd=current,
            )
            descriptors.append(current)

        descriptor = os.open(
            components[-1],
            file_flags,
            dir_fd=current,
        )

        try:
            metadata = os.fstat(descriptor)

            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(
                    f"{label} is not a regular file"
                )

            if metadata.st_size > maximum:
                raise ValueError(
                    f"{label} exceeds size limit"
                )

            chunks = []
            remaining = maximum + 1

            while remaining:
                chunk = os.read(descriptor, remaining)

                if not chunk:
                    break

                chunks.append(chunk)
                remaining -= len(chunk)

            content = b"".join(chunks)

            if len(content) > maximum:
                raise ValueError(
                    f"{label} exceeds size limit"
                )

            return content

        finally:
            import sys

            primary_exception_active = sys.exc_info()[0] is not None

            try:
                os.close(descriptor)
            except OSError:
                if not primary_exception_active:
                    raise

    finally:
        import sys

        primary_exception_active = sys.exc_info()[0] is not None
        close_error = None

        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError as exc:
                if close_error is None:
                    close_error = exc

        if close_error is not None and not primary_exception_active:
            raise close_error


_RESTRICTED_TRUST_REGISTRY_LIMIT = 64 * 1024
_RESTRICTED_TRUST_PUBLIC_KEY_LIMIT = 16 * 1024


def load_bounded_trusted_key(
    registry_path: Path,
    key_id: str,
    source: str,
) -> bytes:
    """Load an authorized RSA-2048 key through secure bounded reads.

    This experimental API uses descriptor-relative POSIX traversal
    for both the trust registry and its authorized public key.

    Production trust resolution remains unchanged.
    """
    if not _supports_secure_trust_traversal():
        raise ValueError(
            "Secure trust traversal is unavailable"
        )

    # Normalize lexically, without following symlinks.
    registry_path = Path(registry_path)

    if ".." in registry_path.parts:
        raise ValueError(
            "Restricted trust registry contains parent traversal"
        )

    # Normalize only after rejecting parent traversal.
    registry_path = Path(
        os.path.abspath(os.fspath(registry_path))
    )

    registry_dir = registry_path.parent

    if registry_dir.name != "config":
        raise ValueError(
            "Restricted trust registry must be inside config"
        )

    project_root = registry_dir.parent

    registry_relative = Path("config") / registry_path.name

    registry_bytes = _read_secure_project_file(
        project_root,
        registry_relative,
        label="Restricted trust registry",
        maximum=_RESTRICTED_TRUST_REGISTRY_LIMIT,
    )

    try:
        registry = json.loads(registry_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(
            "Cannot load restricted trust registry"
        ) from exc

    registry = _validate_trust_registry(registry)

    entry = _authorize_trusted_key(
        registry,
        key_id,
        source,
    )

    key_relative = _restricted_project_relative_key_path(
        entry["public_key"]
    )

    public_key_bytes = _read_secure_project_file(
        project_root,
        key_relative,
        label="Restricted public key",
        maximum=_RESTRICTED_TRUST_PUBLIC_KEY_LIMIT,
    )

    try:
        key = serialization.load_pem_public_key(
            public_key_bytes
        )
    except (ValueError, TypeError) as exc:
        raise ValueError(
            "Trusted public key cannot be loaded"
        ) from exc

    if not isinstance(key, rsa.RSAPublicKey) or key.key_size != 2048:
        raise ValueError("Trusted key must be RSA-2048")

    return public_key_bytes


def resolve_trusted_key(
    registry_path: Path,
    key_id: str,
    source: str,
) -> Path:
    """Return a public key only if registry policy authorizes it."""
    registry = load_trust_registry(registry_path)

    entry = _authorize_trusted_key(
        registry,
        key_id,
        source,
    )

    public_key_path = _resolve_trusted_key_path(
        registry_path,
        entry,
    )

    try:
        key = serialization.load_pem_public_key(
            public_key_path.read_bytes()
        )
    except (OSError, ValueError, TypeError) as exc:
        raise ValueError(
            "Trusted public key cannot be loaded"
        ) from exc

    if not isinstance(key, rsa.RSAPublicKey) or key.key_size != 2048:
        raise ValueError("Trusted key must be RSA-2048")

    return public_key_path
