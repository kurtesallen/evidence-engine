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

        _validate_trust_descriptor(
            current,
            "Project path directory",
            allow_sticky_ancestor=len(root_parts) > 1,
        )

        for index, part in enumerate(root_parts[1:], start=1):
            current = os.open(
                part,
                directory_flags,
                dir_fd=current,
            )
            descriptors.append(current)

            _validate_trust_descriptor(
                current,
                "Project path directory",
                allow_sticky_ancestor=index < len(root_parts) - 1,
            )

        for part in components[:-1]:
            current = os.open(
                part,
                directory_flags,
                dir_fd=current,
            )
            descriptors.append(current)

            _validate_trust_descriptor(
                current,
                f"{label} parent directory",
            )

        descriptor = os.open(
            components[-1],
            file_flags,
            dir_fd=current,
        )

        try:
            metadata = _validate_trust_descriptor(
                descriptor,
                label,
            )

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


def _validate_trust_descriptor(
    fd: int,
    label: str,
    *,
    allow_sticky_ancestor: bool = False,
) -> os.stat_result:
    """Validate POSIX trust material ownership and write permissions."""
    try:
        metadata = os.fstat(fd)
        effective_uid = os.geteuid()
    except OSError as exc:
        raise ValueError(
            f"{label} ownership or permissions cannot be inspected"
        ) from exc

    if metadata.st_uid not in (effective_uid, 0):
        raise ValueError(
            f"{label} has untrusted ownership"
        )

    writable = bool(
        metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    )

    if writable:
        protected_sticky_ancestor = (
            allow_sticky_ancestor
            and metadata.st_uid == 0
            and bool(metadata.st_mode & stat.S_ISVTX)
            and stat.S_ISDIR(metadata.st_mode)
        )

        if not protected_sticky_ancestor:
            raise ValueError(
                f"{label} has unsafe permissions"
            )

    return metadata



def _read_from_pinned_root(
    root_fd: int,
    relative_path: Path,
    *,
    label: str,
    maximum: int,
) -> bytes:
    """Read a bounded regular file relative to an open directory."""
    if type(maximum) is not int or maximum < 0:
        raise ValueError(f"Invalid {label} size limit")

    relative_path = Path(relative_path)

    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise ValueError("Invalid relative trust file path")

    components = [
        part for part in relative_path.parts
        if part not in ("", ".")
    ]

    if not components:
        raise ValueError("Secure trust file path is empty")

    directory_flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )

    file_flags = (
        os.O_RDONLY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_BINARY", 0)
    )

    descriptors = []
    current = root_fd

    try:
        for component in components[:-1]:
            current = os.open(
                component,
                directory_flags,
                dir_fd=current,
            )
            descriptors.append(current)
            _validate_trust_descriptor(
                current,
                f"{label} parent directory",
            )

        file_fd = os.open(
            components[-1],
            file_flags,
            dir_fd=current,
        )

        try:
            metadata = _validate_trust_descriptor(
                file_fd,
                label,
            )

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
                chunk = os.read(file_fd, remaining)

                if not chunk:
                    break

                chunks.append(chunk)
                remaining -= len(chunk)

            result = b"".join(chunks)

            if len(result) > maximum:
                raise ValueError(
                    f"{label} exceeds size limit"
                )

            return result

        finally:
            import sys

            primary_error = sys.exc_info()[0] is not None

            try:
                os.close(file_fd)
            except OSError:
                if not primary_error:
                    raise

    finally:
        import sys

        primary_error = sys.exc_info()[0] is not None
        close_error = None

        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError as exc:
                if close_error is None:
                    close_error = exc

        if close_error is not None and not primary_error:
            raise close_error


def _open_pinned_project_root(project_root: Path) -> int:
    """Open and validate a project root without following symlinks."""
    project_root = Path(project_root)

    if not project_root.is_absolute():
        raise ValueError("Secure project root must be absolute")

    flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )

    current = None

    try:
        for index, component in enumerate(project_root.parts):
            next_fd = os.open(
                component,
                flags,
                **({"dir_fd": current} if current is not None else {}),
            )

            previous_fd = current
            current = next_fd

            if previous_fd is not None:
                os.close(previous_fd)

            _validate_trust_descriptor(
                current,
                "Project path directory",
                allow_sticky_ancestor=(
                    index < len(project_root.parts) - 1
                ),
            )

        if current is None:
            raise ValueError("Invalid secure project root")

        result = current
        current = None
        return result

    finally:
        if current is not None:
            os.close(current)


def _open_pinned_registry_dir(root_fd: int, name: str) -> int:
    """Open and validate a registry directory relative to the pinned root."""
    if name in ("", ".", "..") or "/" in name or "\\" in name:
        raise ValueError("Invalid trust registry directory name")

    descriptor = os.open(
        name,
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0),
        dir_fd=root_fd,
    )

    try:
        _validate_trust_descriptor(
            descriptor,
            "Trust registry directory",
        )
    except BaseException:
        os.close(descriptor)
        raise

    return descriptor

def load_trusted_key_bytes(
    registry_path: Path,
    key_id: str,
    source: str,
) -> bytes:
    """Load an authorized RSA-2048 key without reopening its pathname.

    POSIX uses descriptor-relative, no-follow traversal.
    Windows uses bounded compatibility reads. Its trust directories
    must not be writable by untrusted users.
    """
    from pathlib import PurePosixPath, PureWindowsPath

    registry_path = Path(registry_path)

    if ".." in registry_path.parts:
        raise ValueError(
            "Trust registry path contains parent traversal"
        )

    registry_path = Path(
        os.path.abspath(os.fspath(registry_path))
    )

    registry_dir = registry_path.parent
    project_root = registry_dir.parent

    registry_relative = Path(
        registry_dir.name,
        registry_path.name,
    )

    registry_fd = None
    if _supports_secure_trust_traversal():
        root_fd = _open_pinned_project_root(project_root)
        try:
            registry_fd = _open_pinned_registry_dir(
                root_fd,
                registry_dir.name,
            )
        except BaseException:
            os.close(root_fd)
            raise
    elif os.name == "nt":
        root_fd = None
    else:
        raise ValueError(
            "Secure trust traversal is unavailable"
        )

    def read_file(
        relative_path: Path,
        *,
        label: str,
        maximum: int,
    ) -> bytes:
        if root_fd is not None:
            # Both registry and keys beneath its directory are read
            # through the same pinned directory descriptor. Keys that
            # resolve to siblings (e.g. ../keys) use the pinned parent.
            parts = Path(relative_path).parts
            if parts and parts[0] == registry_dir.name:
                return _read_from_pinned_root(
                    registry_fd,
                    Path(*parts[1:]),
                    label=label,
                    maximum=maximum,
                )
            return _read_from_pinned_root(
                root_fd,
                relative_path,
                label=label,
                maximum=maximum,
            )

        return _read_bounded_trust_file(
            project_root / relative_path,
            label=label,
            maximum=maximum,
        )

    try:
        registry_bytes = read_file(
            registry_relative,
            label="Trust registry",
            maximum=_RESTRICTED_TRUST_REGISTRY_LIMIT,
        )

        try:
            registry = json.loads(registry_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(
                "Cannot load trust registry"
            ) from exc

        registry = _validate_trust_registry(registry)

        entry = _authorize_trusted_key(
            registry,
            key_id,
            source,
        )

        configured = entry["public_key"]

        if (
            PurePosixPath(configured).is_absolute()
            or PureWindowsPath(configured).drive
            or PureWindowsPath(configured).root
            or "\\" in configured
        ):
            raise ValueError(
                "Trusted public key path must be relative"
            )

        components = [registry_dir.name]

        for part in PurePosixPath(configured).parts:
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
            raise ValueError(
                "Trusted public key path is empty"
            )

        key_relative = Path(*components)

        public_key_bytes = read_file(
            key_relative,
            label="Trusted public key",
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

    finally:
        try:
            if registry_fd is not None:
                os.close(registry_fd)
        finally:
            if root_fd is not None:
                os.close(root_fd)


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
