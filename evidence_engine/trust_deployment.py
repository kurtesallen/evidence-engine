"""Secure registry-driven staging of deployment trust material."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from contextlib import ExitStack
from pathlib import Path
from typing import Any, Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from evidence_engine.trust import (
    _RESTRICTED_TRUST_PUBLIC_KEY_LIMIT,
    _RESTRICTED_TRUST_REGISTRY_LIMIT,
    _open_pinned_project_root,
    _open_pinned_registry_dir,
    _read_from_pinned_root,
    _supports_secure_trust_traversal,
    _validate_trust_registry,
)


_KEY_COMPONENT_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$"
)


def _reject_duplicate_fields(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    """Reject ambiguous JSON objects."""

    result: dict[str, Any] = {}

    for name, value in pairs:
        if name in result:
            raise ValueError(
                f"Duplicate trust registry field: {name}"
            )

        result[name] = value

    return result


def _reject_json_constant(value: str) -> None:
    """Reject non-standard JSON constants."""

    raise ValueError(
        f"Invalid trust registry JSON constant: {value}"
    )


def _parse_registry(
    registry_bytes: bytes,
) -> dict[str, Any]:
    """Parse and validate one registry snapshot."""

    try:
        registry = json.loads(
            registry_bytes.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_fields,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(
            "Cannot load deployment trust registry"
        ) from exc

    registry = _validate_trust_registry(registry)

    if not registry["keys"]:
        raise ValueError(
            "Deployment trust registry contains no keys"
        )

    return registry


def _deployment_key_path(configured: str) -> Path:
    """Require an unambiguous path beneath the keys subtree."""

    components = configured.split("/")

    if (
        len(components) < 2
        or components[0] != "keys"
        or any(
            not _KEY_COMPONENT_RE.fullmatch(component)
            for component in components
        )
    ):
        raise ValueError(
            "Deployment public key path must be "
            "contained within keys/"
        )

    return Path(*components)


def _absolute_path(path: Path) -> Path:
    """Normalize a path without following symlinks."""

    path = Path(path)

    if ".." in path.parts:
        raise ValueError(
            "Deployment path contains parent traversal"
        )

    return Path(
        os.path.abspath(os.fspath(path))
    )


def _validate_public_key(
    public_key_bytes: bytes,
) -> None:
    """Require a valid RSA-2048 public key."""

    try:
        key = serialization.load_pem_public_key(
            public_key_bytes
        )
    except (ValueError, TypeError) as exc:
        raise ValueError(
            "Deployment public key cannot be loaded"
        ) from exc

    if (
        not isinstance(key, rsa.RSAPublicKey)
        or key.key_size != 2048
    ):
        raise ValueError(
            "Deployment public key must be RSA-2048"
        )


def _read_deployment_material(
    source_registry: Path,
) -> tuple[bytes, dict[Path, bytes]]:
    """Read and validate all referenced trust material."""

    registry_dir = source_registry.parent
    project_root = registry_dir.parent

    with ExitStack() as stack:
        root_fd = _open_pinned_project_root(
            project_root
        )
        stack.callback(os.close, root_fd)

        registry_fd = _open_pinned_registry_dir(
            root_fd,
            registry_dir.name,
        )
        stack.callback(os.close, registry_fd)

        registry_bytes = _read_from_pinned_root(
            registry_fd,
            Path(source_registry.name),
            label="Deployment trust registry",
            maximum=_RESTRICTED_TRUST_REGISTRY_LIMIT,
        )

        registry = _parse_registry(registry_bytes)

        key_material: dict[Path, bytes] = {}

        for entry in registry["keys"]:
            relative_path = _deployment_key_path(
                entry["public_key"]
            )

            # Multiple registry entries may reference the
            # same public-key file. Read that file only once.
            if relative_path in key_material:
                continue

            public_key_bytes = _read_from_pinned_root(
                registry_fd,
                relative_path,
                label="Deployment public key",
                maximum=_RESTRICTED_TRUST_PUBLIC_KEY_LIMIT,
            )

            _validate_public_key(public_key_bytes)

            key_material[relative_path] = (
                public_key_bytes
            )

        return registry_bytes, key_material


def _create_private_directory(
    parent_fd: int,
    name: str,
) -> int:
    """Create and open a new private directory."""

    os.mkdir(
        name,
        mode=0o700,
        dir_fd=parent_fd,
    )

    descriptor = os.open(
        name,
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0),
        dir_fd=parent_fd,
    )

    try:
        os.fchmod(descriptor, 0o700)
    except BaseException:
        os.close(descriptor)
        raise

    return descriptor


def _write_private_file(
    parent_fd: int,
    name: str,
    content: bytes,
) -> None:
    """Create a private file without replacing an existing file."""

    descriptor = os.open(
        name,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0),
        0o600,
        dir_fd=parent_fd,
    )

    try:
        os.fchmod(descriptor, 0o600)

        remaining = memoryview(content)

        while remaining:
            written = os.write(
                descriptor,
                remaining,
            )

            if written <= 0:
                raise OSError(
                    "Incomplete deployment trust file write"
                )

            remaining = remaining[written:]

        os.fsync(descriptor)

    finally:
        os.close(descriptor)


def _publish_deployment_material(
    destination: Path,
    registry_bytes: bytes,
    key_material: dict[Path, bytes],
) -> Path:
    """Write validated material into a new private directory.

    The registry is written last. Failed staging must never
    be exported to the consumer by the calling workflow.
    """

    with ExitStack() as stack:
        parent_fd = _open_pinned_project_root(
            destination.parent
        )
        stack.callback(os.close, parent_fd)

        destination_fd = _create_private_directory(
            parent_fd,
            destination.name,
        )
        stack.callback(os.close, destination_fd)

        directories: dict[tuple[str, ...], int] = {
            (): destination_fd,
        }

        for relative_path, content in sorted(
            key_material.items()
        ):
            components = relative_path.parts
            current_fd = destination_fd

            for index, component in enumerate(
                components[:-1],
                start=1,
            ):
                directory_key = components[:index]

                if directory_key not in directories:
                    descriptor = _create_private_directory(
                        current_fd,
                        component,
                    )

                    stack.callback(
                        os.close,
                        descriptor,
                    )

                    directories[directory_key] = (
                        descriptor
                    )

                current_fd = directories[directory_key]

            _write_private_file(
                current_fd,
                components[-1],
                content,
            )

        # Persist key directories before publishing the
        # registry that references their contents.
        for descriptor in reversed(
            tuple(directories.values())
        ):
            os.fsync(descriptor)

        _write_private_file(
            destination_fd,
            "registry.json",
            registry_bytes,
        )

        os.fsync(destination_fd)
        os.fsync(parent_fd)

    return destination / "registry.json"


def stage_trust_deployment(
    source_registry: Path,
    destination: Path,
) -> Path:
    """Stage a complete registry and its referenced public keys.

    The destination must not already exist. All source
    material is validated before destination creation.

    This operation stages trust material only. Authorization
    of an expected signing identity remains the responsibility
    of mandatory deployment preflight.
    """

    if not _supports_secure_trust_traversal():
        raise ValueError(
            "Secure trust deployment requires POSIX "
            "descriptor-relative traversal"
        )

    source_registry = _absolute_path(
        source_registry
    )
    destination = _absolute_path(destination)

    if source_registry.name != "registry.json":
        raise ValueError(
            "Deployment source must be registry.json"
        )

    if not destination.name:
        raise ValueError(
            "Invalid trust deployment destination"
        )

    source_directory = source_registry.parent

    if (
        destination == source_directory
        or destination.is_relative_to(source_directory)
        or source_directory.is_relative_to(destination)
    ):
        raise ValueError(
            "Source and destination trust directories "
            "must not overlap"
        )

    if os.path.lexists(destination):
        raise ValueError(
            "Trust deployment destination already exists"
        )

    registry_bytes, key_material = (
        _read_deployment_material(
            source_registry
        )
    )

    return _publish_deployment_material(
        destination,
        registry_bytes,
        key_material,
    )


def main(
    argv: Sequence[str] | None = None,
) -> int:
    """Stage trust material through the deployment CLI."""

    parser = argparse.ArgumentParser(
        description=(
            "Securely stage registry-referenced "
            "deployment trust material"
        )
    )

    parser.add_argument(
        "--source-registry",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--destination",
        required=True,
        type=Path,
    )

    args = parser.parse_args(argv)

    try:
        staged_registry = stage_trust_deployment(
            args.source_registry,
            args.destination,
        )
    except (OSError, ValueError, TypeError) as exc:
        print(
            f"FAIL: trust deployment staging: {exc}",
            file=sys.stderr,
        )
        return 1

    print(
        "PASS: trust deployment staging succeeded"
    )
    print(f"Staged registry: {staged_registry}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
