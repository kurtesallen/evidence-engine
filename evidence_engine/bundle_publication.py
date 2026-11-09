
"""Immutable local bundle generations and atomic CURRENT publication."""

from __future__ import annotations

import os
import re
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path


_GENERATION_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_CURRENT_NAME = "CURRENT"
_GENERATIONS_NAME = "generations"


@dataclass(frozen=True)
class BundlePaths:
    """Paths belonging to one immutable bundle generation."""

    bundle_root: Path
    generation_id: str
    generation_root: Path
    artifacts_root: Path
    manifest_path: Path
    signature_path: Path


def _absolute_path(path: Path) -> Path:
    """Return an absolute lexical path without resolving symlinks."""
    return Path(os.path.abspath(os.fspath(path)))


def _validate_generation_id(value: str) -> str:
    if (
        not isinstance(value, str)
        or _GENERATION_ID_RE.fullmatch(value) is None
    ):
        raise ValueError("Invalid bundle generation ID")

    return value


def _reject_symlink_components(path: Path, label: str) -> None:
    """Reject symlinks in every existing component of an absolute path."""
    absolute = _absolute_path(path)

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


def _paths(
    bundle_root: Path,
    generation_id: str,
    generation_root: Path,
) -> BundlePaths:
    return BundlePaths(
        bundle_root=bundle_root,
        generation_id=generation_id,
        generation_root=generation_root,
        artifacts_root=generation_root / "artifacts",
        manifest_path=generation_root / "manifest.json",
        signature_path=generation_root / "manifest.sig",
    )


def _validate_complete_generation(paths: BundlePaths) -> None:
    generation_root = paths.generation_root

    _reject_symlink_components(
        generation_root,
        "Generation directory",
    )

    if not generation_root.is_dir():
        raise ValueError("Generation directory is missing")

    for path, label in (
        (paths.artifacts_root, "Artifacts directory"),
        (paths.manifest_path, "Manifest"),
        (paths.signature_path, "Signature"),
    ):
        _reject_symlink_components(path, label)

    if not paths.artifacts_root.is_dir():
        raise ValueError("Generation artifacts directory is missing")

    if not paths.manifest_path.is_file():
        raise ValueError("Generation manifest is missing")

    if not paths.signature_path.is_file():
        raise ValueError("Generation signature is missing")


def _validate_current_destination(current: Path) -> None:
    """Validate CURRENT before promoting a generation."""
    _reject_symlink_components(current, "CURRENT pointer")

    if current.exists() and not current.is_file():
        raise ValueError("CURRENT pointer must be a regular file")


def _fsync_directory(path: Path) -> None:
    """Best-effort directory durability where the platform supports it."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)

    try:
        descriptor = os.open(path, flags)
    except OSError:
        return

    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def create_staging_generation(bundle_root: Path) -> BundlePaths:
    """Create a private, unique staging generation."""
    root = _absolute_path(Path(bundle_root))
    _reject_symlink_components(root, "Bundle root")

    root.mkdir(parents=True, exist_ok=True)
    _reject_symlink_components(root, "Bundle root")

    if not root.is_dir():
        raise ValueError("Bundle root is not a directory")

    generations = root / _GENERATIONS_NAME
    _reject_symlink_components(generations, "Generations directory")

    generations.mkdir(mode=0o700, exist_ok=True)
    _reject_symlink_components(generations, "Generations directory")

    if not generations.is_dir():
        raise ValueError("Generations path is not a directory")

    generation_id = uuid.uuid4().hex
    staging_root = generations / f".staging-{generation_id}"
    staging_root.mkdir(mode=0o700)

    _reject_symlink_components(staging_root, "Staging generation")

    return _paths(root, generation_id, staging_root)


def cleanup_staging_generation(paths: BundlePaths) -> bool:
    """Remove only the exact staging directory represented by paths.

    Returns False if the staging directory is already absent or cannot be
    removed. Invalid or forged path descriptions raise ValueError.

    Published generations are never eligible for this operation.
    """
    if not isinstance(paths, BundlePaths):
        raise ValueError("Invalid bundle paths")

    root = _absolute_path(Path(paths.bundle_root))
    generation_id = _validate_generation_id(paths.generation_id)

    expected_staging = (
        root / _GENERATIONS_NAME / f".staging-{generation_id}"
    )
    expected_paths = _paths(root, generation_id, expected_staging)

    if paths != expected_paths:
        raise ValueError("Bundle paths do not match expected staging paths")

    _reject_symlink_components(root, "Bundle root")
    _reject_symlink_components(
        root / _GENERATIONS_NAME,
        "Generations directory",
    )
    _reject_symlink_components(
        expected_staging,
        "Staging generation",
    )

    if not expected_staging.exists():
        return False

    if not expected_staging.is_dir():
        raise ValueError("Staging generation is not a directory")

    try:
        shutil.rmtree(expected_staging)
    except OSError:
        return False

    return True


def publish_generation(paths: BundlePaths) -> BundlePaths:
    """Promote a complete staging generation and atomically update CURRENT.

    The os.replace() of the temporary pointer onto CURRENT is the publication
    commit point. A failed pointer update can leave an unreferenced permanent
    generation.

    Concurrent readers are supported. Concurrent publishers require external
    locking; this implementation assumes a single writer per bundle root.
    """
    if not isinstance(paths, BundlePaths):
        raise ValueError("Invalid bundle paths")

    root = _absolute_path(Path(paths.bundle_root))
    generation_id = _validate_generation_id(paths.generation_id)

    _reject_symlink_components(root, "Bundle root")

    generations = root / _GENERATIONS_NAME
    _reject_symlink_components(generations, "Generations directory")

    if not generations.is_dir():
        raise ValueError("Generations directory is missing")

    expected_staging = generations / f".staging-{generation_id}"
    expected_paths = _paths(root, generation_id, expected_staging)

    if paths != expected_paths:
        raise ValueError("Bundle paths do not match expected staging paths")

    _reject_symlink_components(expected_staging, "Staging generation")

    current = root / _CURRENT_NAME
    _validate_current_destination(current)
    _validate_complete_generation(expected_paths)

    final_root = generations / generation_id
    _reject_symlink_components(final_root, "Final generation")

    if final_root.exists():
        raise FileExistsError("Generation ID already exists")

    # Staging and final paths are siblings on the same filesystem.
    os.replace(expected_staging, final_root)
    _fsync_directory(generations)

    temporary_pointer = root / f".CURRENT-{uuid.uuid4().hex}.tmp"

    try:
        with temporary_pointer.open(
            "x",
            encoding="ascii",
            newline="\n",
        ) as stream:
            stream.write(generation_id + "\n")
            stream.flush()
            os.fsync(stream.fileno())

        # This replacement is the local publication commit point.
        os.replace(temporary_pointer, current)
        _fsync_directory(root)

    finally:
        # Cleanup after the commit point must never turn a successful
        # publication into a reported failure.
        try:
            temporary_pointer.unlink(missing_ok=True)
        except OSError:
            pass

    return _paths(root, generation_id, final_root)


def resolve_current_generation(bundle_root: Path) -> BundlePaths:
    """Resolve CURRENT exactly once and validate its referenced generation."""
    root = _absolute_path(Path(bundle_root))
    _reject_symlink_components(root, "Bundle root")

    if not root.is_dir():
        raise ValueError("Bundle root or CURRENT pointer is missing")

    current = root / _CURRENT_NAME
    generations = root / _GENERATIONS_NAME

    _reject_symlink_components(current, "CURRENT pointer")
    _reject_symlink_components(generations, "Generations directory")

    if not current.is_file():
        raise ValueError(
            "CURRENT pointer is missing or is not a regular file"
        )

    if not generations.is_dir():
        raise ValueError("Generations directory is missing")

    try:
        pointer_bytes = current.read_bytes()
    except OSError as exc:
        raise ValueError("Unable to read CURRENT pointer") from exc

    try:
        pointer = pointer_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("CURRENT pointer is not valid ASCII") from exc

    if not pointer.endswith("\n") or pointer.count("\n") != 1:
        raise ValueError("CURRENT pointer has invalid formatting")

    generation_id = _validate_generation_id(pointer[:-1])
    generation_root = generations / generation_id

    _reject_symlink_components(
        generation_root,
        "Current generation",
    )

    resolved_paths = _paths(root, generation_id, generation_root)
    _validate_complete_generation(resolved_paths)

    return resolved_paths
