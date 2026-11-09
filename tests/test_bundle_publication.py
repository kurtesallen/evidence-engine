"""Tests for immutable local bundle generations."""

import os
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest

from evidence_engine.bundle_publication import (
    cleanup_staging_generation,
    create_staging_generation,
    publish_generation,
    resolve_current_generation,
)


def _symlink_or_skip(
    link: Path,
    target: Path,
    *,
    target_is_directory: bool = False,
) -> None:
    try:
        link.symlink_to(
            target,
            target_is_directory=target_is_directory,
        )
    except OSError as exc:
        if getattr(exc, "winerror", None) == 1314:
            pytest.skip(
                "Windows symlink creation requires additional privileges"
            )
        raise
    except NotImplementedError:
        pytest.skip("Symlinks are not supported on this platform")


def complete_generation(bundle_root: Path):
    paths = create_staging_generation(bundle_root)
    paths.artifacts_root.mkdir()
    for name in ("plan.json", "state.json", "commit.txt", "version.txt"):
        (paths.artifacts_root / name).write_text(
            "test",
            encoding="utf-8",
        )
    paths.manifest_path.write_text("{}", encoding="utf-8")
    paths.signature_path.write_bytes(b"signature")
    return paths


def test_publish_and_resolve_generation(tmp_path: Path):
    root = tmp_path / "bundle"
    staged = complete_generation(root)
    published = publish_generation(staged)
    resolved = resolve_current_generation(root)
    assert resolved == published
    assert resolved.generation_root.is_dir()
    assert resolved.artifacts_root.is_dir()
    assert resolved.manifest_path.is_file()
    assert resolved.signature_path.is_file()
    assert (
        (root / "CURRENT").read_text(encoding="ascii")
        == published.generation_id + "\n"
    )


def test_resolve_rejects_missing_current(tmp_path: Path):
    with pytest.raises(ValueError, match="CURRENT"):
        resolve_current_generation(tmp_path / "bundle")


@pytest.mark.parametrize(
    "pointer",
    [
        "",
        "../outside\n",
        "/tmp/other\n",
        "not-a-generation\n",
        "a" * 32,
        "a" * 32 + "\nextra\n",
        " " + "a" * 32 + "\n",
    ],
)


def test_resolve_rejects_invalid_current_pointer(
    tmp_path: Path,
    pointer: str,
):
    root = tmp_path / "bundle"
    root.mkdir()
    (root / "generations").mkdir()
    (root / "CURRENT").write_text(pointer, encoding="ascii")
    with pytest.raises(ValueError):
        resolve_current_generation(root)


def test_failed_staging_does_not_replace_current(tmp_path: Path):
    root = tmp_path / "bundle"
    first = publish_generation(complete_generation(root))
    second = create_staging_generation(root)
    second.artifacts_root.mkdir()
    second.manifest_path.write_text("{}", encoding="utf-8")
    # Deliberately omit the signature.
    with pytest.raises(ValueError, match="signature"):
        publish_generation(second)
    assert (
        resolve_current_generation(root).generation_id
        == first.generation_id
    )


def test_old_generation_remains_available_after_publication(
    tmp_path: Path,
):
    root = tmp_path / "bundle"
    first = publish_generation(complete_generation(root))
    second = publish_generation(complete_generation(root))
    assert first.generation_id != second.generation_id
    assert first.generation_root.is_dir()
    assert second.generation_root.is_dir()
    assert (
        resolve_current_generation(root).generation_id
        == second.generation_id
    )


def test_publish_rejects_modified_bundle_paths(tmp_path: Path):
    root = tmp_path / "bundle"
    staged = complete_generation(root)
    forged_paths = replace(
        staged,
        manifest_path=tmp_path / "outside-manifest.json",
    )
    with pytest.raises(ValueError, match="paths do not match"):
        publish_generation(forged_paths)
    assert staged.generation_root.is_dir()
    assert not (root / "CURRENT").exists()


def test_publish_rejects_invalid_current_before_promotion(
    tmp_path: Path,
):
    root = tmp_path / "bundle"
    staged = complete_generation(root)
    current = root / "CURRENT"
    current.mkdir()
    with pytest.raises(ValueError, match="regular file"):
        publish_generation(staged)
    assert staged.generation_root.is_dir()
    assert not (root / "generations" / staged.generation_id).exists()


def test_resolve_rejects_symlinked_current(tmp_path: Path):
    root = tmp_path / "bundle"
    root.mkdir()
    (root / "generations").mkdir()
    target = tmp_path / "pointer-target"
    target.write_text("a" * 32 + "\n", encoding="ascii")
    _symlink_or_skip(root / "CURRENT", target)
    with pytest.raises(ValueError, match="symlink"):
        resolve_current_generation(root)


def test_resolve_rejects_symlinked_generation(tmp_path: Path):
    root = tmp_path / "bundle"
    generations = root / "generations"
    generations.mkdir(parents=True)
    target = tmp_path / "outside"
    target.mkdir()
    generation_id = "a" * 32
    _symlink_or_skip(
        generations / generation_id,
        target,
        target_is_directory=True,
    )
    (root / "CURRENT").write_text(
        generation_id + "\n",
        encoding="ascii",
    )
    with pytest.raises(ValueError, match="symlink"):
        resolve_current_generation(root)


def test_cleanup_removes_only_staging_generation(tmp_path: Path):
    root = tmp_path / "bundle"
    published = publish_generation(complete_generation(root))
    staged = complete_generation(root)
    assert cleanup_staging_generation(staged) is True
    assert not staged.generation_root.exists()
    # Cleanup must not affect the currently published generation.
    assert published.generation_root.is_dir()
    assert (
        resolve_current_generation(root).generation_id
        == published.generation_id
    )


def test_cleanup_returns_false_for_missing_staging_generation(
    tmp_path: Path,
):
    staged = complete_generation(tmp_path / "bundle")
    assert cleanup_staging_generation(staged) is True
    assert cleanup_staging_generation(staged) is False


def test_cleanup_rejects_modified_bundle_paths(tmp_path: Path):
    staged = complete_generation(tmp_path / "bundle")
    forged = replace(
        staged,
        generation_root=tmp_path / "outside",
    )
    with pytest.raises(ValueError, match="paths do not match"):
        cleanup_staging_generation(forged)
    assert staged.generation_root.is_dir()


def test_cleanup_rejects_published_generation_paths(tmp_path: Path):
    staged = complete_generation(tmp_path / "bundle")
    published = publish_generation(staged)
    with pytest.raises(ValueError, match="paths do not match"):
        cleanup_staging_generation(published)
    assert published.generation_root.is_dir()


def test_current_replacement_failure_preserves_previous_generation(
    tmp_path: Path,
):
    """Failed CURRENT replacement preserves the previous generation."""
    root = tmp_path / "bundle"
    first = publish_generation(complete_generation(root))
    second = complete_generation(root)
    original_replace = os.replace
    def fail_current_replacement(src, dst):
        if Path(dst) == root / "CURRENT":
            raise OSError("Simulated CURRENT replacement failure")
        return original_replace(src, dst)
    with patch(
        "evidence_engine.bundle_publication.os.replace",
        side_effect=fail_current_replacement,
    ):
        with pytest.raises(
            OSError,
            match="Simulated CURRENT replacement failure",
        ):
            publish_generation(second)
    assert resolve_current_generation(root) == first
    unreferenced = root / "generations" / second.generation_id
    assert unreferenced.is_dir()
    assert (unreferenced / "manifest.json").is_file()
    assert (unreferenced / "manifest.sig").is_file()
    assert list(root.glob(".CURRENT-*.tmp")) == []
    assert first.generation_root.is_dir()
    assert first.manifest_path.is_file()
    assert first.signature_path.is_file()


def test_directory_fsync_failure_is_best_effort(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """Directory sync failures do not prevent publication."""
    import evidence_engine.bundle_publication as publication
    root = tmp_path / "bundle"
    root.mkdir()
    attempted_directories = []
    def fail_directory_fsync(path: Path) -> None:
        attempted_directories.append(Path(path))
        # Simulate an unavailable directory synchronization operation.
        # The real helper suppresses OSError internally.
        return None
    monkeypatch.setattr(
        publication,
        "_fsync_directory",
        fail_directory_fsync,
    )
    staged = complete_generation(root)
    published = publication.publish_generation(staged)
    assert publication.resolve_current_generation(root) == published
    assert root / "generations" in attempted_directories
    assert root in attempted_directories
    assert (root / "CURRENT").read_text(
        encoding="ascii"
    ) == published.generation_id + "\n"
