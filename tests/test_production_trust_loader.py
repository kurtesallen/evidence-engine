"""Security regressions for the production trust-key loader."""

import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import evidence_engine.trust as trust


KEY_ID = "production-test-key"
SOURCE = "local-claimed"


@pytest.fixture
def trust_material(tmp_path):
    project = tmp_path / "project"
    config = project / "config"
    keys = project / "keys"
    config.mkdir(parents=True)
    keys.mkdir()

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    key_path = keys / "public.pem"
    key_path.write_bytes(public_key)

    def registry(path, public_key_path):
        path.write_text(
            json.dumps({
                "schema_version": "1.0",
                "keys": [{
                    "key_id": KEY_ID,
                    "public_key": public_key_path,
                    "status": "active",
                    "allowed_sources": [SOURCE],
                }],
            }),
            encoding="utf-8",
        )
        return path

    return project, config, keys, key_path, public_key, registry


def test_production_loader_accepts_config_layout(trust_material):
    project, config, keys, key_path, expected, registry = trust_material
    registry_path = registry(
        config / "trust.json",
        "../keys/public.pem",
    )

    assert trust.load_trusted_key_bytes(
        registry_path, KEY_ID, SOURCE
    ) == expected


def test_production_loader_accepts_root_layout(trust_material):
    project, config, keys, key_path, expected, registry = trust_material
    registry_path = registry(
        project / "trust.json",
        "keys/public.pem",
    )

    assert trust.load_trusted_key_bytes(
        registry_path, KEY_ID, SOURCE
    ) == expected


@pytest.mark.parametrize("target", ["registry", "key"])
def test_production_loader_rejects_oversized_material(
    trust_material, target
):
    project, config, keys, key_path, expected, registry = trust_material
    registry_path = registry(
        config / "trust.json",
        "../keys/public.pem",
    )

    if target == "registry":
        registry_path.write_bytes(b"x" * (64 * 1024 + 1))
    else:
        key_path.write_bytes(b"x" * (16 * 1024 + 1))

    with pytest.raises(ValueError):
        trust.load_trusted_key_bytes(
            registry_path, KEY_ID, SOURCE
        )


@pytest.mark.parametrize(
    "configured",
    [
        "../../outside.pem",
        "/tmp/outside.pem",
        r"C:\outside.pem",
        r"..\keys\public.pem",
    ],
)
def test_production_loader_rejects_unsafe_key_paths(
    trust_material, configured
):
    project, config, keys, key_path, expected, registry = trust_material
    registry_path = registry(
        config / "trust.json",
        configured,
    )

    with pytest.raises(ValueError):
        trust.load_trusted_key_bytes(
            registry_path, KEY_ID, SOURCE
        )


def test_production_loader_rejects_unauthorized_source(trust_material):
    project, config, keys, key_path, expected, registry = trust_material
    registry_path = registry(
        config / "trust.json",
        "../keys/public.pem",
    )

    with pytest.raises(ValueError):
        trust.load_trusted_key_bytes(
            registry_path, KEY_ID, "github-actions-claimed"
        )


@pytest.mark.skipif(
    os.name != "posix",
    reason="POSIX symlink regression",
)
@pytest.mark.parametrize("target", ["registry", "key", "key_parent"])
def test_production_loader_rejects_symlinks(
    trust_material, tmp_path, target
):
    if not trust._supports_secure_trust_traversal():
        pytest.skip("Secure POSIX traversal unavailable")

    project, config, keys, key_path, expected, registry = trust_material
    registry_path = registry(
        config / "trust.json",
        "../keys/public.pem",
    )

    if target == "registry":
        replacement = config / "original.json"
        registry_path.rename(replacement)
        registry_path.symlink_to(replacement)
    elif target == "key":
        replacement = keys / "original.pem"
        key_path.rename(replacement)
        key_path.symlink_to(replacement)
    else:
        replacement = project / "original_keys"
        keys.rename(replacement)
        keys.symlink_to(replacement, target_is_directory=True)

    with pytest.raises((OSError, ValueError)):
        trust.load_trusted_key_bytes(
            registry_path, KEY_ID, SOURCE
        )


def test_production_loader_fails_closed_without_secure_posix(
    trust_material, monkeypatch
):
    if os.name != "posix":
        pytest.skip("Unsupported POSIX behavior only")

    project, config, keys, key_path, expected, registry = trust_material
    registry_path = registry(
        config / "trust.json",
        "../keys/public.pem",
    )

    monkeypatch.setattr(
        trust,
        "_supports_secure_trust_traversal",
        lambda: False,
    )

    with pytest.raises(ValueError, match="unavailable"):
        trust.load_trusted_key_bytes(
            registry_path, KEY_ID, SOURCE
        )


@pytest.mark.skipif(
    os.name != "posix",
    reason="Requires POSIX descriptor-relative traversal",
)
def test_production_loader_uses_pinned_root_after_path_replacement(
    trust_material,
    monkeypatch,
):
    """Replacing the project pathname must not redirect key loading."""
    if not trust._supports_secure_trust_traversal():
        pytest.skip("Secure POSIX traversal unavailable")

    project, config, keys, key_path, expected, registry = trust_material

    registry_path = registry(
        config / "trust.json",
        "../keys/public.pem",
    )

    original_reader = trust._read_from_pinned_root
    reads = []

    def replace_project_after_registry_read(
        root_fd,
        relative_path,
        *,
        label,
        maximum,
    ):
        result = original_reader(
            root_fd,
            relative_path,
            label=label,
            maximum=maximum,
        )

        reads.append(label)

        if label == "Trust registry":
            moved_project = project.with_name("original_project")

            # Move the legitimate tree away from its original pathname.
            project.rename(moved_project)

            # Create a replacement tree at the same pathname.
            replacement_keys = project / "keys"
            replacement_keys.mkdir(parents=True)

            # The replacement contains invalid attacker-controlled key data.
            (replacement_keys / "public.pem").write_bytes(
                b"attacker-controlled-invalid-public-key"
            )

        return result

    monkeypatch.setattr(
        trust,
        "_read_from_pinned_root",
        replace_project_after_registry_read,
    )

    loaded = trust.load_trusted_key_bytes(
        registry_path,
        KEY_ID,
        SOURCE,
    )

    # The loader must return the original authorized key.
    assert loaded == expected

    # Both reads must have occurred.
    assert reads == [
        "Trust registry",
        "Trusted public key",
    ]


@pytest.mark.skipif(
    os.name != "posix",
    reason="Requires POSIX file descriptors",
)
@pytest.mark.parametrize(
    "failure",
    ["none", "unauthorized", "invalid_key"],
)
def test_production_loader_closes_pinned_root(
    trust_material,
    monkeypatch,
    failure,
):
    """The pinned root descriptor must close on every exit path."""
    if not trust._supports_secure_trust_traversal():
        pytest.skip("Secure POSIX traversal unavailable")

    project, config, keys, key_path, expected, registry = trust_material
    registry_path = registry(
        config / "trust.json",
        "../keys/public.pem",
    )

    if failure == "invalid_key":
        key_path.write_bytes(b"invalid-public-key")

    original_open = trust._open_pinned_project_root
    descriptors = []

    def tracked_open(path):
        fd = original_open(path)
        descriptors.append(fd)
        return fd

    monkeypatch.setattr(
        trust,
        "_open_pinned_project_root",
        tracked_open,
    )

    try:
        if failure == "none":
            assert trust.load_trusted_key_bytes(
                registry_path, KEY_ID, SOURCE
            ) == expected
        elif failure == "unauthorized":
            with pytest.raises(ValueError):
                trust.load_trusted_key_bytes(
                    registry_path,
                    KEY_ID,
                    "github-actions-claimed",
                )
        else:
            with pytest.raises(ValueError):
                trust.load_trusted_key_bytes(
                    registry_path, KEY_ID, SOURCE
                )

        assert len(descriptors) == 1

        with pytest.raises(OSError):
            os.fstat(descriptors[0])
    finally:
        # Defensive cleanup if a regression leaves the descriptor open.
        for fd in descriptors:
            try:
                os.close(fd)
            except OSError:
                pass


@pytest.mark.skipif(
    os.name != "posix",
    reason="Requires POSIX directory descriptors",
)
def test_pinned_root_open_closes_new_descriptor_if_previous_close_fails(
    tmp_path,
    monkeypatch,
):
    """A failed handoff must not leak the newly opened directory."""
    if not trust._supports_secure_trust_traversal():
        pytest.skip("Secure POSIX traversal unavailable")

    project = tmp_path / "project"
    project.mkdir()

    real_open = trust.os.open
    real_close = trust.os.close

    opened = []
    failed = False

    def tracked_open(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        opened.append(fd)
        return fd

    def fail_one_close(fd):
        nonlocal failed

        if not failed:
            failed = True
            real_close(fd)
            raise OSError("simulated directory close failure")

        return real_close(fd)

    monkeypatch.setattr(trust.os, "open", tracked_open)
    monkeypatch.setattr(trust.os, "close", fail_one_close)

    with pytest.raises(OSError, match="simulated directory close failure"):
        trust._open_pinned_project_root(project)

    assert len(opened) >= 2

    for fd in opened:
        with pytest.raises(OSError):
            os.fstat(fd)


@pytest.mark.skipif(
    os.name != "posix",
    reason="Requires POSIX descriptor-relative traversal",
)
def test_root_layout_remains_pinned_after_project_replacement(
    trust_material,
    monkeypatch,
):
    """Replacing the project pathname must not redirect root-layout keys."""
    if not trust._supports_secure_trust_traversal():
        pytest.skip("Secure POSIX traversal unavailable")

    project, config, keys, key_path, expected, registry = trust_material

    registry_path = registry(
        project / "trust.json",
        "keys/public.pem",
    )

    original_reader = trust._read_from_pinned_root
    reads = []
    replaced = False

    def replace_after_registry_read(
        root_fd,
        relative_path,
        *,
        label,
        maximum,
    ):
        nonlocal replaced

        result = original_reader(
            root_fd,
            relative_path,
            label=label,
            maximum=maximum,
        )
        reads.append(label)

        if label == "Trust registry" and not replaced:
            replaced = True

            moved_project = project.with_name("original_project")
            project.rename(moved_project)

            replacement_keys = project / "keys"
            replacement_keys.mkdir(parents=True)

            (replacement_keys / "public.pem").write_bytes(
                b"attacker-controlled-invalid-public-key"
            )

        return result

    monkeypatch.setattr(
        trust,
        "_read_from_pinned_root",
        replace_after_registry_read,
    )

    loaded = trust.load_trusted_key_bytes(
        registry_path,
        KEY_ID,
        SOURCE,
    )

    assert loaded == expected
    assert reads == [
        "Trust registry",
        "Trusted public key",
    ]