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




@pytest.mark.skipif(
    os.name != "posix",
    reason="Requires POSIX descriptor-relative traversal",
)
@pytest.mark.xfail(
    strict=True,
    reason=(
        "Threat Model A excludes same-owner mutation of trust directories; "
        "nested directory replacement remains a known limitation"
    ),
)
def test_production_loader_rejects_nested_key_directory_replacement(
    trust_material,
    monkeypatch,
):
    """A nested directory swap must not silently substitute a trust key."""
    if not trust._supports_secure_trust_traversal():
        pytest.skip("Secure POSIX traversal unavailable")

    project, config, keys, key_path, expected, registry = trust_material
    registry_path = registry(
        config / "trust.json",
        "../keys/public.pem",
    )

    attacker_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    attacker_public_key = attacker_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    original_reader = trust._read_from_pinned_root
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

        if label == "Trust registry" and not replaced:
            replaced = True
            keys.rename(project / "original_keys")
            keys.mkdir()
            (keys / "public.pem").write_bytes(attacker_public_key)

        return result

    monkeypatch.setattr(
        trust,
        "_read_from_pinned_root",
        replace_after_registry_read,
    )

    try:
        loaded = trust.load_trusted_key_bytes(
            registry_path,
            KEY_ID,
            SOURCE,
        )
    except (ValueError, OSError):
        return  # Rejecting the replacement is acceptable.

    assert loaded == expected, (
        "Nested directory replacement substituted an unauthorized key"
    )


@pytest.mark.skipif(
    os.name != "posix",
    reason="Requires POSIX filesystem permissions",
)
@pytest.mark.parametrize(
    "target",
    ["project", "config", "registry", "key"],
)
@pytest.mark.parametrize("write_bit", [0o020, 0o002])
def test_production_loader_rejects_untrusted_writable_material(
    trust_material,
    target,
    write_bit,
):
    """Production trust material must reject group/other write access."""
    if not trust._supports_secure_trust_traversal():
        pytest.skip("Secure POSIX traversal unavailable")

    project, config, keys, key_path, expected, registry = trust_material

    registry_path = registry(
        config / "trust.json",
        "../keys/public.pem",
    )

    targets = {
        "project": project,
        "config": config,
        "registry": registry_path,
        "key": key_path,
    }

    path = targets[target]
    original_mode = path.stat().st_mode & 0o777

    try:
        path.chmod(original_mode | write_bit)

        with pytest.raises(ValueError, match="permissions|writable"):
            trust.load_trusted_key_bytes(
                registry_path,
                KEY_ID,
                SOURCE,
            )
    finally:
        path.chmod(original_mode)


@pytest.mark.parametrize(
    "target",
    ["project", "config", "registry", "key"],
)
def test_production_loader_rejects_untrusted_ownership(
    trust_material,
    monkeypatch,
    target,
):
    """Reject trust descriptors owned by an unrelated user."""
    if not trust._supports_secure_trust_traversal():
        pytest.skip("Secure POSIX traversal unavailable")

    project, config, keys, key_path, expected, registry = trust_material

    registry_path = registry(
        config / "trust.json",
        "../keys/public.pem",
    )

    targets = {
        "project": project,
        "config": config,
        "registry": registry_path,
        "key": key_path,
    }

    original_fstat = trust.os.fstat
    target_stat = targets[target].stat()

    def untrusted_fstat(fd):
        metadata = original_fstat(fd)

        if (
            metadata.st_dev == target_stat.st_dev
            and metadata.st_ino == target_stat.st_ino
        ):
            values = list(metadata)
            values[4] = trust.os.geteuid() + 10000
            return trust.os.stat_result(values)

        return metadata

    monkeypatch.setattr(trust.os, "fstat", untrusted_fstat)

    with pytest.raises(ValueError, match="ownership"):
        trust.load_trusted_key_bytes(
            registry_path,
            KEY_ID,
            SOURCE,
        )


@pytest.mark.parametrize(
    "target",
    ["project", "config", "registry", "key"],
)
def test_production_loader_fails_closed_on_fstat_error(
    trust_material,
    monkeypatch,
    target,
):
    """Descriptor metadata failures must reject trust material."""
    if not trust._supports_secure_trust_traversal():
        pytest.skip("Secure POSIX traversal unavailable")

    project, config, keys, key_path, expected, registry = trust_material

    registry_path = registry(
        config / "trust.json",
        "../keys/public.pem",
    )

    targets = {
        "project": project,
        "config": config,
        "registry": registry_path,
        "key": key_path,
    }

    original_fstat = trust.os.fstat
    target_stat = targets[target].stat()

    def failing_fstat(fd):
        metadata = original_fstat(fd)

        if (
            metadata.st_dev == target_stat.st_dev
            and metadata.st_ino == target_stat.st_ino
        ):
            raise OSError("simulated metadata failure")

        return metadata

    monkeypatch.setattr(trust.os, "fstat", failing_fstat)

    with pytest.raises(ValueError, match="inspected"):
        trust.load_trusted_key_bytes(
            registry_path,
            KEY_ID,
            SOURCE,
        )


@pytest.mark.parametrize("write_bit", [0o020, 0o002])
def test_production_loader_rejects_writable_nested_key_directory(
    trust_material,
    write_bit,
):
    """Nested key directories must not be group/other writable."""
    if not trust._supports_secure_trust_traversal():
        pytest.skip("Secure POSIX traversal unavailable")

    project, config, keys, key_path, expected, registry = trust_material

    nested = keys / "nested"
    nested.mkdir()
    nested_key = nested / "public.pem"
    nested_key.write_bytes(key_path.read_bytes())

    registry_path = registry(
        config / "trust.json",
        "../keys/nested/public.pem",
    )

    original_mode = nested.stat().st_mode & 0o777

    try:
        nested.chmod(original_mode | write_bit)

        with pytest.raises(ValueError, match="permissions"):
            trust.load_trusted_key_bytes(
                registry_path,
                KEY_ID,
                SOURCE,
            )
    finally:
        nested.chmod(original_mode)


@pytest.mark.parametrize(
    "target",
    ["project", "config", "registry", "key"],
)
def test_production_loader_closes_descriptors_on_validation_failure(
    trust_material,
    monkeypatch,
    target,
):
    """Every descriptor opened by the loader closes after rejection."""
    if not trust._supports_secure_trust_traversal():
        pytest.skip("Secure POSIX traversal unavailable")

    project, config, keys, key_path, expected, registry = trust_material

    registry_path = registry(
        config / "trust.json",
        "../keys/public.pem",
    )

    targets = {
        "project": project,
        "config": config,
        "registry": registry_path,
        "key": key_path,
    }

    target_stat = targets[target].stat()
    original_fstat = os.fstat
    original_open = os.open
    original_close = os.close

    opened = []
    closed = []
    injected = False

    def tracked_open(*args, **kwargs):
        fd = original_open(*args, **kwargs)
        opened.append(fd)
        return fd

    def tracked_close(fd):
        closed.append(fd)
        return original_close(fd)

    def failing_fstat(fd):
        nonlocal injected

        metadata = original_fstat(fd)

        if (
            metadata.st_dev == target_stat.st_dev
            and metadata.st_ino == target_stat.st_ino
        ):
            injected = True
            raise OSError("simulated metadata failure")

        return metadata

    monkeypatch.setattr(trust.os, "open", tracked_open)
    monkeypatch.setattr(trust.os, "close", tracked_close)
    monkeypatch.setattr(trust.os, "fstat", failing_fstat)

    monkeypatch.setattr(
        trust,
        "_supports_secure_trust_traversal",
        lambda: True,
    )

    with pytest.raises(ValueError, match="inspected"):
        trust.load_trusted_key_bytes(
            registry_path,
            KEY_ID,
            SOURCE,
        )

    assert injected, "Target descriptor was never inspected"
    assert opened, "No descriptors were opened"
    assert sorted(opened) == sorted(closed)

@pytest.mark.parametrize(
    ("mode", "owner_is_root", "allow_ancestor", "accepted"),
    [
        (0o41777, True, True, True),
        (0o40777, True, True, False),
        (0o41777, True, False, False),
        (0o41777, False, True, False),
    ],
)
def test_trust_descriptor_sticky_ancestor_policy(
    tmp_path,
    monkeypatch,
    mode,
    owner_is_root,
    allow_ancestor,
    accepted,
):
    """Only root-owned sticky ancestors receive the write exception."""
    if os.name != "posix":
        pytest.skip("Requires POSIX descriptor metadata")

    directory = tmp_path / "ancestor"
    directory.mkdir()

    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)

    original_fstat = trust.os.fstat
    original_euid = trust.os.geteuid

    try:
        def synthetic_fstat(candidate):
            metadata = original_fstat(candidate)

            if candidate != fd:
                return metadata

            values = list(metadata)
            values[0] = mode
            values[4] = 0 if owner_is_root else original_euid() + 10000

            return os.stat_result(values)

        monkeypatch.setattr(trust.os, "fstat", synthetic_fstat)

        if accepted:
            trust._validate_trust_descriptor(
                fd,
                "Ancestor",
                allow_sticky_ancestor=allow_ancestor,
            )
        else:
            with pytest.raises(ValueError):
                trust._validate_trust_descriptor(
                    fd,
                    "Ancestor",
                    allow_sticky_ancestor=allow_ancestor,
                )
    finally:
        os.close(fd)