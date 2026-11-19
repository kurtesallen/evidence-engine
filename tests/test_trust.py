from pathlib import Path
import json

import pytest
from evidence_engine.trust import _supports_secure_trust_traversal

from evidence_engine.trust import (
    load_trust_registry,
    resolve_trusted_key,
)


def write_registry(path, public_key, *, status="active", sources=None):
    registry = {
        "schema_version": "1.0",
        "keys": [
            {
                "key_id": "test-key",
                "public_key": str(public_key),
                "status": status,
                "allowed_sources": (
                    ["local-claimed"] if sources is None else sources
                ),
            }
        ],
    }
    path.write_text(json.dumps(registry), encoding="utf-8")


def test_active_authorized_key_is_resolved(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    project = tmp_path / "project"
    config = project / "config"
    keys = project / "keys"
    config.mkdir(parents=True)
    keys.mkdir()

    public_key = keys / "public.pem"
    public_key.write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    registry_path = config / "trust_registry.json"
    write_registry(
        registry_path,
        "../keys/public.pem",
    )

    resolved = resolve_trusted_key(
        registry_path,
        "test-key",
        "local-claimed",
    )

    assert resolved == public_key.resolve()


def test_unknown_key_id_is_rejected(tmp_path):
    registry = tmp_path / "trust_registry.json"
    registry.write_text(
        json.dumps({"schema_version": "1.0", "keys": []}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Unknown or ambiguous"):
        resolve_trusted_key(
            registry,
            "unknown-key",
            "local-claimed",
        )


@pytest.mark.parametrize("status", ["revoked", "retired"])
def test_inactive_key_is_rejected(tmp_path, status):
    registry = tmp_path / "trust_registry.json"
    write_registry(
        registry,
        "unused.pem",
        status=status,
    )

    with pytest.raises(ValueError, match="not active"):
        resolve_trusted_key(
            registry,
            "test-key",
            "local-claimed",
        )


def test_disallowed_source_is_rejected(tmp_path):
    registry = tmp_path / "trust_registry.json"
    write_registry(
        registry,
        "unused.pem",
        sources=["github-actions-claimed"],
    )

    with pytest.raises(ValueError, match="not authorized"):
        resolve_trusted_key(
            registry,
            "test-key",
            "local-claimed",
        )


def test_duplicate_key_ids_are_rejected(tmp_path):
    registry = tmp_path / "trust_registry.json"

    entry = {
        "key_id": "duplicate",
        "public_key": "unused.pem",
        "status": "active",
        "allowed_sources": ["local-claimed"],
    }

    registry.write_text(
        json.dumps({
            "schema_version": "1.0",
            "keys": [entry, entry],
        }),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Duplicate trust registry key ID"):
        load_trust_registry(registry)


def test_parsed_registry_validation_matches_file_validation(tmp_path):
    import json

    from evidence_engine.trust import (
        _validate_trust_registry,
        load_trust_registry,
    )

    registry_path = tmp_path / "trust_registry.json"

    registry = {
        "schema_version": "1.0",
        "keys": [
            {
                "key_id": "test-key",
                "public_key": "../keys/public.pem",
                "status": "active",
                "allowed_sources": ["local-claimed"],
            }
        ],
    }

    registry_path.write_text(
        json.dumps(registry),
        encoding="utf-8",
    )

    assert _validate_trust_registry(registry) == registry
    assert load_trust_registry(registry_path) == registry


def test_parsed_registry_validation_rejects_duplicate_keys():
    import pytest

    from evidence_engine.trust import _validate_trust_registry

    entry = {
        "key_id": "duplicate",
        "public_key": "../keys/public.pem",
        "status": "active",
        "allowed_sources": ["local-claimed"],
    }

    registry = {
        "schema_version": "1.0",
        "keys": [entry, entry],
    }

    with pytest.raises(
        ValueError,
        match="Duplicate trust registry key ID",
    ):
        _validate_trust_registry(registry)


def test_authorization_helper_selects_active_allowed_key():
    from evidence_engine.trust import _authorize_trusted_key

    entry = {
        "key_id": "test-key",
        "public_key": "../keys/public.pem",
        "status": "active",
        "allowed_sources": ["local-claimed"],
    }

    registry = {
        "schema_version": "1.0",
        "keys": [entry],
    }

    assert (
        _authorize_trusted_key(
            registry,
            "test-key",
            "local-claimed",
        )
        is entry
    )


def test_authorization_helper_rejects_disallowed_source():
    from evidence_engine.trust import _authorize_trusted_key

    registry = {
        "schema_version": "1.0",
        "keys": [
            {
                "key_id": "test-key",
                "public_key": "../keys/public.pem",
                "status": "active",
                "allowed_sources": ["github-actions-claimed"],
            }
        ],
    }

    with pytest.raises(
        ValueError,
        match="Signing key is not authorized for this source",
    ):
        _authorize_trusted_key(
            registry,
            "test-key",
            "local-claimed",
        )


@pytest.mark.parametrize("maximum", [0, 1, 16, 1024])
def test_bounded_trust_file_accepts_within_limit(
    tmp_path,
    maximum,
):
    from evidence_engine.trust import _read_bounded_trust_file

    path = tmp_path / "trust.bin"
    content = b"x" * maximum
    path.write_bytes(content)

    assert _read_bounded_trust_file(
        path,
        label="Trust test",
        maximum=maximum,
    ) == content


def test_bounded_trust_file_rejects_oversized_file(tmp_path):
    from evidence_engine.trust import _read_bounded_trust_file

    path = tmp_path / "trust.bin"
    path.write_bytes(b"x" * 1025)

    with pytest.raises(ValueError, match="exceeds size limit"):
        _read_bounded_trust_file(
            path,
            label="Trust test",
            maximum=1024,
        )


def test_bounded_trust_file_rejects_invalid_limit(tmp_path):
    from evidence_engine.trust import _read_bounded_trust_file

    path = tmp_path / "trust.bin"
    path.write_bytes(b"test")

    with pytest.raises(ValueError, match="Invalid Trust test size limit"):
        _read_bounded_trust_file(
            path,
            label="Trust test",
            maximum=-1,
        )


def test_bounded_trust_file_rejects_directory(tmp_path):
    from evidence_engine.trust import _read_bounded_trust_file

    try:
        _read_bounded_trust_file(
            tmp_path,
            label="Trust test",
            maximum=1024,
        )
    except (OSError, ValueError) as exc:
        assert isinstance(exc, OSError) or (
            "not a regular file" in str(exc)
        )
    else:
        pytest.fail("Directory was accepted as a trust file")


def test_bounded_loader_accepts_authorized_key(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    from evidence_engine.trust import load_bounded_trusted_key

    project = tmp_path / "project"
    config = project / "config"
    keys = project / "keys"

    config.mkdir(parents=True)
    keys.mkdir()

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    public_key_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    (keys / "public.pem").write_bytes(public_key_bytes)

    registry_path = config / "trust_registry.json"
    write_registry(registry_path, "../keys/public.pem")

    result = load_bounded_trusted_key(
        registry_path,
        "test-key",
        "local-claimed",
    )

    assert result == public_key_bytes


@pytest.mark.parametrize(
    "target,maximum",
    [
        ("registry", 64 * 1024),
        ("key", 16 * 1024),
    ],
)
def test_bounded_loader_rejects_oversized_trust_material(
    tmp_path,
    target,
    maximum,
):
    from evidence_engine.trust import load_bounded_trusted_key

    project = tmp_path / "project"
    config = project / "config"
    keys = project / "keys"

    config.mkdir(parents=True)
    keys.mkdir()

    registry_path = config / "trust_registry.json"
    key_path = keys / "public.pem"

    write_registry(registry_path, "../keys/public.pem")

    if target == "registry":
        registry_path.write_bytes(b"x" * (maximum + 1))
    else:
        key_path.write_bytes(b"x" * (maximum + 1))

    with pytest.raises(ValueError, match="exceeds size limit"):
        load_bounded_trusted_key(
            registry_path,
            "test-key",
            "local-claimed",
        )


def test_bounded_loader_rejects_invalid_public_key(tmp_path):
    from evidence_engine.trust import load_bounded_trusted_key

    project = tmp_path / "project"
    config = project / "config"
    keys = project / "keys"

    config.mkdir(parents=True)
    keys.mkdir()

    registry_path = config / "trust_registry.json"
    write_registry(registry_path, "../keys/public.pem")

    (keys / "public.pem").write_bytes(b"not-a-public-key")

    with pytest.raises(
        ValueError,
        match="Trusted public key cannot be loaded",
    ):
        load_bounded_trusted_key(
            registry_path,
            "test-key",
            "local-claimed",
        )


def test_bounded_loader_rejects_unauthorized_source(tmp_path):
    from evidence_engine.trust import load_bounded_trusted_key

    config = tmp_path / "project" / "config"
    config.mkdir(parents=True)
    registry_path = config / "trust_registry.json"

    write_registry(
        registry_path,
        "unused.pem",
        sources=["github-actions-claimed"],
    )

    with pytest.raises(ValueError, match="not authorized"):
        load_bounded_trusted_key(
            registry_path,
            "test-key",
            "local-claimed",
        )


def test_bounded_loader_rejects_symlinked_registry(tmp_path):
    from evidence_engine.trust import load_bounded_trusted_key

    config = tmp_path / "project" / "config"
    config.mkdir(parents=True)
    actual = config / "actual.json"
    write_registry(actual, "unused.pem")

    linked = config / "trust_registry.json"

    try:
        linked.symlink_to(actual)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks unavailable on this platform")

    with pytest.raises(OSError):
        load_bounded_trusted_key(
            linked,
            "test-key",
            "local-claimed",
        )


def test_bounded_loader_rejects_symlinked_public_key(tmp_path):
    from evidence_engine.trust import load_bounded_trusted_key

    project = tmp_path / "project"
    config = project / "config"
    keys = project / "keys"

    config.mkdir(parents=True)
    keys.mkdir()

    registry = config / "trust_registry.json"
    write_registry(registry, "../keys/public.pem")

    actual = keys / "actual.pem"
    actual.write_bytes(b"placeholder")

    linked = keys / "public.pem"

    try:
        linked.symlink_to(actual)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks unavailable on this platform")

    with pytest.raises(OSError):
        load_bounded_trusted_key(
            registry,
            "test-key",
            "local-claimed",
        )


def test_bounded_loader_rejects_symlinked_key_parent(tmp_path):
    from evidence_engine.trust import load_bounded_trusted_key

    project = tmp_path / "project"
    config = project / "config"
    actual_keys = project / "actual_keys"
    linked_keys = project / "keys"

    config.mkdir(parents=True)
    actual_keys.mkdir()

    (actual_keys / "public.pem").write_bytes(b"placeholder")

    try:
        linked_keys.symlink_to(actual_keys, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks unavailable on this platform")

    registry = config / "trust_registry.json"
    write_registry(registry, "../keys/public.pem")

    with pytest.raises(OSError):
        load_bounded_trusted_key(
            registry,
            "test-key",
            "local-claimed",
        )


def test_bounded_trust_file_rejects_oversized_before_read(
    tmp_path,
    monkeypatch,
):
    import os

    from evidence_engine.trust import _read_bounded_trust_file

    path = tmp_path / "oversized.bin"
    path.write_bytes(b"x" * 1025)

    original_fdopen = os.fdopen

    class GuardedStream:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def fileno(self):
            return self.stream.fileno()

        def read(self, *args, **kwargs):
            pytest.fail("Oversized file was read")

    def guarded_fdopen(*args, **kwargs):
        return GuardedStream(original_fdopen(*args, **kwargs))

    monkeypatch.setattr(os, "fdopen", guarded_fdopen)

    with pytest.raises(ValueError, match="exceeds size limit"):
        _read_bounded_trust_file(
            path,
            label="Trust test",
            maximum=1024,
        )


def test_bounded_trust_file_reads_open_descriptor_after_path_replacement(
    tmp_path,
    monkeypatch,
):
    import os

    from evidence_engine.trust import _read_bounded_trust_file

    target = tmp_path / "trusted.bin"
    replacement = tmp_path / "replacement.bin"

    original_content = b"ORIGINAL-TRUST-MATERIAL"
    replacement_content = b"REPLACEMENT-TRUST-MATERIAL"

    target.write_bytes(original_content)
    replacement.write_bytes(replacement_content)

    original_fdopen = os.fdopen
    replaced = False

    def replacing_fdopen(descriptor, *args, **kwargs):
        nonlocal replaced

        if not replaced:
            replaced = True

            # The descriptor already refers to the original file.
            # Replace the pathname before the reader performs fstat/read.
            try:
                os.replace(replacement, target)
            except PermissionError:
                if os.name == "nt":
                    pytest.skip(
                        "Windows prevents replacing an open file"
                    )
                raise

        return original_fdopen(descriptor, *args, **kwargs)

    monkeypatch.setattr(os, "fdopen", replacing_fdopen)

    content = _read_bounded_trust_file(
        target,
        label="Trust test",
        maximum=1024,
    )

    assert replaced is True
    assert content == original_content
    assert target.read_bytes() == replacement_content


def test_secure_trust_traversal_capability_matches_platform():
    import os

    from evidence_engine.trust import (
        _supports_secure_trust_traversal,
    )

    expected = (
        os.name == "posix"
        and hasattr(os, "O_NOFOLLOW")
        and hasattr(os, "O_DIRECTORY")
        and os.open in os.supports_dir_fd
    )

    assert _supports_secure_trust_traversal() is expected



def test_secure_project_reader_closes_descriptors_on_success(
    tmp_path,
    monkeypatch,
):
    import os
    import pytest

    from evidence_engine.trust import (
        _read_secure_project_file,
        _supports_secure_trust_traversal,
    )

    if not _supports_secure_trust_traversal():
        pytest.skip("Secure descriptor traversal unavailable")

    project = tmp_path / "project"
    project.mkdir()
    target = project / "public.pem"
    target.write_bytes(b"VALID")

    original_open = os.open
    original_close = os.close
    opened = []
    closed = []

    def tracked_open(*args, **kwargs):
        descriptor = original_open(*args, **kwargs)
        opened.append(descriptor)
        return descriptor

    def tracked_close(descriptor):
        closed.append(descriptor)
        return original_close(descriptor)

    with monkeypatch.context() as patch:
        patch.setattr(
            "evidence_engine.trust._supports_secure_trust_traversal",
            lambda: True,
        )

        patch.setattr(
            "evidence_engine.trust.os.open",
            tracked_open,
        )
        patch.setattr(
            "evidence_engine.trust.os.close",
            tracked_close,
        )

        assert _read_secure_project_file(
            project,
            Path("public.pem"),
            label="Trust test",
            maximum=1024,
        ) == b"VALID"

    assert opened
    assert sorted(opened) == sorted(closed)


def test_secure_project_reader_closes_descriptors_on_oversize(
    tmp_path,
    monkeypatch,
):
    import os
    import pytest

    from evidence_engine.trust import (
        _read_secure_project_file,
        _supports_secure_trust_traversal,
    )

    if not _supports_secure_trust_traversal():
        pytest.skip("Secure descriptor traversal unavailable")

    project = tmp_path / "project"
    project.mkdir()
    target = project / "public.pem"
    target.write_bytes(b"X" * 1025)

    original_open = os.open
    original_close = os.close
    opened = []
    closed = []

    def tracked_open(*args, **kwargs):
        descriptor = original_open(*args, **kwargs)
        opened.append(descriptor)
        return descriptor

    def tracked_close(descriptor):
        closed.append(descriptor)
        return original_close(descriptor)

    with monkeypatch.context() as patch:
        patch.setattr(
            "evidence_engine.trust._supports_secure_trust_traversal",
            lambda: True,
        )

        patch.setattr(
            "evidence_engine.trust.os.open",
            tracked_open,
        )
        patch.setattr(
            "evidence_engine.trust.os.close",
            tracked_close,
        )

        with pytest.raises(
            ValueError,
            match="exceeds size limit",
        ):
            _read_secure_project_file(
                project,
                Path("public.pem"),
                label="Trust test",
                maximum=1024,
            )

    assert opened
    assert sorted(opened) == sorted(closed)


def test_secure_project_reader_accepts_regular_file(tmp_path):
    import pytest

    from evidence_engine.trust import (
        _read_secure_project_file,
        _supports_secure_trust_traversal,
    )

    if not _supports_secure_trust_traversal():
        pytest.skip("Secure descriptor traversal unavailable")

    project = tmp_path / "project"
    keys = project / "keys"
    keys.mkdir(parents=True)

    content = b"AUTHORIZED-TRUST-MATERIAL"
    (keys / "public.pem").write_bytes(content)

    assert _read_secure_project_file(
        project,
        Path("keys/public.pem"),
        label="Trust test",
        maximum=1024,
    ) == content


def test_secure_project_reader_rejects_oversized_file(tmp_path):
    import pytest

    from evidence_engine.trust import (
        _read_secure_project_file,
        _supports_secure_trust_traversal,
    )

    if not _supports_secure_trust_traversal():
        pytest.skip("Secure descriptor traversal unavailable")

    project = tmp_path / "project"
    project.mkdir()

    (project / "oversized.bin").write_bytes(b"x" * 1025)

    with pytest.raises(ValueError, match="exceeds size limit"):
        _read_secure_project_file(
            project,
            Path("oversized.bin"),
            label="Trust test",
            maximum=1024,
        )


def test_secure_project_reader_rejects_directory(tmp_path):
    import pytest

    from evidence_engine.trust import (
        _read_secure_project_file,
        _supports_secure_trust_traversal,
    )

    if not _supports_secure_trust_traversal():
        pytest.skip("Secure descriptor traversal unavailable")

    project = tmp_path / "project"
    (project / "keys").mkdir(parents=True)

    with pytest.raises(ValueError, match="not a regular file"):
        _read_secure_project_file(
            project,
            Path("keys"),
            label="Trust test",
            maximum=1024,
        )


@pytest.mark.parametrize(
    "relative",
    [
        "../outside.pem",
        "keys/../public.pem",
        "linked/../keys/public.pem",
    ],
)
def test_secure_project_reader_rejects_parent_traversal(
    tmp_path,
    relative,
):
    from pathlib import Path

    from evidence_engine.trust import _read_secure_project_file

    with pytest.raises(
        ValueError,
        match="contains parent traversal",
    ):
        _read_secure_project_file(
            tmp_path,
            Path(relative),
            label="Trust test",
            maximum=1024,
        )


def test_secure_project_reader_rejects_symlinked_file(tmp_path):
    import pytest

    from evidence_engine.trust import (
        _read_secure_project_file,
        _supports_secure_trust_traversal,
    )

    if not _supports_secure_trust_traversal():
        pytest.skip("Secure descriptor traversal unavailable")

    project = tmp_path / "project"
    project.mkdir()

    actual = project / "actual.pem"
    actual.write_bytes(b"ORIGINAL")

    linked = project / "linked.pem"
    linked.symlink_to(actual)

    with pytest.raises(OSError):
        _read_secure_project_file(
            project,
            Path("linked.pem"),
            label="Trust test",
            maximum=1024,
        )


def test_secure_project_reader_rejects_symlinked_parent(tmp_path):
    import pytest

    from evidence_engine.trust import (
        _read_secure_project_file,
        _supports_secure_trust_traversal,
    )

    if not _supports_secure_trust_traversal():
        pytest.skip("Secure descriptor traversal unavailable")

    project = tmp_path / "project"
    actual = project / "actual"
    actual.mkdir(parents=True)

    (actual / "public.pem").write_bytes(b"ORIGINAL")

    linked = project / "linked"
    linked.symlink_to(actual, target_is_directory=True)

    with pytest.raises(OSError):
        _read_secure_project_file(
            project,
            Path("linked/public.pem"),
            label="Trust test",
            maximum=1024,
        )


@pytest.mark.parametrize(
    "configured,expected",
    [
        ("../keys/public.pem", "keys/public.pem"),
        ("subdir/../../keys/public.pem", "keys/public.pem"),
        ("keys/public.pem", "config/keys/public.pem"),
        ("./public.pem", "config/public.pem"),
    ],
)
def test_restricted_key_path_normalization_accepts_contained_paths(
    configured,
    expected,
):
    from evidence_engine.trust import (
        _restricted_project_relative_key_path,
    )

    assert _restricted_project_relative_key_path(
        configured
    ) == Path(expected)


@pytest.mark.parametrize(
    "configured",
    [
        "../../outside.pem",
        "../../../outside.pem",
        "../..",
        "../",
        "/tmp/outside.pem",
    ],
)
def test_restricted_key_path_normalization_rejects_escape(
    configured,
):
    from evidence_engine.trust import (
        _restricted_project_relative_key_path,
    )

    with pytest.raises(ValueError):
        _restricted_project_relative_key_path(configured)


@pytest.mark.parametrize(
    "configured",
    [
        r"..\keys\public.pem",
        r"../keys\public.pem",
        r"C:\keys\public.pem",
        r"C:keys\public.pem",
        r"\\server\share\public.pem",
    ],
)
def test_restricted_key_path_rejects_windows_paths(configured):
    from evidence_engine.trust import (
        _restricted_project_relative_key_path,
    )

    with pytest.raises(ValueError):
        _restricted_project_relative_key_path(configured)


@pytest.mark.skipif(
    not _supports_secure_trust_traversal(),
    reason="Secure POSIX trust traversal unavailable",
)
def test_bounded_loader_rejects_registry_parent_traversal(tmp_path):
    from evidence_engine.trust import load_bounded_trusted_key

    project = tmp_path / "project"
    config = project / "config"
    config.mkdir(parents=True)

    registry = config / "trust_registry.json"
    write_registry(registry, "../keys/public.pem")

    traversing_path = (
        project
        / "config"
        / ".."
        / "config"
        / "trust_registry.json"
    )

    with pytest.raises(ValueError, match="parent traversal"):
        load_bounded_trusted_key(
            traversing_path,
            "test-key",
            "local-claimed",
        )


@pytest.mark.skipif(
    not _supports_secure_trust_traversal(),
    reason="Secure POSIX trust traversal unavailable",
)
def test_bounded_loader_rejects_symlinked_registry_ancestor(tmp_path):
    from evidence_engine.trust import load_bounded_trusted_key

    project = tmp_path / "project"
    config = project / "config"
    config.mkdir(parents=True)

    registry = config / "trust_registry.json"
    write_registry(registry, "../keys/public.pem")

    linked_project = tmp_path / "linked_project"

    try:
        linked_project.symlink_to(
            project,
            target_is_directory=True,
        )
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks unavailable on this platform")

    linked_registry = (
        linked_project / "config" / "trust_registry.json"
    )

    with pytest.raises(OSError):
        load_bounded_trusted_key(
            linked_registry,
            "test-key",
            "local-claimed",
        )


def test_secure_project_reader_closes_descriptors_on_read_failure(
    tmp_path,
    monkeypatch,
):
    """Close trust-file and directory descriptors after read failure."""
    import os
    from pathlib import Path

    import evidence_engine.trust as trust_module

    if not trust_module._supports_secure_trust_traversal():
        pytest.skip("Secure POSIX trust traversal unavailable")

    project = tmp_path / "project"
    project.mkdir()

    target = project / "public.pem"
    target.write_bytes(b"AUTHORIZED-TRUST-MATERIAL")

    original_open = os.open
    original_read = os.read
    original_close = os.close

    opened = []
    closed = []
    file_descriptor = None
    injected = False

    def tracked_open(path, flags, *args, **kwargs):
        nonlocal file_descriptor

        descriptor = original_open(path, flags, *args, **kwargs)
        opened.append(descriptor)

        if os.fspath(path) == "public.pem":
            file_descriptor = descriptor

        return descriptor

    def failing_read(descriptor, size):
        nonlocal injected

        if descriptor == file_descriptor:
            injected = True
            raise OSError("injected trust read failure")

        return original_read(descriptor, size)

    def tracked_close(descriptor):
        closed.append(descriptor)
        return original_close(descriptor)

    with monkeypatch.context() as patch:
        patch.setattr(trust_module.os, "open", tracked_open)
        patch.setattr(trust_module.os, "read", failing_read)
        patch.setattr(trust_module.os, "close", tracked_close)
        patch.setattr(
            trust_module,
            "_supports_secure_trust_traversal",
            lambda: True,
        )

        with pytest.raises(
            OSError,
            match="injected trust read failure",
        ):
            trust_module._read_secure_project_file(
                project,
                Path("public.pem"),
                label="Trust test",
                maximum=1024,
            )

    assert injected, "Trust read failure was not injected"
    assert file_descriptor is not None
    assert opened
    assert sorted(opened) == sorted(closed)

    for descriptor in opened:
        with pytest.raises(OSError):
            os.fstat(descriptor)
