"""Security regression tests for registry-driven trust deployment."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import evidence_engine.trust_deployment as deployment


pytestmark = pytest.mark.skipif(
    os.name != "posix",
    reason="Secure trust deployment requires POSIX traversal",
)

SOURCE = "github-actions-claimed"
KEY_A = "deployment-key-a"
KEY_B = "deployment-key-b"


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _write_private(path: Path, content: bytes) -> None:
    path.write_bytes(content)
    path.chmod(0o600)


def _public_key_bytes(key_size: int = 2048) -> bytes:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


class DeploymentEnvironment:
    """Isolated deployment source and destination."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.project = root / "project"
        self.trust = self.project / "trust"
        self.keys = self.trust / "keys"

        for directory in (
            self.project,
            self.trust,
            self.keys,
        ):
            directory.mkdir(mode=0o700)
            directory.chmod(0o700)

        self.registry = self.trust / "registry.json"
        self.destination = root / "staged"

        self.key_a = self.keys / "key-a.pem"
        self.key_b = self.keys / "key-b.pem"

        _write_private(self.key_a, _public_key_bytes())
        _write_private(self.key_b, _public_key_bytes())

        self.write_registry([self.entry_a()])

    def entry_a(self) -> dict:
        return {
            "key_id": KEY_A,
            "public_key": "keys/key-a.pem",
            "status": "active",
            "allowed_sources": [SOURCE],
        }

    def entry_b(self) -> dict:
        return {
            "key_id": KEY_B,
            "public_key": "keys/key-b.pem",
            "status": "active",
            "allowed_sources": [SOURCE],
        }

    def write_registry(self, entries: list[dict]) -> None:
        registry = {
            "schema_version": "1.0",
            "keys": entries,
        }

        _write_private(
            self.registry,
            json.dumps(registry).encode("utf-8"),
        )

    def stage(self) -> Path:
        return deployment.stage_trust_deployment(
            self.registry,
            self.destination,
        )


@pytest.fixture
def environment(tmp_path):
    if not deployment._supports_secure_trust_traversal():
        pytest.skip("Secure POSIX traversal unavailable")

    tmp_path.chmod(0o700)

    return DeploymentEnvironment(tmp_path)


def test_stage_single_referenced_key(environment):
    env = environment

    staged_registry = env.stage()

    assert staged_registry == (
        env.destination / "registry.json"
    )

    assert staged_registry.read_bytes() == (
        env.registry.read_bytes()
    )

    staged_key = env.destination / "keys" / "key-a.pem"

    assert staged_key.read_bytes() == (
        env.key_a.read_bytes()
    )

    assert not (
        env.destination / "keys" / "key-b.pem"
    ).exists()


def test_stage_multiple_rotation_keys(environment):
    env = environment

    entry_a = env.entry_a()
    entry_a["status"] = "retired"

    env.write_registry([
        entry_a,
        env.entry_b(),
    ])

    staged_registry = env.stage()

    assert staged_registry.read_bytes() == (
        env.registry.read_bytes()
    )

    for source_key in (env.key_a, env.key_b):
        staged_key = (
            env.destination / "keys" / source_key.name
        )

        assert staged_key.read_bytes() == (
            source_key.read_bytes()
        )


def test_stage_shared_public_key_reference(environment):
    env = environment

    entry_b = env.entry_b()
    entry_b["public_key"] = "keys/key-a.pem"

    env.write_registry([
        env.entry_a(),
        entry_b,
    ])

    env.stage()

    staged_keys = sorted(
        path.name
        for path in (env.destination / "keys").iterdir()
    )

    assert staged_keys == ["key-a.pem"]


def test_stage_nested_key_directory(environment):
    env = environment

    nested = env.keys / "rotation"
    nested.mkdir(mode=0o700)
    nested.chmod(0o700)

    nested_key = nested / "key-b.pem"

    _write_private(
        nested_key,
        env.key_b.read_bytes(),
    )

    entry_b = env.entry_b()
    entry_b["public_key"] = (
        "keys/rotation/key-b.pem"
    )

    env.write_registry([
        env.entry_a(),
        entry_b,
    ])

    env.stage()

    staged_nested_key = (
        env.destination
        / "keys"
        / "rotation"
        / "key-b.pem"
    )

    assert staged_nested_key.read_bytes() == (
        nested_key.read_bytes()
    )

    assert _mode(staged_nested_key.parent) == 0o700
    assert _mode(staged_nested_key) == 0o600


def test_stage_exact_private_permissions(environment):
    env = environment

    env.write_registry([
        env.entry_a(),
        env.entry_b(),
    ])

    env.stage()

    assert _mode(env.destination) == 0o700

    for path in env.destination.rglob("*"):
        assert not path.is_symlink()

        if path.is_dir():
            assert _mode(path) == 0o700
        else:
            assert path.is_file()
            assert _mode(path) == 0o600


@pytest.mark.parametrize(
    "target",
    ["project", "trust", "keys", "registry", "key_a"],
)
def test_stage_rejects_unsafe_source_permissions(
    environment,
    target,
):
    env = environment
    path = getattr(env, target)

    path.chmod(
        0o777 if path.is_dir() else 0o666
    )

    try:
        with pytest.raises((OSError, ValueError)):
            env.stage()

        assert not env.destination.exists()
    finally:
        path.chmod(
            0o700 if path.is_dir() else 0o600
        )


@pytest.mark.parametrize(
    "target",
    ["registry", "key_a", "keys"],
)
def test_stage_rejects_source_symlink(
    environment,
    target,
):
    env = environment
    path = getattr(env, target)

    is_directory = path.is_dir()

    original = path.with_name(
        path.name + ".original"
    )

    path.rename(original)

    path.symlink_to(
        original,
        target_is_directory=is_directory,
    )

    with pytest.raises((OSError, ValueError)):
        env.stage()

    assert not env.destination.exists()


@pytest.mark.parametrize(
    "configured",
    [
        "../outside.pem",
        "keys/../outside.pem",
        "/tmp/outside.pem",
        "keys//key-a.pem",
        "keys/./key-a.pem",
        r"keys\key-a.pem",
        r"C:\outside.pem",
        "outside.pem",
    ],
)
def test_stage_rejects_unsafe_key_path(
    environment,
    configured,
):
    env = environment

    entry = env.entry_a()
    entry["public_key"] = configured

    env.write_registry([entry])

    with pytest.raises((OSError, ValueError)):
        env.stage()

    assert not env.destination.exists()


def test_stage_rejects_empty_registry(environment):
    env = environment

    env.write_registry([])

    with pytest.raises(ValueError):
        env.stage()

    assert not env.destination.exists()


def test_stage_rejects_duplicate_registry_fields(
    environment,
):
    env = environment

    _write_private(
        env.registry,
        b'{"schema_version":"1.0",'
        b'"schema_version":"1.0","keys":[]}',
    )

    with pytest.raises(ValueError):
        env.stage()

    assert not env.destination.exists()


def test_stage_rejects_invalid_public_key(environment):
    env = environment

    _write_private(
        env.key_a,
        b"invalid-public-key",
    )

    with pytest.raises(ValueError):
        env.stage()

    assert not env.destination.exists()


def test_stage_rejects_wrong_rsa_key_size(environment):
    env = environment

    _write_private(
        env.key_a,
        _public_key_bytes(key_size=3072),
    )

    with pytest.raises(ValueError):
        env.stage()

    assert not env.destination.exists()


def test_stage_rejects_missing_referenced_key(environment):
    env = environment

    env.key_a.unlink()

    with pytest.raises((OSError, ValueError)):
        env.stage()

    assert not env.destination.exists()


def test_stage_validates_all_keys_before_publication(
    environment,
):
    env = environment

    env.write_registry([
        env.entry_a(),
        env.entry_b(),
    ])

    _write_private(
        env.key_b,
        b"invalid-second-public-key",
    )

    with pytest.raises(ValueError):
        env.stage()

    assert not env.destination.exists()


def test_stage_rejects_existing_destination(environment):
    env = environment

    env.destination.mkdir(mode=0o700)

    sentinel = env.destination / "sentinel.txt"
    _write_private(sentinel, b"preserve-existing-data")

    with pytest.raises(ValueError):
        env.stage()

    assert sentinel.read_bytes() == (
        b"preserve-existing-data"
    )

    assert sorted(
        path.name for path in env.destination.iterdir()
    ) == ["sentinel.txt"]


def test_stage_rejects_dangling_destination_symlink(
    environment,
):
    env = environment

    missing = env.root / "missing-target"

    env.destination.symlink_to(
        missing,
        target_is_directory=True,
    )

    with pytest.raises((OSError, ValueError)):
        env.stage()

    assert env.destination.is_symlink()
    assert not missing.exists()


def test_stage_rejects_unsafe_destination_parent(
    environment,
):
    env = environment

    unsafe = env.root / "unsafe-parent"
    unsafe.mkdir(mode=0o700)
    unsafe.chmod(0o777)

    destination = unsafe / "staged"

    try:
        with pytest.raises((OSError, ValueError)):
            deployment.stage_trust_deployment(
                env.registry,
                destination,
            )

        assert not destination.exists()
    finally:
        unsafe.chmod(0o700)


@pytest.mark.parametrize(
    "relationship",
    ["same", "descendant", "ancestor"],
)
def test_stage_rejects_overlapping_destination(
    environment,
    relationship,
):
    env = environment

    destinations = {
        "same": env.trust,
        "descendant": env.trust / "staged",
        "ancestor": env.project,
    }

    original = env.registry.read_bytes()

    with pytest.raises(ValueError, match="overlap"):
        deployment.stage_trust_deployment(
            env.registry,
            destinations[relationship],
        )

    assert env.registry.read_bytes() == original


def test_stage_fails_closed_without_secure_traversal(
    environment,
    monkeypatch,
):
    env = environment

    monkeypatch.setattr(
        deployment,
        "_supports_secure_trust_traversal",
        lambda: False,
    )

    with pytest.raises(ValueError):
        env.stage()

    assert not env.destination.exists()


@pytest.mark.parametrize(
    "target",
    ["registry", "key_a"],
)
def test_stage_rejects_fifo_without_blocking(
    environment,
    target,
):
    env = environment

    path = getattr(env, target)
    path.unlink()

    os.mkfifo(path, 0o600)

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "evidence_engine.trust_deployment",
            "--source-registry",
            str(env.registry),
            "--destination",
            str(env.destination),
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert result.returncode == 1
    assert "FAIL:" in result.stderr
    assert "PASS:" not in result.stdout
    assert not env.destination.exists()


def test_stage_key_write_failure_does_not_publish_registry(
    environment,
    monkeypatch,
):
    env = environment

    def fail_write(parent_fd, name, content):
        raise OSError("Injected key write failure")

    monkeypatch.setattr(
        deployment,
        "_write_private_file",
        fail_write,
    )

    with pytest.raises(
        OSError,
        match="Injected key write failure",
    ):
        env.stage()

    assert not (
        env.destination / "registry.json"
    ).exists()


def test_failed_destination_cannot_be_reused(
    environment,
    monkeypatch,
):
    env = environment

    with monkeypatch.context() as patch:

        def fail_write(parent_fd, name, content):
            raise OSError("Injected publication failure")

        patch.setattr(
            deployment,
            "_write_private_file",
            fail_write,
        )

        with pytest.raises(OSError):
            env.stage()

    # Current contract retains a failed destination.
    # It must never be reused or exported.
    assert env.destination.is_dir()

    with pytest.raises(
        ValueError,
        match="already exists",
    ):
        env.stage()


def test_cli_success_reports_staged_registry(
    environment,
    capsys,
):
    env = environment

    result = deployment.main([
        "--source-registry",
        str(env.registry),
        "--destination",
        str(env.destination),
    ])

    captured = capsys.readouterr()

    assert result == 0
    assert "PASS:" in captured.out
    assert str(
        env.destination / "registry.json"
    ) in captured.out
    assert captured.err == ""


def test_cli_failure_does_not_report_success(
    environment,
    capsys,
):
    env = environment

    _write_private(
        env.key_a,
        b"invalid-public-key",
    )

    result = deployment.main([
        "--source-registry",
        str(env.registry),
        "--destination",
        str(env.destination),
    ])

    captured = capsys.readouterr()

    assert result == 1
    assert "FAIL:" in captured.err
    assert "PASS:" not in captured.out
    assert "Staged registry:" not in captured.out
    assert not env.destination.exists()


def test_cli_sync_failure_does_not_report_success(
    environment,
    monkeypatch,
    capsys,
):
    env = environment

    def fail_sync(descriptor):
        raise OSError("Injected synchronization failure")

    monkeypatch.setattr(
        deployment.os,
        "fsync",
        fail_sync,
    )

    result = deployment.main([
        "--source-registry",
        str(env.registry),
        "--destination",
        str(env.destination),
    ])

    captured = capsys.readouterr()

    assert result == 1
    assert "Injected synchronization failure" in captured.err
    assert "PASS:" not in captured.out
    assert "Staged registry:" not in captured.out
    assert not (
        env.destination / "registry.json"
    ).exists()



@pytest.mark.parametrize(
    "failure_target",
    ["destination", "parent"],
)
def test_cli_late_sync_failure_does_not_report_success(
    environment,
    monkeypatch,
    capsys,
    failure_target,
):
    """A complete-looking destination is not proof of success."""

    env = environment

    original_fsync = deployment.os.fsync

    staged_registry = (
        env.destination / "registry.json"
    )

    failed_directory = (
        env.destination
        if failure_target == "destination"
        else env.destination.parent
    )

    injected_failures = []

    def fail_late_sync(descriptor):
        if staged_registry.is_file():
            descriptor_stat = os.fstat(descriptor)
            target_stat = failed_directory.stat()

            if (
                stat.S_ISDIR(descriptor_stat.st_mode)
                and descriptor_stat.st_dev
                == target_stat.st_dev
                and descriptor_stat.st_ino
                == target_stat.st_ino
            ):
                injected_failures.append(
                    failure_target
                )

                raise OSError(
                    "Injected late synchronization failure"
                )

        return original_fsync(descriptor)

    with monkeypatch.context() as patch:
        patch.setattr(
            deployment.os,
            "fsync",
            fail_late_sync,
        )

        result = deployment.main([
            "--source-registry",
            str(env.registry),
            "--destination",
            str(env.destination),
        ])

    captured = capsys.readouterr()

    assert injected_failures == [failure_target]

    assert result == 1

    assert (
        "Injected late synchronization failure"
        in captured.err
    )

    assert "PASS:" not in captured.out
    assert "Staged registry:" not in captured.out

    # The current publication contract may retain
    # complete-looking material after a late failure.
    assert staged_registry.is_file()

    assert staged_registry.read_bytes() == (
        env.registry.read_bytes()
    )

    assert (
        env.destination / "keys" / "key-a.pem"
    ).read_bytes() == env.key_a.read_bytes()

    # Failed destinations must never be reused.
    with pytest.raises(
        ValueError,
        match="already exists",
    ):
        env.stage()
