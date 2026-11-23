"""Tests for the production trust deployment preflight."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from evidence_engine import trust_preflight


KEY_ID = "deployment-test-key"
SOURCE = "github-actions-claimed"


@pytest.fixture
def trust_material(tmp_path: Path) -> tuple[Path, Path]:
    """Create an isolated project with a valid trust registry and key."""
    project = tmp_path / "project"
    key_dir = project / "keys"
    key_dir.mkdir(parents=True)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    public_key = key_dir / "public.pem"
    public_key.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    registry = project / "registry.json"
    registry.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "keys": [
                    {
                        "key_id": KEY_ID,
                        "public_key": "keys/public.pem",
                        "status": "active",
                        "allowed_sources": [SOURCE],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    return registry, public_key


def run_preflight(registry: Path, source: str = SOURCE) -> int:
    return trust_preflight.main(
        [
            "--trust-registry",
            str(registry),
            "--expected-key-id",
            KEY_ID,
            "--expected-source",
            source,
        ]
    )


@pytest.mark.skipif(
    os.name != "posix",
    reason="Production trust permission checks require POSIX",
)
def test_valid_trust_material_passes(trust_material, capsys):
    registry, _ = trust_material

    assert run_preflight(registry) == 0

    captured = capsys.readouterr()
    assert "PASS:" in captured.out
    assert captured.err == ""


@pytest.mark.skipif(
    os.name != "posix",
    reason="Production trust permission checks require POSIX",
)
def test_unauthorized_source_fails(trust_material, capsys):
    registry, _ = trust_material

    assert run_preflight(registry, "local-claimed") == 1

    captured = capsys.readouterr()
    assert "FAIL:" in captured.err
    assert "PASS:" not in captured.out


@pytest.mark.skipif(
    os.name != "posix",
    reason="Production trust permission checks require POSIX",
)
def test_missing_public_key_fails(trust_material, capsys):
    registry, public_key = trust_material
    public_key.unlink()

    assert run_preflight(registry) == 1

    captured = capsys.readouterr()
    assert "FAIL:" in captured.err


@pytest.mark.skipif(
    os.name != "posix",
    reason="Production trust permission checks require POSIX",
)
@pytest.mark.parametrize("mode", [0o666, 0o660])
def test_writable_public_key_fails(
    trust_material,
    capsys,
    mode,
):
    registry, public_key = trust_material
    public_key.chmod(mode)

    assert run_preflight(registry) == 1

    captured = capsys.readouterr()
    assert "FAIL:" in captured.err


@pytest.mark.skipif(
    os.name != "posix",
    reason="Production trust permission checks require POSIX",
)
def test_writable_parent_directory_fails(
    trust_material,
    capsys,
):
    registry, public_key = trust_material
    public_key.parent.chmod(0o777)

    assert run_preflight(registry) == 1

    captured = capsys.readouterr()
    assert "FAIL:" in captured.err


@pytest.mark.skipif(
    os.name != "posix",
    reason="Production trust permission checks require POSIX",
)
def test_symlinked_public_key_fails(
    trust_material,
    tmp_path,
    capsys,
):
    registry, public_key = trust_material

    replacement = tmp_path / "replacement.pem"
    replacement.write_bytes(public_key.read_bytes())

    public_key.unlink()
    public_key.symlink_to(replacement)

    assert run_preflight(registry) == 1

    captured = capsys.readouterr()
    assert "FAIL:" in captured.err


@pytest.mark.skipif(
    os.name != "posix",
    reason="Production trust permission checks require POSIX",
)

@pytest.mark.parametrize(
    ("source", "expected_returncode"),
    [
        (SOURCE, 0),
        ("local-claimed", 1),
    ],
)
def test_preflight_module_process_exit_code(
    trust_material,
    source,
    expected_returncode,
):
    """The module entry point must preserve success and failure exit codes."""
    registry, _ = trust_material

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "evidence_engine.trust_preflight",
            "--trust-registry",
            str(registry),
            "--expected-key-id",
            KEY_ID,
            "--expected-source",
            source,
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == expected_returncode

    if expected_returncode == 0:
        assert "PASS:" in completed.stdout
        assert completed.stderr == ""
    else:
        assert "FAIL:" in completed.stderr
        assert "PASS:" not in completed.stdout
