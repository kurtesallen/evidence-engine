import json

import pytest

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