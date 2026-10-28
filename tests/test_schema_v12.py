
import copy

import pytest

from evidence_engine.schema import validate_manifest


def valid_manifest_v11():
    return {
        "schema_version": "1.1",
        "hash_algorithm": "SHA-256",
        "signature_algorithm": "RSA-PSS-SHA256",
        "key_id": "test-key",
        "provenance": {
            "repository": "example-org/evidence-engine",
            "commit_sha": "a" * 40,
            "workflow_run_id": "123456789",
            "terraform_version": "1.9.0",
            "provider_lock_sha256": "",
            "source": "local-claimed",
        },
        "artifacts": [
            {
                "name": name,
                "size_bytes": 0,
                "representation": "sample",
                "sanitization_rule_version": None,
                "sha256": "b" * 64,
            }
            for name in (
                "plan.json",
                "state.json",
                "commit.txt",
                "version.txt",
            )
        ],
    }


def valid_manifest_v12():
    manifest = valid_manifest_v11()
    manifest["schema_version"] = "1.2"
    manifest["provenance"].update(
        {
            "source": "github-actions-claimed",
            "ref": "refs/heads/main",
            "workflow_ref": (
                "example-org/evidence-engine/"
                ".github/workflows/ci.yml@refs/heads/main"
            ),
            "run_number": "42",
            "run_attempt": "1",
        }
    )
    return manifest


def test_v11_manifest_remains_valid():
    validate_manifest(valid_manifest_v11())


def test_v12_ordered_ci_manifest_is_valid():
    validate_manifest(valid_manifest_v12())


@pytest.mark.parametrize("field", ["ref", "workflow_ref", "run_number", "run_attempt"])
def test_v12_rejects_missing_ordering_fields(field):
    manifest = valid_manifest_v12()
    del manifest["provenance"][field]

    with pytest.raises(ValueError, match="Provenance"):
        validate_manifest(manifest)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("run_number", ""),
        ("run_number", "0"),
        ("run_number", "-1"),
        ("run_number", "01"),
        ("run_number", "1.5"),
        ("run_number", "abc"),
        ("run_attempt", ""),
        ("run_attempt", "0"),
        ("run_attempt", "-1"),
        ("run_attempt", "01"),
        ("run_attempt", "1.5"),
        ("run_attempt", "abc"),
    ],
)
def test_v12_rejects_invalid_ordering_numbers(field, value):
    manifest = valid_manifest_v12()
    manifest["provenance"][field] = value

    with pytest.raises(ValueError, match="provenance field"):
        validate_manifest(manifest)


def test_v12_rejects_local_claimed_source():
    manifest = valid_manifest_v12()
    manifest["provenance"]["source"] = "local-claimed"

    with pytest.raises(ValueError, match="GitHub Actions provenance"):
        validate_manifest(manifest)


def test_v12_rejects_invalid_ref():
    manifest = valid_manifest_v12()
    manifest["provenance"]["ref"] = "main"

    with pytest.raises(ValueError, match="provenance ref"):
        validate_manifest(manifest)


def test_v12_rejects_unknown_provenance_fields():
    manifest = valid_manifest_v12()
    manifest["provenance"]["unexpected"] = "value"

    with pytest.raises(ValueError, match="Provenance"):
        validate_manifest(manifest)


def test_v11_does_not_accept_v12_fields():
    manifest = valid_manifest_v11()
    manifest["provenance"]["run_number"] = "42"

    with pytest.raises(ValueError, match="Provenance"):
        validate_manifest(manifest)

def valid_manifest_v13():
    manifest = valid_manifest_v12()
    manifest["schema_version"] = "1.3"
    manifest["provenance"]["stream_id"] = "terraform-production"
    return manifest


def test_v13_manifest_with_stream_identity_is_valid():
    validate_manifest(valid_manifest_v13())


def test_v12_manifest_remains_valid_without_stream_identity():
    validate_manifest(valid_manifest_v12())


def test_v13_rejects_missing_stream_identity():
    manifest = valid_manifest_v13()
    del manifest["provenance"]["stream_id"]

    with pytest.raises(ValueError, match="Provenance"):
        validate_manifest(manifest)


@pytest.mark.parametrize(
    "stream_id",
    [
        "",
        " ",
        "../production",
        "production workspace",
        "x" * 129,
    ],
)
def test_v13_rejects_invalid_stream_identity(stream_id):
    manifest = valid_manifest_v13()
    manifest["provenance"]["stream_id"] = stream_id

    with pytest.raises(ValueError, match="stream_id"):
        validate_manifest(manifest)
