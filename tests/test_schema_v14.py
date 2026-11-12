"""Structural tests for experimental restricted-evidence manifest v1.4."""

from copy import deepcopy

import pytest

from evidence_engine.policy import PolicyEngine
from evidence_engine.restricted_contract import PROFILE_20, PROFILE_21
from evidence_engine.schema import validate_manifest
from test_schema_v12 import valid_manifest_v13


PROFILE_RULES = {
    PROFILE_20: "2.0",
    PROFILE_21: "2.1",
}


def valid_manifest_v14(profile=PROFILE_21):
    manifest = deepcopy(valid_manifest_v13())
    manifest["schema_version"] = "1.4"
    manifest["evidence_profile"] = profile

    for artifact in manifest["artifacts"]:
        if artifact["name"] in {"plan.json", "state.json"}:
            artifact["representation"] = "sanitized"
            artifact["sanitization_rule_version"] = PROFILE_RULES[profile]

    return manifest


@pytest.mark.parametrize("profile", [PROFILE_20, PROFILE_21])
def test_v14_accepts_supported_profiles_structurally(profile):
    validate_manifest(valid_manifest_v14(profile))


@pytest.mark.parametrize(
    "profile",
    ["", "terraform-restricted-9.9", None, 21],
)
def test_v14_rejects_unsupported_profiles(profile):
    manifest = valid_manifest_v14()
    manifest["evidence_profile"] = profile

    with pytest.raises(ValueError):
        validate_manifest(manifest)


def test_v14_requires_profile():
    manifest = valid_manifest_v14()
    del manifest["evidence_profile"]

    with pytest.raises(ValueError):
        validate_manifest(manifest)


def test_v14_rejects_unknown_top_level_fields():
    manifest = valid_manifest_v14()
    manifest["unexpected"] = "value"

    with pytest.raises(ValueError):
        validate_manifest(manifest)


@pytest.mark.parametrize("version", ["1.1", "1.2", "1.3"])
def test_legacy_schemas_reject_profile_field(version):
    manifest = valid_manifest_v14()
    manifest["schema_version"] = version

    with pytest.raises(ValueError):
        validate_manifest(manifest)


@pytest.mark.parametrize("name", ["plan.json", "state.json"])
@pytest.mark.parametrize("representation", ["raw", "sample"])
def test_v14_requires_sanitized_terraform_artifacts(name, representation):
    manifest = valid_manifest_v14()

    for artifact in manifest["artifacts"]:
        if artifact["name"] == name:
            artifact["representation"] = representation
            artifact["sanitization_rule_version"] = None

    with pytest.raises(ValueError):
        validate_manifest(manifest)


@pytest.mark.parametrize("name", ["plan.json", "state.json"])
@pytest.mark.parametrize("version", [None, "1.1", "2.0", "99.0"])
def test_v14_rejects_mismatched_rule_version(name, version):
    manifest = valid_manifest_v14()

    for artifact in manifest["artifacts"]:
        if artifact["name"] == name:
            artifact["sanitization_rule_version"] = version

    with pytest.raises(ValueError):
        validate_manifest(manifest)


@pytest.mark.parametrize("name", ["commit.txt", "version.txt"])
def test_v14_rejects_sanitized_metadata_artifacts(name):
    manifest = valid_manifest_v14()

    for artifact in manifest["artifacts"]:
        if artifact["name"] == name:
            artifact["representation"] = "sanitized"
            artifact["sanitization_rule_version"] = "2.1"

    with pytest.raises(ValueError):
        validate_manifest(manifest)


def test_v14_requires_ordered_ci_provenance():
    manifest = valid_manifest_v14()
    del manifest["provenance"]["stream_id"]

    with pytest.raises(ValueError):
        validate_manifest(manifest)


def test_v14_rejects_local_claimed_provenance():
    manifest = valid_manifest_v14()
    manifest["provenance"]["source"] = "local-claimed"

    with pytest.raises(ValueError):
        validate_manifest(manifest)


@pytest.mark.parametrize("profile", [PROFILE_20, PROFILE_21])
def test_production_policy_still_rejects_v14(profile):
    manifest = valid_manifest_v14(profile)

    decision = PolicyEngine().evaluate_integrity(manifest)

    assert decision.allowed is False
    assert decision.reason == "integrity-schema-version-unsupported"
