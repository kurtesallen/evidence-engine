
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from evidence_engine.manifest import write_manifest
from evidence_engine.signing import KEY_ID, sign_bytes
from evidence_engine.verify import verify_bundle


TERRAFORM_VERSION = "1.9.0"
SANITIZATION_RULE_VERSION = "1.1"


def _artifact_metadata(
    *,
    plan_representation: str = "sanitized",
    state_representation: str = "sanitized",
    sanitization_rule_version: str = SANITIZATION_RULE_VERSION,
) -> dict[str, dict[str, str | None]]:
    return {
        "plan.json": {
            "representation": plan_representation,
            "sanitization_rule_version": (
                sanitization_rule_version
                if plan_representation == "sanitized"
                else None
            ),
        },
        "state.json": {
            "representation": state_representation,
            "sanitization_rule_version": (
                sanitization_rule_version
                if state_representation == "sanitized"
                else None
            ),
        },
        "commit.txt": {
            "representation": "raw",
            "sanitization_rule_version": None,
        },
        "version.txt": {
            "representation": "raw",
            "sanitization_rule_version": None,
        },
    }


@pytest.fixture
def signed_terraform_bundle(tmp_path: Path):
    def create_bundle(
        *,
        plan_version: str = TERRAFORM_VERSION,
        state_version: str = TERRAFORM_VERSION,
        provenance_version: str = TERRAFORM_VERSION,
        plan_representation: str = "sanitized",
        state_representation: str = "sanitized",
        include_metadata: bool = True,
        schema_version: str = "1.1",
        sanitization_rule_version: str = SANITIZATION_RULE_VERSION,
    ) -> dict[str, Path | str]:
        root = tmp_path / "bundle"
        artifacts = root / "artifacts"
        output = root / "output"
        keys = root / "keys"
        config = root / "config"

        for directory in (artifacts, output, keys, config):
            directory.mkdir(parents=True, exist_ok=True)

        plan = {
            "format_version": "1.0",
            "terraform_version": plan_version,
            "planned_values": {
                "root_module": {
                    "resources": [],
                },
            },
            "resource_changes": [],
        }

        state = {
            "version": 4,
            "terraform_version": state_version,
            "values": {
                "root_module": {
                    "resources": [],
                },
            },
        }

        (artifacts / "plan.json").write_text(
            json.dumps(plan),
            encoding="utf-8",
        )
        (artifacts / "state.json").write_text(
            json.dumps(state),
            encoding="utf-8",
        )
        (artifacts / "commit.txt").write_text(
            "test-commit\n",
            encoding="utf-8",
        )
        (artifacts / "version.txt").write_text(
            f"Terraform {provenance_version}\n",
            encoding="utf-8",
        )

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        private_key_path = keys / "private.pem"
        private_key_path.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

        public_key_path = keys / "public.pem"
        public_key_path.write_bytes(
            private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

        trust_registry = config / "trust_registry.json"
        trust_registry.write_text(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "keys": [
                        {
                            "key_id": KEY_ID,
                            "public_key": "../keys/public.pem",
                            "status": "active",
                            "allowed_sources": [
                                "local-claimed",
                                "github-actions-claimed",
                            ],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        is_modern_schema = schema_version in {"1.2", "1.3"}

        provenance = {
            "repository": "test/repository",
            "commit_sha": "a" * 40,
            "workflow_run_id": (
                "123456789"
                if is_modern_schema
                else "local-test"
            ),
            "terraform_version": provenance_version,
            "provider_lock_sha256": "",
            "source": (
                "github-actions-claimed"
                if is_modern_schema
                else "local-claimed"
            ),
        }

        if is_modern_schema:
            provenance.update(
                {
                    "ref": "refs/heads/main",
                    "workflow_ref": (
                        "test/repository/"
                        ".github/workflows/evidence.yml@refs/heads/main"
                    ),
                    "run_number": "1",
                    "run_attempt": "1",
                }
            )

        if schema_version == "1.3":
            provenance["stream_id"] = "test-stream"

        metadata = (
            _artifact_metadata(
                plan_representation=plan_representation,
                state_representation=state_representation,
                sanitization_rule_version=sanitization_rule_version,
            )
            if include_metadata
            else None
        )

        manifest_path = output / "manifest.json"
        signature_path = output / "manifest.sig"

        write_manifest(
            artifact_dir=artifacts,
            destination=manifest_path,
            provenance=provenance,
            key_id=KEY_ID,
            schema_version=schema_version,
            artifact_metadata=metadata,
        )

        signature_path.write_bytes(
            sign_bytes(
                private_key_path,
                manifest_path.read_bytes(),
            )
        )

        return {
            "artifacts": artifacts,
            "manifest": manifest_path,
            "signature": signature_path,
            "trust_registry": trust_registry,
            "key_id": KEY_ID,
        }

    return create_bundle


def verify(bundle: dict[str, Path | str]) -> bool:
    return verify_bundle(
        bundle["artifacts"],
        bundle["manifest"],
        bundle["signature"],
        bundle["trust_registry"],
        bundle["key_id"],
    )


def test_matching_terraform_versions_are_accepted(
    signed_terraform_bundle,
):
    bundle = signed_terraform_bundle()

    assert verify(bundle) is True


def test_plan_and_state_version_mismatch_is_rejected(
    signed_terraform_bundle,
):
    bundle = signed_terraform_bundle(
        plan_version="1.9.0",
        state_version="1.8.5",
        provenance_version="1.9.0",
    )

    assert verify(bundle) is False


def test_provenance_version_mismatch_is_rejected(
    signed_terraform_bundle,
):
    bundle = signed_terraform_bundle(
        plan_version="1.9.0",
        state_version="1.9.0",
        provenance_version="1.8.5",
    )

    assert verify(bundle) is False


def test_only_one_sanitized_terraform_artifact_is_rejected(
    signed_terraform_bundle,
):
    bundle = signed_terraform_bundle(
        plan_representation="sanitized",
        state_representation="raw",
    )

    assert verify(bundle) is False


def test_legacy_non_sanitized_bundle_remains_compatible(
    signed_terraform_bundle,
):
    bundle = signed_terraform_bundle(
        plan_version="legacy",
        state_version="legacy",
        provenance_version="legacy",
        include_metadata=False,
    )

    assert verify(bundle) is True


def test_modern_v13_bundle_with_sanitized_artifacts_is_accepted(
    signed_terraform_bundle,
):
    bundle = signed_terraform_bundle(
        schema_version="1.3",
        plan_representation="sanitized",
        state_representation="sanitized",
    )

    assert verify(bundle) is True


def test_modern_v13_bundle_with_raw_terraform_artifacts_is_rejected(
    signed_terraform_bundle,
):
    bundle = signed_terraform_bundle(
        schema_version="1.3",
        plan_representation="raw",
        state_representation="raw",
    )

    assert verify(bundle) is False


def test_modern_v13_bundle_with_unsupported_sanitization_version_is_rejected(
    signed_terraform_bundle,
):
    bundle = signed_terraform_bundle(
        schema_version="1.3",
        sanitization_rule_version="0.9",
    )

    assert verify(bundle) is False


def test_modern_v12_bundle_requires_sanitized_terraform_artifacts(
    signed_terraform_bundle,
):
    bundle = signed_terraform_bundle(
        schema_version="1.2",
        plan_representation="raw",
        state_representation="sanitized",
    )

    assert verify(bundle) is False
