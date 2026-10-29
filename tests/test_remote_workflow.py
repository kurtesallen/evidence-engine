from __future__ import annotations

import json
from io import BytesIO
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from evidence_engine.agents.consumer_factory import create_consumer
from evidence_engine.agents.producer_factory import create_producer
from evidence_engine.aws.config import BACKEND_ENV
from evidence_engine.aws.storage_config import BUCKET_ENV, KMS_KEY_ID_ENV
from evidence_engine.schema import REQUIRED_ARTIFACTS
from evidence_engine.signing import KEY_ID
from evidence_engine.sanitization import TERRAFORM_JSON_CONTENT_RULE_VERSION


class FakeVersionedS3:
    """Small versioned S3 test double for the real storage adapter."""

    def __init__(self):
        self.objects = {}
        self.put_calls = []
        self.get_calls = []
        self.counter = 0

    def put_object(self, **kwargs):
        self.put_calls.append(kwargs)
        self.counter += 1

        version_id = f"version-{self.counter}"
        key = (kwargs["Bucket"], kwargs["Key"])

        self.objects.setdefault(key, []).append(
            {
                "VersionId": version_id,
                "Body": kwargs["Body"],
                "Metadata": dict(kwargs.get("Metadata") or {}),
            }
        )
        return {"VersionId": version_id}

    def get_object(self, **kwargs):
        self.get_calls.append(kwargs)

        key = (kwargs["Bucket"], kwargs["Key"])
        versions = self.objects[key]
        requested_version = kwargs.get("VersionId")

        if requested_version is None:
            obj = versions[-1]
        else:
            obj = next(
                (
                    item
                    for item in versions
                    if item["VersionId"] == requested_version
                ),
                None,
            )
            if obj is None:
                raise ValueError("Unknown S3 object version")

        return {
            "VersionId": obj["VersionId"],
            "Metadata": dict(obj["Metadata"]),
            "Body": BytesIO(obj["Body"]),
        }


def test_producer_to_remote_consumer_and_replay_detection(
    tmp_path: Path,
):
    # Create a real signing key pair and trusted public-key registry.
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    private_key_path = tmp_path / "private.pem"
    private_key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    public_key_path = tmp_path / "public.pem"
    public_key_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    trust_registry = tmp_path / "trust.json"
    trust_registry.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "keys": [
                    {
                        "key_id": KEY_ID,
                        "public_key": "public.pem",
                        "status": "active",
                        "allowed_sources": ["local-claimed"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    # Create the exact required source artifact set.
    artifacts_root = tmp_path / "source-artifacts"
    artifacts_root.mkdir()

    for name in REQUIRED_ARTIFACTS:
        (artifacts_root / name).write_bytes(
            f"test data: {name}\n".encode()
        )

    # Valid synthetic terraform show -json envelopes with explicit sensitivity masks.
    plan_document = {
        "format_version": "1.0",
        "terraform_version": "1.9.0",
        "planned_values": {"root_module": {"resources": []}},
        "resource_changes": [{
            "address": "example.db",
            "change": {
                "actions": ["update"],
                "before": {"opaque": "PLAN-CANARY-SECRET"},
                "before_sensitive": {"opaque": True},
                "after": {"opaque": "PLAN-CANARY-SECRET"},
                "after_sensitive": {"opaque": True},
            },
        }],
    }
    state_document = {
        "format_version": "1.0",
        "terraform_version": "1.9.0",
        "values": {"root_module": {"resources": [{
            "address": "example.db",
            "mode": "managed",
            "type": "example",
            "name": "db",
            "values": {"opaque": "STATE-CANARY-SECRET"},
            "sensitive_values": {"opaque": True},
        }]}},
    }
    (artifacts_root / "plan.json").write_text(
        json.dumps(plan_document), encoding="utf-8"
    )
    (artifacts_root / "state.json").write_text(
        json.dumps(state_document), encoding="utf-8"
    )

    # Exercise the application factories with the real S3 adapter and a
    # versioned fake client. No AWS account or credentials are required.
    s3_client = FakeVersionedS3()

    storage_settings = {
        BUCKET_ENV: "evidence-test-bucket",
        KMS_KEY_ID_ENV: "test-s3-encryption-key",
    }

    provenance = {
        "repository": "example-org/example-repo",
        "commit_sha": "a" * 40,
        "workflow_run_id": "remote-workflow-test",
        "terraform_version": "1.9.0",
        "provider_lock_sha256": "",
        "source": "local-claimed",
    }

    # The producer factory must configure remote storage as required.
    producer = create_producer(
        artifacts_root=artifacts_root,
        output_dir=tmp_path / "producer-bundle",
        provenance=provenance,
        trust_registry_path=trust_registry,
        signing_mode="local",
        private_key=private_key_path,
        bundle_prefix="runs/e2e-test",
        environ=storage_settings,
        s3_client=s3_client,
        artifact_metadata={
            "plan.json": {
                "representation": "sanitized",
                "sanitization_rule_version": TERRAFORM_JSON_CONTENT_RULE_VERSION,
            },
            "state.json": {
                "representation": "sanitized",
                "sanitization_rule_version": TERRAFORM_JSON_CONTENT_RULE_VERSION,
            },
            "commit.txt": {
                "representation": "raw",
                "sanitization_rule_version": None,
            },
            "version.txt": {
                "representation": "raw",
                "sanitization_rule_version": None,
            },
        },
    )

    produced = producer.run()

    assert produced.success is True
    assert produced.data["storage_mode"] == "s3"
    assert produced.data["bundle_reference"]["prefix"] == "runs/e2e-test"

    # The remotely published Terraform JSON must be the sanitized staged bytes.
    uploaded_plan = s3_client.objects[("evidence-test-bucket", "runs/e2e-test/artifacts/plan.json")][-1]["Body"]
    uploaded_state = s3_client.objects[("evidence-test-bucket", "runs/e2e-test/artifacts/state.json")][-1]["Body"]
    assert b"PLAN-CANARY-SECRET" not in uploaded_plan
    assert b"STATE-CANARY-SECRET" not in uploaded_state
    assert b"[REDACTED]" in uploaded_plan
    assert b"[REDACTED]" in uploaded_state

    # Construct the consumer through its application factory.
    # In-memory acceptance state is used only for this isolated test;
    # production deployment must explicitly configure DynamoDB.
    consumer = create_consumer(
        artifacts_root=tmp_path / "consumer-root",
        expected_source="local-claimed",
        expected_key_id=KEY_ID,
        environ={
            **storage_settings,
            BACKEND_ENV: "memory",
        },
        s3_client=s3_client,
        configure_remote_storage=True,
        require_remote_bundle=True,
        trust_registry_path=trust_registry,
    )

    # Remote-only mode must reject a local receipt before processing it.
    local_attempt = consumer.run({"source": "local-claimed"})

    assert local_attempt.success is False
    assert local_attempt.error == "remote-bundle-required"

    # A valid remote bundle should still verify successfully.
    first = consumer.run(produced.data)

    assert first.success is True
    assert first.data == {"verified": True, "key_id": KEY_ID}
    assert len(s3_client.put_calls) == len(REQUIRED_ARTIFACTS) + 2

    # Downloads must use the immutable object versions in the reference,
    # rather than whichever versions currently happen to be latest.
    assert len(s3_client.get_calls) == len(REQUIRED_ARTIFACTS) + 2
    assert all(call.get("VersionId") for call in s3_client.get_calls)

    # The same signed manifest must not be accepted twice.
    second = consumer.run(produced.data)

    assert second.success is False
    assert second.error == "bundle-replay-detected"
    assert first.audit["bundle_digest"] == second.audit["bundle_digest"]