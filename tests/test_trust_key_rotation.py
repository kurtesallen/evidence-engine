"""Real cryptographic regression tests for signing-key rotation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from evidence_engine.acceptance import InMemoryAcceptanceState
from evidence_engine.agents.artifact_staging import (
    stage_sanitized_artifacts,
)
from evidence_engine.agents.consumer import ConsumerAgent
from evidence_engine.manifest import write_manifest
from evidence_engine.sanitization import (
    TERRAFORM_JSON_CONTENT_RULE_VERSION,
)
from evidence_engine.signing import sign_bytes
from evidence_engine.trust_preflight import (
    validate_trust_deployment,
)
from evidence_engine.verify import verify_bundle


KEY_A = "rotation-key-a"
KEY_B = "rotation-key-b"

SOURCE = "github-actions-claimed"
CONSUMER_ID = "rotation-test-consumer"
STREAM_ID = "rotation-test-stream"
TERRAFORM_VERSION = "1.9.0"

ARTIFACT_METADATA = {
    "plan.json": {
        "representation": "sanitized",
        "sanitization_rule_version": (
            TERRAFORM_JSON_CONTENT_RULE_VERSION
        ),
    },
    "state.json": {
        "representation": "sanitized",
        "sanitization_rule_version": (
            TERRAFORM_JSON_CONTENT_RULE_VERSION
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


class RotationEnvironment:
    """Isolated signing identities and shared acceptance state."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(mode=0o700)

        self.trust_root = root / "trust"
        self.trust_root.mkdir(mode=0o700)

        self.public_keys = self.trust_root / "keys"
        self.public_keys.mkdir(mode=0o700)

        self.private_keys = root / "private"
        self.private_keys.mkdir(mode=0o700)

        self.registry = self.trust_root / "registry.json"

        self.acceptance = InMemoryAcceptanceState()
        self.bundle_counter = 0

        for key_id in (KEY_A, KEY_B):
            self.generate_key(key_id)

        self.write_registry()

    def generate_key(self, key_id: str) -> None:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        private_path = self.private_keys / f"{key_id}.pem"
        public_path = self.public_keys / f"{key_id}.pem"

        private_path.touch(mode=0o600, exist_ok=False)
        private_path.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=(
                    serialization.NoEncryption()
                ),
            )
        )

        public_path.touch(mode=0o600, exist_ok=False)
        public_path.write_bytes(
            private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=(
                    serialization.PublicFormat.SubjectPublicKeyInfo
                ),
            )
        )

    def write_registry(
        self,
        *,
        status_a: str = "active",
        status_b: str = "active",
        source_a: str = SOURCE,
        source_b: str = SOURCE,
        public_key_b: str | None = None,
    ) -> None:
        """Publish a complete registry within the isolated test root."""

        registry = {
            "schema_version": "1.0",
            "keys": [
                {
                    "key_id": KEY_A,
                    "public_key": f"keys/{KEY_A}.pem",
                    "status": status_a,
                    "allowed_sources": [source_a],
                },
                {
                    "key_id": KEY_B,
                    "public_key": (
                        public_key_b or f"keys/{KEY_B}.pem"
                    ),
                    "status": status_b,
                    "allowed_sources": [source_b],
                },
            ],
        }

        temporary = self.trust_root / "registry.tmp"
        temporary.touch(mode=0o600, exist_ok=False)

        try:
            temporary.write_text(
                json.dumps(registry),
                encoding="utf-8",
            )
            temporary.replace(self.registry)
        finally:
            temporary.unlink(missing_ok=True)

    def make_bundle(
        self,
        key_id: str,
        run_number: int,
        run_attempt: int = 1,
    ) -> dict[str, Any]:
        """Create real sanitized artifacts and a signed v1.3 manifest."""

        self.bundle_counter += 1

        bundle_root = (
            self.root / f"bundle-{self.bundle_counter}"
        )
        bundle_root.mkdir(mode=0o700)

        source_root = bundle_root / "source"
        source_root.mkdir(mode=0o700)

        artifacts_root = bundle_root / "artifacts"

        plan = {
            "format_version": "1.0",
            "terraform_version": TERRAFORM_VERSION,
            "planned_values": {
                "root_module": {"resources": []},
            },
            "resource_changes": [],
        }

        state = {
            "format_version": "1.0",
            "terraform_version": TERRAFORM_VERSION,
            "values": {
                "root_module": {"resources": []},
            },
        }

        (source_root / "plan.json").write_text(
            json.dumps(plan),
            encoding="utf-8",
        )

        (source_root / "state.json").write_text(
            json.dumps(state),
            encoding="utf-8",
        )

        (source_root / "commit.txt").write_text(
            "a" * 40 + "\n",
            encoding="utf-8",
        )

        (source_root / "version.txt").write_text(
            f"Terraform {TERRAFORM_VERSION}\n",
            encoding="utf-8",
        )

        stage_sanitized_artifacts(
            source_root=source_root,
            destination_root=artifacts_root,
            artifact_metadata=ARTIFACT_METADATA,
        )

        provenance = {
            "repository": "example/repo",
            "commit_sha": "a" * 40,
            "workflow_run_id": str(100000 + run_number),
            "terraform_version": TERRAFORM_VERSION,
            "provider_lock_sha256": "b" * 64,
            "source": SOURCE,
            "ref": "refs/heads/master",
            "workflow_ref": (
                "example/repo/.github/workflows/"
                "evidence-producer.yml@refs/heads/master"
            ),
            "run_number": str(run_number),
            "run_attempt": str(run_attempt),
            "stream_id": STREAM_ID,
        }

        manifest_path = bundle_root / "manifest.json"
        signature_path = bundle_root / "manifest.sig"

        manifest = write_manifest(
            artifacts_root,
            manifest_path,
            provenance,
            key_id,
            schema_version="1.3",
            artifact_metadata=ARTIFACT_METADATA,
        )

        signature_path.write_bytes(
            sign_bytes(
                self.private_keys / f"{key_id}.pem",
                manifest_path.read_bytes(),
            )
        )

        return {
            "artifacts_root": artifacts_root,
            "manifest_path": manifest_path,
            "signature_path": signature_path,
            "trust_registry_path": self.registry,
            "source": SOURCE,
            "signature_key_id": key_id,
            "artifacts": [
                entry["name"]
                for entry in manifest["artifacts"]
            ],
        }

    def verify(self, receipt: dict[str, Any]) -> bool:
        """Verify using the production cryptographic verifier."""

        return verify_bundle(
            receipt["artifacts_root"],
            receipt["manifest_path"],
            receipt["signature_path"],
            self.registry,
            receipt["signature_key_id"],
        )

    def consume(
        self,
        receipt: dict[str, Any],
        expected_key_id: str,
    ):
        """Reconfigure signing identity without resetting acceptance."""

        consumer = ConsumerAgent(
            artifacts_root=receipt["artifacts_root"],
            expected_source=SOURCE,
            expected_key_id=expected_key_id,
            acceptance_state=self.acceptance,
            trust_registry_path=self.registry,
            consumer_id=CONSUMER_ID,
            expected_stream_id=STREAM_ID,
        )

        return consumer.run(receipt)


@pytest.fixture
def rotation(tmp_path: Path) -> RotationEnvironment:
    return RotationEnvironment(tmp_path / "rotation")


def assert_accepted(result) -> None:
    assert result.success is True, result
    assert result.error is None
    assert result.data["verified"] is True


def assert_rejected(result, expected_error: str) -> None:
    assert result.success is False, result
    assert result.error == expected_error, result


def test_rotation_overlap_preflight(rotation):
    """Both active signing identities independently authorize."""

    for key_id in (KEY_A, KEY_B):
        validate_trust_deployment(
            rotation.registry,
            key_id,
            SOURCE,
        )

    assert (
        rotation.public_keys.joinpath(f"{KEY_A}.pem").read_bytes()
        != rotation.public_keys.joinpath(f"{KEY_B}.pem").read_bytes()
    )

    bundle_a = rotation.make_bundle(KEY_A, 100)
    bundle_b = rotation.make_bundle(KEY_B, 101)

    assert rotation.verify(bundle_a) is True
    assert rotation.verify(bundle_b) is True


@pytest.mark.parametrize(
    ("expected_key", "actual_key"),
    [
        (KEY_A, KEY_B),
        (KEY_B, KEY_A),
    ],
)
def test_rotation_preserves_expected_key_pinning(
    rotation,
    expected_key,
    actual_key,
):
    """An alternate active key cannot bypass explicit consumer pinning."""

    bundle = rotation.make_bundle(actual_key, 100)

    assert rotation.verify(bundle) is True

    assert_rejected(
        rotation.consume(bundle, expected_key),
        "key-id-mismatch",
    )

    # The rejected submission must not consume the bundle digest.
    assert_accepted(
        rotation.consume(bundle, actual_key)
    )


def test_rotation_preserves_ordered_acceptance(rotation):
    """Changing signing keys must not reset the stream checkpoint."""

    original = rotation.make_bundle(KEY_A, 100)

    assert_accepted(
        rotation.consume(original, KEY_A)
    )

    for run_number in (99, 100):
        candidate = rotation.make_bundle(
            KEY_B,
            run_number,
        )

        assert rotation.verify(candidate) is True

        assert_rejected(
            rotation.consume(candidate, KEY_B),
            "bundle-rollback-detected",
        )

    newer = rotation.make_bundle(KEY_B, 101)

    assert_accepted(
        rotation.consume(newer, KEY_B)
    )

    older = rotation.make_bundle(KEY_B, 100, 9)

    assert_rejected(
        rotation.consume(older, KEY_B),
        "bundle-rollback-detected",
    )


def test_rotation_preserves_replay_detection(rotation):
    """Previously accepted manifest digests survive key transitions."""

    original = rotation.make_bundle(KEY_A, 100)
    newer = rotation.make_bundle(KEY_B, 101)

    assert_accepted(
        rotation.consume(original, KEY_A)
    )

    assert_accepted(
        rotation.consume(newer, KEY_B)
    )

    # Key A remains authorized during the rotation overlap.
    # Its original digest must still be recognized as a replay.
    assert_rejected(
        rotation.consume(original, KEY_A),
        "bundle-replay-detected",
    )

    assert_rejected(
        rotation.consume(newer, KEY_B),
        "bundle-replay-detected",
    )


def test_rotation_preserves_run_attempt_ordering(rotation):
    """Run-attempt ordering remains monotonic across signing keys."""

    original = rotation.make_bundle(KEY_A, 100, 1)

    assert_accepted(
        rotation.consume(original, KEY_A)
    )

    for run_number, run_attempt in (
        (99, 9),
        (100, 1),
    ):
        candidate = rotation.make_bundle(
            KEY_B,
            run_number,
            run_attempt,
        )

        assert_rejected(
            rotation.consume(candidate, KEY_B),
            "bundle-rollback-detected",
        )

    retry = rotation.make_bundle(KEY_B, 100, 2)

    assert_accepted(
        rotation.consume(retry, KEY_B)
    )

    older_attempt = rotation.make_bundle(KEY_B, 100, 1)

    assert_rejected(
        rotation.consume(older_attempt, KEY_B),
        "bundle-rollback-detected",
    )

    next_run = rotation.make_bundle(KEY_B, 101, 1)

    assert_accepted(
        rotation.consume(next_run, KEY_B)
    )


@pytest.mark.parametrize("inactive_status", ["retired", "revoked"])
def test_inactive_key_rejected_after_rotation(
    rotation,
    inactive_status,
):
    """Retirement and revocation invalidate old signing authorization."""

    original = rotation.make_bundle(KEY_A, 100)
    future_old_key = rotation.make_bundle(KEY_A, 999)

    assert_accepted(
        rotation.consume(original, KEY_A)
    )

    assert rotation.verify(future_old_key) is True

    rotation.write_registry(status_a=inactive_status)

    with pytest.raises(ValueError):
        validate_trust_deployment(
            rotation.registry,
            KEY_A,
            SOURCE,
        )

    validate_trust_deployment(
        rotation.registry,
        KEY_B,
        SOURCE,
    )

    # Even evidence signed before the status change is no longer
    # eligible for verification under the current trust policy.
    assert rotation.verify(original) is False

    assert_rejected(
        rotation.consume(original, KEY_A),
        "verification-failed",
    )

    assert_rejected(
        rotation.consume(future_old_key, KEY_A),
        "verification-failed",
    )

    # Rejection of run 999 must not advance the checkpoint.
    replacement = rotation.make_bundle(KEY_B, 101)

    assert_accepted(
        rotation.consume(replacement, KEY_B)
    )


def test_rejected_rotation_bundle_does_not_advance_checkpoint(
    rotation,
):
    """Unauthorized source rejection cannot mutate ordered acceptance."""

    original = rotation.make_bundle(KEY_A, 100)

    assert_accepted(
        rotation.consume(original, KEY_A)
    )

    candidate = rotation.make_bundle(KEY_B, 999)

    assert rotation.verify(candidate) is True

    rotation.write_registry(source_b="local-claimed")

    with pytest.raises(ValueError):
        validate_trust_deployment(
            rotation.registry,
            KEY_B,
            SOURCE,
        )

    assert_rejected(
        rotation.consume(candidate, KEY_B),
        "verification-failed",
    )

    # Restore the authorized source without resetting acceptance.
    rotation.write_registry()

    newer = rotation.make_bundle(KEY_B, 101)

    assert_accepted(
        rotation.consume(newer, KEY_B)
    )

    # The previously rejected digest must not be recorded as accepted.
    assert_accepted(
        rotation.consume(candidate, KEY_B)
    )

    assert_rejected(
        rotation.consume(candidate, KEY_B),
        "bundle-replay-detected",
    )


def test_rotation_rejects_mismatched_public_key(rotation):
    """An authorized key ID cannot substitute for signature validity."""

    original = rotation.make_bundle(KEY_A, 100)

    assert_accepted(
        rotation.consume(original, KEY_A)
    )

    candidate = rotation.make_bundle(KEY_B, 999)

    assert rotation.verify(candidate) is True

    # Associate Key B's identity with Key A's public key.
    rotation.write_registry(
        public_key_b=f"keys/{KEY_A}.pem",
    )

    # Preflight validates authorization and public-key structure.
    # It does not prove that the key matches the signing private key.
    validate_trust_deployment(
        rotation.registry,
        KEY_B,
        SOURCE,
    )

    assert rotation.verify(candidate) is False

    assert_rejected(
        rotation.consume(candidate, KEY_B),
        "verification-failed",
    )

    # Correct the public-key mapping.
    rotation.write_registry()

    newer = rotation.make_bundle(KEY_B, 101)

    assert_accepted(
        rotation.consume(newer, KEY_B)
    )

    assert_accepted(
        rotation.consume(candidate, KEY_B)
    )

    assert_rejected(
        rotation.consume(candidate, KEY_B),
        "bundle-replay-detected",
    )
