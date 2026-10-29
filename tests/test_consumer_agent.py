import hashlib
from pathlib import Path

import pytest

from evidence_engine.acceptance import InMemoryAcceptanceState
from evidence_engine.agents.consumer import ConsumerAgent
from evidence_engine.aws.reference import BundleReference
from evidence_engine.canonical import canonical_json_bytes
from evidence_engine.schema import REQUIRED_ARTIFACTS


def make_consumer(root, **kwargs):
    kwargs.setdefault("acceptance_state", InMemoryAcceptanceState())
    return ConsumerAgent(root, **kwargs)


def valid_manifest():
    names = ["plan.json", "state.json", "commit.txt", "version.txt"]
    return {
        "schema_version": "1.1",
        "hash_algorithm": "SHA-256",
        "signature_algorithm": "RSA-PSS-SHA256",
        "key_id": "test-key",
        "provenance": {
            "repository": "example/repo",
            "commit_sha": "a" * 40,
            "workflow_run_id": "none",
            "terraform_version": "1.9.0",
            "provider_lock_sha256": "b" * 64,
            "source": "local-claimed",
        },
        "artifacts": [
            {
                "name": name,
                "size_bytes": 0,
                "representation": "raw",
                "sanitization_rule_version": None,
                "sha256": "0" * 64,
            }
            for name in names
        ],
    }


@pytest.fixture
def consumer_setup(tmp_path, monkeypatch):
    root = tmp_path / "artifacts"
    root.mkdir()

    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_bytes(canonical_json_bytes(valid_manifest()))

    receipt = {
        "artifacts_root": str(root),
        "manifest_path": str(manifest_path),
        "signature_path": str(tmp_path / "manifest.sig"),
        "trust_registry_path": str(tmp_path / "trust.json"),
        "source": "local-claimed",
        "artifacts": [
            "plan.json",
            "state.json",
            "commit.txt",
            "version.txt",
        ],
        "signature_key_id": "test-key",
    }

    calls = []

    def fake_verify_bundle(*args):
        calls.append(args)
        return True

    monkeypatch.setattr(
        "evidence_engine.agents.consumer.verify_bundle",
        fake_verify_bundle,
    )

    return root, receipt, calls


def remote_payloads(prefix):
    """Return deterministic bytes for a complete mocked remote bundle."""
    payloads = {
        f"{prefix}/manifest.json": canonical_json_bytes(valid_manifest()),
        f"{prefix}/manifest.sig": b"test-signature",
    }

    for name in sorted(REQUIRED_ARTIFACTS):
        payloads[f"{prefix}/artifacts/{name}"] = b""

    return payloads


def valid_bundle_reference():
    prefix = "runs/remote-test"
    payloads = remote_payloads(prefix)

    objects = [
        {
            "key": key,
            "sha256": hashlib.sha256(content).hexdigest(),
            "version_id": f"version-{index}",
        }
        for index, (key, content) in enumerate(
            sorted(payloads.items()),
            start=1,
        )
    ]

    return BundleReference.from_upload(
        bucket="evidence-test-bucket",
        prefix=prefix,
        objects=objects,
    ).to_dict()


class FakeRemoteStorage:
    """Mock S3 retrieval, including bundle-reference digest checks."""

    def __init__(self, fail=False):
        self.fail = fail
        self.calls = []

    def download_bundle(self, *, prefix, destination, reference):
        self.calls.append(
            {
                "prefix": prefix,
                "destination": Path(destination),
                "reference": reference,
            }
        )

        if self.fail:
            raise RuntimeError("simulated S3 download failure")

        if reference.prefix != prefix:
            raise ValueError("Bundle prefix mismatch")

        payloads = remote_payloads(prefix)
        referenced_objects = {
            item["key"]: item for item in reference.objects
        }

        if set(payloads) != set(referenced_objects):
            raise ValueError("Incomplete bundle reference")

        destination = Path(destination)
        destination.mkdir(parents=True)

        for key, content in payloads.items():
            expected_digest = referenced_objects[key]["sha256"]
            actual_digest = hashlib.sha256(content).hexdigest()

            if actual_digest != expected_digest:
                raise ValueError(f"Bundle reference digest mismatch: {key}")

            if key.endswith("/manifest.json"):
                relative = Path("manifest.json")
            elif key.endswith("/manifest.sig"):
                relative = Path("manifest.sig")
            else:
                relative = Path("artifacts") / key.rsplit("/", 1)[-1]

            path = destination / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)


def test_consumer_requires_expected_key_id(consumer_setup):
    root, receipt, calls = consumer_setup

    result = make_consumer(root).run(receipt)

    assert result.success is False
    assert result.error == "expected-key-id-missing"
    assert calls == []


def test_consumer_verifies_matching_receipt(consumer_setup):
    root, receipt, calls = consumer_setup

    result = make_consumer(
        root,
        expected_source="local-claimed",
        expected_key_id="test-key",
    ).run(receipt)

    assert result.success is True
    assert result.data == {"verified": True, "key_id": "test-key"}
    assert len(calls) == 1


@pytest.mark.parametrize(
    ("field", "value", "expected_error"),
    [
        ("source", "github-actions-claimed", "receipt-source-mismatch"),
        ("signature_key_id", "other-key", "receipt-key-id-mismatch"),
        ("artifacts", ["plan.json"], "receipt-artifacts-mismatch"),
    ],
)
def test_consumer_rejects_receipt_metadata_mismatch(
    consumer_setup, field, value, expected_error
):
    root, receipt, calls = consumer_setup
    receipt[field] = value

    result = make_consumer(
        root,
        expected_key_id="test-key",
    ).run(receipt)

    assert result.success is False
    assert result.error == expected_error
    assert calls == []


def test_consumer_rejects_key_id_mismatch(consumer_setup):
    root, receipt, calls = consumer_setup

    result = make_consumer(
        root,
        expected_key_id="different-key",
    ).run(receipt)

    assert result.success is False
    assert result.error == "key-id-mismatch"
    assert calls == []


def test_consumer_reports_failed_cryptographic_verification(
    consumer_setup, monkeypatch
):
    root, receipt, calls = consumer_setup

    monkeypatch.setattr(
        "evidence_engine.agents.consumer.verify_bundle",
        lambda *args: False,
    )

    result = make_consumer(
        root,
        expected_key_id="test-key",
    ).run(receipt)

    assert result.success is False
    assert result.error == "verification-failed"


def test_consumer_rejects_artifact_root_mismatch(consumer_setup, tmp_path):
    root, receipt, calls = consumer_setup
    receipt["artifacts_root"] = str(tmp_path / "different-root")

    result = make_consumer(
        root,
        expected_key_id="test-key",
    ).run(receipt)

    assert result.success is False
    assert result.error == "receipt-artifacts-root-mismatch"
    assert calls == []


def test_consumer_rejects_replayed_bundle(consumer_setup):
    root, receipt, calls = consumer_setup
    state = InMemoryAcceptanceState()

    consumer = ConsumerAgent(
        root,
        expected_key_id="test-key",
        acceptance_state=state,
    )

    first = consumer.run(receipt)
    second = consumer.run(receipt)

    assert first.success is True
    assert second.success is False
    assert second.error == "bundle-replay-detected"
    assert first.audit["bundle_digest"] == second.audit["bundle_digest"]
    assert len(calls) == 2


def test_consumer_fails_closed_when_acceptance_state_errors(consumer_setup):
    root, receipt, calls = consumer_setup

    class BrokenAcceptanceState:
        def accept_once(self, bundle_digest: str) -> bool:
            raise RuntimeError("simulated storage failure")

    consumer = ConsumerAgent(
        root,
        expected_key_id="test-key",
        acceptance_state=BrokenAcceptanceState(),
    )

    result = consumer.run(receipt)

    assert result.success is False
    assert result.error == "acceptance-state-error"
    assert len(calls) == 1


def test_remote_consumer_downloads_verifies_and_accepts(
    consumer_setup, tmp_path
):
    root, producer_receipt, verify_calls = consumer_setup
    storage = FakeRemoteStorage()
    trust_registry = tmp_path / "consumer-trust.json"

    consumer = ConsumerAgent(
        root,
        expected_source="local-claimed",
        expected_key_id="test-key",
        acceptance_state=InMemoryAcceptanceState(),
        bundle_storage=storage,
        trust_registry_path=trust_registry,
    )

    # Matches the orchestrator's nested result structure.
    producer_result = {
        "receipt": producer_receipt,
        "bundle_reference": valid_bundle_reference(),
    }

    result = consumer.run(producer_result)

    assert result.success is True
    assert len(storage.calls) == 1
    assert storage.calls[0]["prefix"] == "runs/remote-test"
    assert len(verify_calls) == 1

    verify_args = verify_calls[0]
    assert Path(verify_args[0]).name == "artifacts"
    assert Path(verify_args[1]).name == "manifest.json"
    assert Path(verify_args[2]).name == "manifest.sig"
    assert Path(verify_args[3]) == trust_registry
    assert verify_args[4] == "test-key"

    expected_digest = hashlib.sha256(
        canonical_json_bytes(valid_manifest())
    ).hexdigest()
    assert result.audit["bundle_digest"] == expected_digest


def test_remote_consumer_requires_configured_trust_registry(
    consumer_setup,
):
    root, producer_receipt, verify_calls = consumer_setup
    storage = FakeRemoteStorage()

    consumer = ConsumerAgent(
        root,
        expected_key_id="test-key",
        acceptance_state=InMemoryAcceptanceState(),
        bundle_storage=storage,
    )

    result = consumer.run(
        {
            "receipt": producer_receipt,
            "bundle_reference": valid_bundle_reference(),
        }
    )

    assert result.success is False
    assert result.error == "trusted-registry-missing"
    assert storage.calls == []
    assert verify_calls == []


def test_remote_consumer_fails_closed_on_download_error(
    consumer_setup, tmp_path
):
    root, producer_receipt, verify_calls = consumer_setup
    storage = FakeRemoteStorage(fail=True)

    consumer = ConsumerAgent(
        root,
        expected_key_id="test-key",
        acceptance_state=InMemoryAcceptanceState(),
        bundle_storage=storage,
        trust_registry_path=tmp_path / "consumer-trust.json",
    )

    result = consumer.run(
        {
            "receipt": producer_receipt,
            "bundle_reference": valid_bundle_reference(),
        }
    )

    assert result.success is False
    assert result.error == "bundle-download-failed"
    assert result.audit["exception_type"] == "RuntimeError"
    assert verify_calls == []

def _write_v13_receipt(
    receipt,
    *,
    stream_id="terraform-production",
    run_number="42",
    run_attempt="1",
):
    manifest = valid_manifest()
    manifest["schema_version"] = "1.3"
    manifest["provenance"].update(
        {
            "source": "github-actions-claimed",
            "workflow_run_id": "123456789",
            "ref": "refs/heads/master",
            "workflow_ref": (
                "example/repo/.github/workflows/"
                "evidence-producer.yml@refs/heads/master"
            ),
            "run_number": run_number,
            "run_attempt": run_attempt,
            "stream_id": stream_id,
        }
    )

    Path(receipt["manifest_path"]).write_bytes(canonical_json_bytes(manifest))
    receipt["source"] = "github-actions-claimed"


def test_v13_consumer_requires_ordered_acceptance_configuration(
    consumer_setup,
):
    root, receipt, _ = consumer_setup
    _write_v13_receipt(receipt)

    consumer = ConsumerAgent(
        root,
        expected_key_id="test-key",
        acceptance_state=InMemoryAcceptanceState(),
    )

    result = consumer.run(receipt)

    assert result.success is False
    assert result.error == "ordered-acceptance-config-missing"


def test_v13_consumer_rejects_unexpected_stream(consumer_setup):
    root, receipt, _ = consumer_setup
    _write_v13_receipt(receipt, stream_id="terraform-production")

    consumer = ConsumerAgent(
        root,
        expected_key_id="test-key",
        acceptance_state=InMemoryAcceptanceState(),
        consumer_id="consumer-a",
        expected_stream_id="terraform-staging",
    )

    result = consumer.run(receipt)

    assert result.success is False
    assert result.error == "stream-id-mismatch"


def test_v13_consumer_rejects_replay_and_stale_run(consumer_setup):
    root, receipt, _ = consumer_setup
    state = InMemoryAcceptanceState()
    _write_v13_receipt(receipt, run_number="42", run_attempt="1")

    consumer = ConsumerAgent(
        root,
        expected_key_id="test-key",
        acceptance_state=state,
        consumer_id="consumer-a",
        expected_stream_id="terraform-production",
    )

    first = consumer.run(receipt)
    duplicate = consumer.run(receipt)

    assert first.success is True
    assert duplicate.success is False
    assert duplicate.error == "bundle-replay-detected"

    # A distinct bundle from an older run must not roll back the checkpoint.
    _write_v13_receipt(receipt, run_number="41", run_attempt="9")
    stale = consumer.run(receipt)

    assert stale.success is False
    assert stale.error == "bundle-rollback-detected"

    # A newer attempt for run 42 advances beyond attempt 1.
    _write_v13_receipt(receipt, run_number="42", run_attempt="2")
    newer = consumer.run(receipt)

    assert newer.success is True
