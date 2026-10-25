import pytest

from evidence_engine.agents.base import Agent, AgentResult
from evidence_engine.policy import PolicyDecision, PolicyEngine


class DummyAgent(Agent):
    def __init__(self) -> None:
        super().__init__("dummy-agent")

    def run(self, **kwargs):
        # Simple success path for testing
        return AgentResult(
            success=True,
            data={"value": kwargs.get("value", 42)},
            error=None,
            audit={"inputs": kwargs},
        )


def test_agent_result_success_shape():
    result = AgentResult(
        success=True,
        data={"foo": "bar"},
        error=None,
        audit={"stage": "test"},
    )

    assert result.success is True
    assert result.error is None
    assert result.data == {"foo": "bar"}
    assert result.audit == {"stage": "test"}


def test_agent_result_failure_shape():
    result = AgentResult(
        success=False,
        data=None,
        error="test-error",
        audit={"stage": "test"},
    )

    assert result.success is False
    assert result.error == "test-error"
    assert result.data is None
    assert "stage" in result.audit


def test_agent_requires_non_empty_name():
    with pytest.raises(ValueError):
        Agent(name="")  # type: ignore[abstract]


def test_dummy_agent_run_success():
    agent = DummyAgent()
    result = agent.run(value=7)

    assert result.success is True
    assert result.error is None
    assert result.data["value"] == 7
    assert result.audit["inputs"]["value"] == 7


def test_policy_decision_structure():
    decision = PolicyDecision(
        allowed=True,
        reason="test-reason",
        details={"foo": "bar"},
    )

    assert decision.allowed is True
    assert decision.reason == "test-reason"
    assert decision.details["foo"] == "bar"


def test_policy_engine_version_validation():
    with pytest.raises(ValueError):
        PolicyEngine(version="")

    engine = PolicyEngine(version="1.2")
    assert engine.version == "1.2"


def test_collection_policy_fail_closed_on_invalid_metadata_type():
    engine = PolicyEngine()
    decision = engine.evaluate_collection(metadata=None)

    assert decision.allowed is False
    assert decision.reason == "collection-metadata-invalid"


def test_collection_policy_fail_closed_on_missing_root():
    engine = PolicyEngine()
    decision = engine.evaluate_collection(metadata={"files": ["a.txt"]})

    assert decision.allowed is False
    assert decision.reason == "collection-root-missing"


def test_collection_policy_fail_closed_on_missing_files():
    engine = PolicyEngine()
    decision = engine.evaluate_collection(metadata={"root": "/tmp"})

    assert decision.allowed is False
    assert decision.reason == "collection-files-missing"


def test_collection_policy_allows_valid_metadata():
    engine = PolicyEngine()
    decision = engine.evaluate_collection(
        metadata={"root": "/tmp/artifacts", "files": ["a.txt", "b.json"]}
    )

    assert decision.allowed is True
    assert decision.reason == "collection-allowed"
    assert decision.details["file_count"] == 2


def test_integrity_policy_fail_closed_on_invalid_manifest():
    engine = PolicyEngine()
    decision = engine.evaluate_integrity(manifest=None)

    assert decision.allowed is False
    assert decision.reason == "integrity-manifest-invalid"


def test_integrity_policy_fail_closed_on_missing_artifacts():
    engine = PolicyEngine()
    decision = engine.evaluate_integrity(manifest={})

    assert decision.allowed is False
    assert decision.reason == "integrity-artifacts-missing"


def test_integrity_policy_allows_valid_manifest():
    engine = PolicyEngine()
    manifest = {
        "artifacts": [
            {"name": "plan.json"},
            {"name": "state.json"},
        ]
    }
    decision = engine.evaluate_integrity(manifest=manifest)

    assert decision.allowed is True
    assert decision.reason == "integrity-allowed"
    assert decision.details["artifact_count"] == 2


def test_consumption_policy_fail_closed_on_invalid_receipt():
    engine = PolicyEngine()
    decision = engine.evaluate_consumption(receipt=None)

    assert decision.allowed is False
    assert decision.reason == "consumption-receipt-invalid"


def test_consumption_policy_fail_closed_on_missing_artifacts():
    engine = PolicyEngine()
    decision = engine.evaluate_consumption(
        receipt={"signature_key_id": "key-123"}
    )

    assert decision.allowed is False
    assert decision.reason == "consumption-artifacts-missing"


def test_consumption_policy_fail_closed_on_missing_key_id():
    engine = PolicyEngine()
    decision = engine.evaluate_consumption(
        receipt={"artifacts": ["a.txt"]}
    )

    assert decision.allowed is False
    assert decision.reason == "consumption-key-id-missing"


def test_consumption_policy_allows_valid_receipt():
    engine = PolicyEngine()
    receipt = {
        "artifacts": ["a.txt", "b.json"],
        "signature_key_id": "key-123",
    }
    decision = engine.evaluate_consumption(receipt=receipt)

    assert decision.allowed is True
    assert decision.reason == "consumption-allowed"
    assert decision.details["artifact_count"] == 2
