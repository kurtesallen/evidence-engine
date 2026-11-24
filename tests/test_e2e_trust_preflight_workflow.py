"""Structural regression tests for independent E2E trust deployment."""

from pathlib import Path

import pytest


WORKFLOW = (
    Path(__file__).resolve().parents[1]
    / ".github"
    / "workflows"
    / "evidence-e2e-integration.yml"
)

PRODUCER_STAGE = (
    "Stage producer trust material and enforce deployment preflight"
)

CONSUMER_STAGE = (
    "Stage trust material and enforce deployment preflight"
)

PRODUCER_EXECUTION = (
    "Create, sanitize, sign, and upload synthetic bundle"
)

CONSUMER_EXECUTION = (
    "Verify tampering, trust policy, rollback, "
    "concurrency, acceptance, and replay"
)

REGISTRY_EXPORT = (
    'echo "EVIDENCE_ENGINE_TRUST_REGISTRY_PATH='
    '$staged_trust/registry.json"'
)

REGISTRY_GUARD = (
    'test -n "${EVIDENCE_ENGINE_TRUST_REGISTRY_PATH:-}"'
)


def workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def workflow_job(mode: str) -> str:
    workflow = workflow_text()

    producer_start = workflow.index("\n  produce:\n")
    consumer_start = workflow.index("\n  consume:\n")

    if mode == "produce":
        return workflow[producer_start:consumer_start]

    if mode == "consume":
        return workflow[consumer_start:]

    raise ValueError(f"Unsupported workflow mode: {mode}")


def workflow_step(job: str, name: str) -> str:
    marker = f"      - name: {name}\n"

    assert job.count(marker) == 1, name

    start = job.index(marker)
    end = job.find("\n      - name: ", start + len(marker))

    if end == -1:
        end = len(job)

    return job[start:end]


@pytest.mark.parametrize(
    ("mode", "stage_name", "execution_name"),
    [
        ("produce", PRODUCER_STAGE, PRODUCER_EXECUTION),
        ("consume", CONSUMER_STAGE, CONSUMER_EXECUTION),
    ],
)
def test_independent_trust_gate_precedes_execution(
    mode,
    stage_name,
    execution_name,
):
    job = workflow_job(mode)

    stage = workflow_step(job, stage_name)
    execution = workflow_step(job, execution_name)

    assert job.index(stage) < job.index(execution)

    assert "shell: bash" in stage
    assert "set -euo pipefail" in stage
    assert "umask 077" in stage

    assert (
        'mktemp -d "$HOME/evidence-engine-trust.XXXXXXXX"'
        in stage
    )

    assert 'staged_trust="$trust_root/staged"' in stage

    assert "python -m evidence_engine.trust_deployment" in stage

    assert (
        '--source-registry "$GITHUB_WORKSPACE/trust/registry.json"'
        in stage
    )

    assert '--destination "$staged_trust"' in stage

    assert "python -m evidence_engine.trust_preflight" in stage

    assert (
        '--trust-registry "$staged_trust/registry.json"'
        in stage
    )

    assert (
        '--expected-key-id "$EVIDENCE_ENGINE_SIGNING_KEY_ID"'
        in stage
    )

    assert "--expected-source github-actions-claimed" in stage

    assert REGISTRY_EXPORT in stage
    assert '>> "$GITHUB_ENV"' in stage

    ordered_markers = (
        "set -euo pipefail",
        "umask 077",
        'mktemp -d "$HOME/evidence-engine-trust.XXXXXXXX"',
        'staged_trust="$trust_root/staged"',
        "python -m evidence_engine.trust_deployment",
        "python -m evidence_engine.trust_preflight",
        REGISTRY_EXPORT,
        '>> "$GITHUB_ENV"',
    )

    positions = [
        stage.index(marker)
        for marker in ordered_markers
    ]

    assert positions == sorted(positions)

    assert "shell: bash" in execution
    assert "set -euo pipefail" in execution
    assert REGISTRY_GUARD in execution

    command = f"python scripts/e2e_synthetic_aws.py {mode}"

    assert command in execution

    assert execution.index(REGISTRY_GUARD) < (
        execution.index(command)
    )

    for step in (stage, execution):
        assert "continue-on-error:" not in step
        assert "always()" not in step
        assert "failure()" not in step
        assert "|| true" not in step


def test_workflow_has_two_independent_trust_gates():
    workflow = workflow_text()

    for marker in (
        "python -m evidence_engine.trust_deployment",
        "python -m evidence_engine.trust_preflight",
        REGISTRY_EXPORT,
        REGISTRY_GUARD,
    ):
        assert workflow.count(marker) == 2

    for mode in ("produce", "consume"):
        job = workflow_job(mode)

        assert job.count(
            "python -m evidence_engine.trust_deployment"
        ) == 1

        assert job.count(
            "python -m evidence_engine.trust_preflight"
        ) == 1

        assert job.count(REGISTRY_EXPORT) == 1
        assert job.count(REGISTRY_GUARD) == 1


def test_workflow_has_no_hardcoded_public_key_installation():
    workflow = workflow_text()

    assert "evidence-engine-signing-public.pem" not in workflow
    assert "install -m 600 trust/registry.json" not in workflow
    assert 'mkdir -m 700 "$trust_root/keys"' not in workflow


def test_producer_provenance_configuration_is_preserved():
    producer = workflow_job("produce")

    execution = workflow_step(
        producer,
        PRODUCER_EXECUTION,
    )

    expected = (
        'GITHUB_ACTIONS: "true"',
        "GITHUB_REPOSITORY: ${{ github.repository }}",
        "GITHUB_SHA: ${{ github.sha }}",
        "GITHUB_REF: ${{ github.ref }}",
        "GITHUB_RUN_ID: ${{ github.run_id }}",
        "GITHUB_WORKFLOW_REF: ${{ github.workflow_ref }}",
        "GITHUB_RUN_NUMBER: ${{ github.run_number }}",
        "GITHUB_RUN_ATTEMPT: ${{ github.run_attempt }}",
    )

    for marker in expected:
        assert marker in execution


def test_workflow_preserves_independent_job_boundaries():
    producer = workflow_job("produce")
    consumer = workflow_job("consume")

    assert "needs: guard" in producer
    assert "needs: produce" in consumer

    assert "name: evidence-producer" in producer
    assert "name: evidence-consumer" in consumer

    assert "persist-credentials: false" in producer
    assert "persist-credentials: false" in consumer

    assert "id-token: write" in producer
    assert "id-token: write" in consumer


def test_workflow_transfers_reference_not_trust_material():
    producer = workflow_job("produce")

    transfer = workflow_step(
        producer,
        "Transfer versioned bundle reference to consumer job",
    )

    assert "path: bundle-reference.json" in transfer
    assert "if-no-files-found: error" in transfer

    assert "$staged_trust" not in transfer
    assert "$trust_root" not in transfer
    assert "registry.json" not in transfer


def test_workflow_preserves_manual_synthetic_only_guard():
    workflow = workflow_text()

    guard = workflow.split("\n  produce:\n", 1)[0]

    assert "workflow_dispatch:" in guard
    assert "confirm_synthetic_only:" in guard
    assert "default: false" in guard

    assert (
        'if [[ "$GITHUB_REF" != "refs/heads/master" ]]; then'
        in guard
    )

    assert (
        'if [[ "$CONFIRM_SYNTHETIC_ONLY" != "true" ]]; then'
        in guard
    )

    assert guard.count("exit 1") >= 2
