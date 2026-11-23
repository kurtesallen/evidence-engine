
from pathlib import Path


WORKFLOW = (
    Path(__file__).resolve().parents[1]
    / ".github"
    / "workflows"
    / "evidence-e2e-integration.yml"
)


def test_preflight_precedes_consumer_and_exports_same_registry():
    workflow = WORKFLOW.read_text(encoding="utf-8")

    preflight_step = (
        "- name: Stage trust material and enforce deployment preflight"
    )
    consume_step = (
        "- name: Verify tampering, trust policy, rollback, "
        "concurrency, acceptance, and replay"
    )

    assert workflow.count(preflight_step) == 1
    assert workflow.count(consume_step) == 1

    preflight_position = workflow.index(preflight_step)
    consume_position = workflow.index(consume_step)

    assert preflight_position < consume_position

    preflight = workflow[preflight_position:consume_position]
    consumer = workflow[consume_position:]

    assert "set -euo pipefail" in preflight
    assert "umask 077" in preflight
    assert 'mktemp -d "$HOME/evidence-engine-trust.XXXXXXXX"' in preflight
    assert 'mkdir -m 700 "$trust_root/keys"' in preflight
    assert "install -m 600 trust/registry.json" in preflight
    assert "python -m evidence_engine.trust_preflight" in preflight
    assert '--trust-registry "$trust_root/registry.json"' in preflight
    assert '--expected-key-id "$EVIDENCE_ENGINE_SIGNING_KEY_ID"' in preflight
    assert "--expected-source github-actions-claimed" in preflight

    export = (
        'echo "EVIDENCE_ENGINE_TRUST_REGISTRY_PATH='
        '$trust_root/registry.json"'
    )
    assert export in preflight
    assert '>> "$GITHUB_ENV"' in preflight
    assert preflight.index("python -m evidence_engine.trust_preflight") < (
        preflight.index(export)
    )

    assert 'test -n "${EVIDENCE_ENGINE_TRUST_REGISTRY_PATH:-}"' in consumer
    assert "python scripts/e2e_synthetic_aws.py consume" in consumer
    assert consumer.index(
        'test -n "${EVIDENCE_ENGINE_TRUST_REGISTRY_PATH:-}"'
    ) < consumer.index("python scripts/e2e_synthetic_aws.py consume")
