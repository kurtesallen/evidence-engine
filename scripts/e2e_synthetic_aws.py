from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from evidence_engine.agents.consumer_factory import create_consumer
from evidence_engine.agents.producer_factory import create_producer
from evidence_engine.ci_provenance import capture_ci_context
from evidence_engine.collect import provenance_for
from evidence_engine.sanitization import TERRAFORM_JSON_CONTENT_RULE_VERSION

ROOT = Path(__file__).resolve().parents[1]
TRUST_REGISTRY = ROOT / "trust" / "registry.json"
REFERENCE_FILE = ROOT / "bundle-reference.json"
SYNTHETIC_TERRAFORM_VERSION = "1.9.0"
STREAM_ID = "evidence-integration-test"

ARTIFACT_METADATA: dict[str, dict[str, Any]] = {
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
}


def require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"Required environment variable is missing: {name}")
    return value


def capture_and_check_ci_context() -> dict[str, str]:
    context = capture_ci_context()
    checked_out = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip().lower()
    if checked_out != context["commit_sha"]:
        raise RuntimeError("GitHub event SHA does not match checked-out commit")
    if context["stream_id"] != STREAM_ID:
        raise RuntimeError("Unexpected integration stream ID")
    if not TRUST_REGISTRY.is_file():
        raise RuntimeError(f"Trusted-key registry is missing: {TRUST_REGISTRY}")
    return context


def write_synthetic_artifacts(artifacts_root: Path, commit_sha: str) -> None:
    """Create synthetic Terraform JSON only; never reads real Terraform state."""
    artifacts_root.mkdir(parents=True, exist_ok=False)

    plan = {
        "format_version": "1.0",
        "terraform_version": SYNTHETIC_TERRAFORM_VERSION,
        "planned_values": {"root_module": {"resources": []}},
        "resource_changes": [
            {
                "address": "example.synthetic",
                "mode": "managed",
                "type": "example",
                "name": "synthetic",
                "change": {
                    "actions": ["update"],
                    "before": {"canary_value": "SYNTHETIC-PLAN-CANARY-SECRET"},
                    "before_sensitive": {"canary_value": True},
                    "after": {"canary_value": "SYNTHETIC-PLAN-CANARY-SECRET"},
                    "after_sensitive": {"canary_value": True},
                },
            }
        ],
    }
    state = {
        "format_version": "1.0",
        "terraform_version": SYNTHETIC_TERRAFORM_VERSION,
        "values": {
            "root_module": {
                "resources": [
                    {
                        "address": "example.synthetic",
                        "mode": "managed",
                        "type": "example",
                        "name": "synthetic",
                        "values": {"canary_value": "SYNTHETIC-STATE-CANARY-SECRET"},
                        "sensitive_values": {"canary_value": True},
                    }
                ]
            }
        },
    }

    (artifacts_root / "plan.json").write_text(
        json.dumps(plan, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    (artifacts_root / "state.json").write_text(
        json.dumps(state, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    (artifacts_root / "commit.txt").write_text(commit_sha + "\n", encoding="utf-8")
    (artifacts_root / "version.txt").write_text(
        f"Terraform {SYNTHETIC_TERRAFORM_VERSION} (synthetic fixture)\n",
        encoding="utf-8",
    )


def build_ci_provenance(context: dict[str, str]) -> dict[str, str]:
    base = provenance_for(ROOT)
    return {
        "repository": context["repository"],
        "commit_sha": context["commit_sha"],
        "workflow_run_id": context["run_id"],
        "terraform_version": SYNTHETIC_TERRAFORM_VERSION,
        "provider_lock_sha256": base.get("provider_lock_sha256", ""),
        "source": "github-actions-claimed",
        "ref": context["ref"],
        "workflow_ref": context["workflow_ref"],
        "run_number": context["run_number"],
        "run_attempt": context["run_attempt"],
        "stream_id": context["stream_id"],
    }


def produce() -> None:
    context = capture_and_check_ci_context()
    region = require_env("AWS_REGION")
    signing_key_id = require_env("EVIDENCE_ENGINE_SIGNING_KEY_ID")
    require_env("EVIDENCE_ENGINE_S3_BUCKET")
    require_env("EVIDENCE_ENGINE_S3_KMS_KEY_ID")

    prefix = (
        "evidence-engine/integration-tests/"
        f"{context['run_id']}/{context['run_attempt']}"
    )
    with TemporaryDirectory(prefix="evidence-engine-synthetic-producer-") as temp:
        temp_root = Path(temp)
        source = temp_root / "source-artifacts"
        output = temp_root / "producer-output"
        write_synthetic_artifacts(source, context["commit_sha"])

        producer = create_producer(
            artifacts_root=source,
            output_dir=output,
            provenance=build_ci_provenance(context),
            trust_registry_path=TRUST_REGISTRY,
            signing_mode="kms",
            kms_key_id=signing_key_id,
            aws_region=region,
            bundle_prefix=prefix,
            artifact_metadata=ARTIFACT_METADATA,
        )
        result = producer.run()
        if not result.success or not isinstance(result.data, dict):
            raise RuntimeError(
                f"Synthetic producer failed: {result.error}; audit={result.audit}"
            )

        staged_plan = (output / "artifacts" / "plan.json").read_bytes()
        staged_state = (output / "artifacts" / "state.json").read_bytes()
        for canary, payload in (
            (b"SYNTHETIC-PLAN-CANARY-SECRET", staged_plan),
            (b"SYNTHETIC-STATE-CANARY-SECRET", staged_state),
        ):
            if canary in payload or b"[REDACTED]" not in payload:
                raise RuntimeError("Synthetic sensitive canary was not safely redacted")

        bundle_reference = result.data.get("bundle_reference")
        receipt = result.data.get("receipt")
        if not isinstance(bundle_reference, dict) or not isinstance(receipt, dict):
            raise RuntimeError("Producer returned an incomplete remote bundle result")
        REFERENCE_FILE.write_text(
            json.dumps(
                {"receipt": receipt, "bundle_reference": bundle_reference},
                sort_keys=True,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    print(f"Synthetic bundle uploaded under prefix: {prefix}")
    print("Sanitization canaries were redacted before manifest hashing and upload.")
    print(f"Transfer reference created: {REFERENCE_FILE.name}")


def consume() -> None:
    require_env("AWS_REGION")
    require_env("EVIDENCE_ENGINE_S3_BUCKET")
    require_env("EVIDENCE_ENGINE_S3_KMS_KEY_ID")
    signing_key_id = require_env("EVIDENCE_ENGINE_SIGNING_KEY_ID")
    if not REFERENCE_FILE.is_file():
        raise RuntimeError(f"Producer reference is missing: {REFERENCE_FILE}")
    payload = json.loads(REFERENCE_FILE.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("bundle_reference"), dict):
        raise RuntimeError("Producer reference file is invalid")

    consumer = create_consumer(
        artifacts_root=ROOT / ".e2e-consumer-unused",
        expected_source="github-actions-claimed",
        expected_key_id=signing_key_id,
        trust_registry_path=TRUST_REGISTRY,
        configure_remote_storage=True,
        require_remote_bundle=True,
        consumer_id=require_env("EVIDENCE_ENGINE_CONSUMER_ID"),
        expected_stream_id=require_env("EVIDENCE_ENGINE_EXPECTED_STREAM_ID"),
    )

    first = consumer.run(payload)
    if not first.success:
        raise RuntimeError(
            f"First consumer attempt failed: {first.error}; audit={first.audit}"
        )
    if not isinstance(first.data, dict) or first.data.get("verified") is not True:
        raise RuntimeError("Consumer did not report successful signature verification")
    print("First consumption: signature verified and acceptance recorded.")

    replay = consumer.run(payload)
    if replay.success or replay.error != "bundle-replay-detected":
        raise RuntimeError(
            "Replay assertion failed: expected bundle-replay-detected, "
            f"got success={replay.success}, error={replay.error}, audit={replay.audit}"
        )
    print("Second consumption: duplicate bundle rejected as replay.")
    print(f"Accepted manifest digest: {first.audit.get('bundle_digest', 'unreported')}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Synthetic-only AWS end-to-end test for EvidenceEngine."
    )
    parser.add_argument("mode", choices=("produce", "consume"))
    args = parser.parse_args()
    try:
        if args.mode == "produce":
            produce()
        else:
            consume()
    except Exception as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
