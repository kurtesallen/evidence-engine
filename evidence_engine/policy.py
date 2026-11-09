from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from evidence_engine.sanitization import (
    TERRAFORM_JSON_CONTENT_RULE_VERSION,
)


@dataclass(frozen=True)
class PolicyDecision:
    """
    Structured policy decision.

    - allowed: True if the action is permitted, False otherwise.
    - reason: short, machine-readable reason code.
    - details: structured context for auditing and debugging.
    """

    allowed: bool
    reason: str
    details: Mapping[str, Any]


class PolicyEngine:
    """
    Versioned policy engine for EvidenceEngine agents.

    Policies MUST fail closed:
    - malformed or missing required inputs -> allowed=False
    - unexpected types or structures -> allowed=False
    """

    def __init__(self, version: str = "1.0") -> None:
        if not isinstance(version, str) or not version.strip():
            raise ValueError("Policy version must be a non-empty string")
        self.version = version

    def _fail_closed(
        self,
        reason: str,
        details: Mapping[str, Any] | None = None,
    ) -> PolicyDecision:
        return PolicyDecision(
            allowed=False,
            reason=reason,
            details={"version": self.version, **(details or {})},
        )

    def evaluate_collection(
        self,
        metadata: Mapping[str, Any] | None,
    ) -> PolicyDecision:
        """
        Evaluate whether evidence collection is allowed.

        Required inputs:
        - metadata["root"]: non-empty string path
        - metadata["files"]: iterable of non-empty string filenames
        """
        if not isinstance(metadata, Mapping):
            return self._fail_closed(
                "collection-metadata-invalid",
                {"metadata_type": type(metadata).__name__},
            )

        root = metadata.get("root")
        files = metadata.get("files")

        if not isinstance(root, str) or not root.strip():
            return self._fail_closed(
                "collection-root-missing",
                {"root": root},
            )

        if not isinstance(files, (list, tuple)) or not files:
            return self._fail_closed(
                "collection-files-missing",
                {"files": files},
            )

        for name in files:
            if not isinstance(name, str) or not name.strip():
                return self._fail_closed(
                    "collection-file-name-invalid",
                    {"file": name},
                )

        return PolicyDecision(
            allowed=True,
            reason="collection-allowed",
            details={
                "version": self.version,
                "file_count": len(files),
            },
        )

    def evaluate_integrity(
        self,
        manifest: Mapping[str, Any] | None,
    ) -> PolicyDecision:
        """
        Evaluate manifest integrity and Terraform artifact policy.

        This validates manifest metadata only. Artifact contents and
        Terraform version consistency are checked by verify_bundle().

        Representation policy:
        - v1.1: plan/state must both be raw, both sample, or both sanitized.
        - v1.2/v1.3: plan/state must both be sanitized.
        - Sanitized Terraform artifacts must use the supported rule version.
        - commit.txt and version.txt must be raw or sample, without a rule version.
        """
        if not isinstance(manifest, Mapping):
            return self._fail_closed(
                "integrity-manifest-invalid",
                {"manifest_type": type(manifest).__name__},
            )

        artifacts = manifest.get("artifacts")
        if not isinstance(artifacts, (list, tuple)) or not artifacts:
            return self._fail_closed(
                "integrity-artifacts-missing",
                {"artifacts": artifacts},
            )

        entries: dict[str, Mapping[str, Any]] = {}

        for entry in artifacts:
            if not isinstance(entry, Mapping):
                return self._fail_closed(
                    "integrity-artifact-entry-invalid",
                    {"entry_type": type(entry).__name__},
                )

            name = entry.get("name")
            if not isinstance(name, str) or not name.strip():
                return self._fail_closed(
                    "integrity-artifact-name-invalid",
                    {"entry": dict(entry)},
                )

            if name in entries:
                return self._fail_closed(
                    "integrity-artifact-duplicate",
                    {"name": name},
                )

            entries[name] = entry

        required = {
            "plan.json",
            "state.json",
            "commit.txt",
            "version.txt",
        }

        if set(entries) != required:
            return self._fail_closed(
                "integrity-artifact-set-invalid",
                {
                    "expected": sorted(required),
                    "actual": sorted(entries),
                },
            )

        schema_version = manifest.get("schema_version")

        if (
            not isinstance(schema_version, str)
            or schema_version not in {"1.1", "1.2", "1.3"}
        ):
            return self._fail_closed(
                "integrity-schema-version-unsupported",
                {"schema_version": schema_version},
            )

        plan = entries["plan.json"]
        state = entries["state.json"]

        plan_representation = plan.get("representation")
        state_representation = state.get("representation")

        valid_terraform_representations = {
            "raw",
            "sample",
            "sanitized",
        }

        if (
            not isinstance(plan_representation, str)
            or plan_representation not in valid_terraform_representations
        ):
            return self._fail_closed(
                "integrity-terraform-representation-invalid",
                {"representation": plan_representation},
            )

        if (
            not isinstance(state_representation, str)
            or state_representation not in valid_terraform_representations
        ):
            return self._fail_closed(
                "integrity-terraform-representation-invalid",
                {"representation": state_representation},
            )

        if schema_version in {"1.2", "1.3"}:
            if (
                plan_representation != "sanitized"
                or state_representation != "sanitized"
            ):
                return self._fail_closed(
                    "integrity-terraform-artifacts-not-sanitized",
                    {
                        "plan_representation": plan_representation,
                        "state_representation": state_representation,
                    },
                )
        elif plan_representation != state_representation:
            return self._fail_closed(
                "integrity-terraform-representation-mismatch",
                {
                    "plan_representation": plan_representation,
                    "state_representation": state_representation,
                },
            )

        if plan_representation == "sanitized":
            expected_rule = TERRAFORM_JSON_CONTENT_RULE_VERSION

            for name, entry in (
                ("plan.json", plan),
                ("state.json", state),
            ):
                if entry.get("sanitization_rule_version") != expected_rule:
                    return self._fail_closed(
                        "integrity-sanitization-rule-unsupported",
                        {
                            "name": name,
                            "actual": entry.get(
                                "sanitization_rule_version"
                            ),
                            "expected": expected_rule,
                        },
                    )
        else:
            for name, entry in (
                ("plan.json", plan),
                ("state.json", state),
            ):
                if entry.get("sanitization_rule_version") is not None:
                    return self._fail_closed(
                        "integrity-unexpected-sanitization-rule",
                        {
                            "name": name,
                            "rule_version": entry.get(
                                "sanitization_rule_version"
                            ),
                        },
                    )

        for name in ("commit.txt", "version.txt"):
            entry = entries[name]
            representation = entry.get("representation")

            if (
                not isinstance(representation, str)
                or representation not in {"raw", "sample"}
            ):
                return self._fail_closed(
                    "integrity-metadata-representation-invalid",
                    {
                        "name": name,
                        "representation": representation,
                    },
                )

            if entry.get("sanitization_rule_version") is not None:
                return self._fail_closed(
                    "integrity-unexpected-sanitization-rule",
                    {
                        "name": name,
                        "rule_version": entry.get(
                            "sanitization_rule_version"
                        ),
                    },
                )

        return PolicyDecision(
            allowed=True,
            reason="integrity-allowed",
            details={
                "version": self.version,
                "artifact_count": len(artifacts),
                "schema_version": schema_version,
                "terraform_representation": plan_representation,
            },
        )

    def evaluate_consumption(
        self,
        receipt: Mapping[str, Any] | None,
    ) -> PolicyDecision:
        """
        Evaluate whether evidence consumption is allowed.

        Required inputs:
        - receipt["artifacts"]: iterable of non-empty string names
        - receipt["signature_key_id"]: non-empty string
        """
        if not isinstance(receipt, Mapping):
            return self._fail_closed(
                "consumption-receipt-invalid",
                {"receipt_type": type(receipt).__name__},
            )

        artifacts = receipt.get("artifacts")
        key_id = receipt.get("signature_key_id")

        if not isinstance(artifacts, (list, tuple)) or not artifacts:
            return self._fail_closed(
                "consumption-artifacts-missing",
                {"artifacts": artifacts},
            )

        for name in artifacts:
            if not isinstance(name, str) or not name.strip():
                return self._fail_closed(
                    "consumption-artifact-name-invalid",
                    {"artifact": name},
                )

        if not isinstance(key_id, str) or not key_id.strip():
            return self._fail_closed(
                "consumption-key-id-missing",
                {"signature_key_id": key_id},
            )

        return PolicyDecision(
            allowed=True,
            reason="consumption-allowed",
            details={
                "version": self.version,
                "artifact_count": len(artifacts),
            },
        )
