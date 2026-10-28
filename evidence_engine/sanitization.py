from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, MutableMapping, Sequence

from evidence_engine.canonical import canonical_json_bytes


REDACTED = "[REDACTED]"
TERRAFORM_JSON_CONTENT_RULE = "terraform_json_content"
TERRAFORM_JSON_CONTENT_RULE_VERSION = "1.1"


class ArtifactSanitizationError(ValueError):
    """Raised when artifact content cannot be sanitized with confidence."""


@dataclass(frozen=True)
class SanitizationRule:
    name: str
    description: str
    version: str


@dataclass(frozen=True)
class SanitizationResult:
    sanitized: Mapping[str, Any]
    applied_rules: Sequence[str]


@dataclass(frozen=True)
class ArtifactSanitizationResult:
    """Sanitized artifact bytes and the content rules actually applied."""

    content: bytes
    applied_rules: Sequence[str]


# Key names are normalized before matching, so client_secret, client-secret,
# clientSecret and ClientSecret are treated alike. This deliberately favors
# redaction over preserving a possibly sensitive field.
_SENSITIVE_KEY_MARKERS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "privatekey",
    "apikey",
    "accesskey",
    "credential",
    "authorization",
    "cookie",
    "sessionid",
    "connectionstring",
)

# High-confidence patterns that must not remain under an innocuous-looking
# key. This is not a complete detector for arbitrary secrets; the sanitizer
# is intentionally scoped and will fail if one of these patterns remains.
_RECOGNIZABLE_SECRET_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
        r"\bgithub_pat_[A-Za-z0-9_]{20,}\b",
        r"\bgh[pousr]_[A-Za-z0-9]{20,}\b",
        r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b",
        r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}",
        r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^@\s/]+@",
    )
)

_MASK_KEYS = {"before_sensitive", "after_sensitive", "sensitive_values"}


def _normalize_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.casefold())


def _is_sensitive_key(key: str) -> bool:
    normalized = _normalize_key(key)
    return any(marker in normalized for marker in _SENSITIVE_KEY_MARKERS)


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ArtifactSanitizationError("JSON contains a duplicate object key")
        result[key] = value
    return result


def _reject_nonstandard_constant(value: str) -> None:
    raise ArtifactSanitizationError("JSON contains a non-standard numeric constant")


def _validate_terraform_document(name: str, document: Mapping[str, Any]) -> None:
    """Validate the outer envelope emitted by ``terraform show -json``.

    Terraform permits backward-compatible minor format additions, but callers
    must reject an unsupported major version. We intentionally validate only a
    small set of discriminating fields and leave unknown minor-version fields
    untouched for forward compatibility.
    """
    format_version = document.get("format_version")
    if not isinstance(format_version, str) or not re.fullmatch(
        r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", format_version
    ):
        raise ArtifactSanitizationError(
            "Terraform JSON requires a valid format_version in major.minor form"
        )

    major_text, _minor_text = format_version.split(".", maxsplit=1)
    if major_text != "1":
        raise ArtifactSanitizationError(
            f"Unsupported Terraform JSON format major version: {major_text}"
        )

    terraform_version = document.get("terraform_version")
    if not isinstance(terraform_version, str) or not terraform_version.strip():
        raise ArtifactSanitizationError(
            "Terraform JSON requires a non-empty terraform_version"
        )

    if name == "plan.json":
        if "values" in document:
            raise ArtifactSanitizationError(
                "state-shaped Terraform JSON supplied as plan.json"
            )
        if not isinstance(document.get("planned_values"), Mapping):
            raise ArtifactSanitizationError(
                "Terraform plan JSON requires planned_values to be an object"
            )
        if not isinstance(document.get("resource_changes"), list):
            raise ArtifactSanitizationError(
                "Terraform plan JSON requires resource_changes to be an array"
            )
    else:
        plan_only_fields = {
            "planned_values",
            "resource_changes",
            "resource_drift",
            "output_changes",
            "prior_state",
            "configuration",
        }
        present_plan_fields = sorted(plan_only_fields.intersection(document))
        if present_plan_fields:
            raise ArtifactSanitizationError(
                "plan-shaped Terraform JSON supplied as state.json: "
                + ", ".join(present_plan_fields)
            )
        if not isinstance(document.get("values"), Mapping):
            raise ArtifactSanitizationError(
                "Terraform state JSON requires values to be an object"
            )


def _mask_contains_true(mask: Any) -> bool:
    if mask is True:
        return True
    if mask is False or mask is None:
        return False
    if isinstance(mask, Mapping):
        return any(_mask_contains_true(value) for value in mask.values())
    if isinstance(mask, list):
        return any(_mask_contains_true(value) for value in mask)
    raise ArtifactSanitizationError("Terraform sensitivity mask has an invalid type")


def _apply_sensitivity_mask(value: Any, mask: Any, path: str) -> Any:
    """Apply Terraform's parallel sensitivity mask, failing on shape ambiguity."""
    if mask is True:
        return REDACTED
    if mask is False or mask is None:
        return value

    if isinstance(mask, Mapping):
        if not isinstance(value, Mapping):
            if _mask_contains_true(mask):
                raise ArtifactSanitizationError(
                    f"Terraform sensitivity mask does not match value at {path}"
                )
            return value
        result = dict(value)
        for key, child_mask in mask.items():
            if key not in value:
                if _mask_contains_true(child_mask):
                    raise ArtifactSanitizationError(
                        f"Terraform sensitivity mask references a missing value at {path}"
                    )
                continue
            result[key] = _apply_sensitivity_mask(
                value[key], child_mask, f"{path}.{key}"
            )
        return result

    if isinstance(mask, list):
        if not isinstance(value, list) or len(mask) != len(value):
            raise ArtifactSanitizationError(
                f"Terraform sensitivity mask does not match list at {path}"
            )
        return [
            _apply_sensitivity_mask(item, child_mask, f"{path}[{index}]")
            for index, (item, child_mask) in enumerate(zip(value, mask))
        ]

    raise ArtifactSanitizationError("Terraform sensitivity mask has an invalid type")


def _sanitize_json_node(node: Any, path: str = "$", *, inspect: bool = False) -> Any:
    if isinstance(node, dict):
        result: dict[str, Any] = {}
        for key, value in node.items():
            # Preserve Terraform mask structures exactly; their keys can
            # themselves be names such as "secret" and their values are booleans.
            if key in _MASK_KEYS or key in {"after_unknown", "before_unknown"}:
                result[key] = value
            elif _is_sensitive_key(key):
                result[key] = REDACTED
            else:
                result[key] = _sanitize_json_node(value, f"{path}.{key}", inspect=inspect)

        # Terraform plan JSON uses parallel masks for resource-change values.
        for side in ("before", "after"):
            mask_key = f"{side}_sensitive"
            if side in result and mask_key in result:
                result[side] = _apply_sensitivity_mask(
                    result[side], result[mask_key], f"{path}.{side}"
                )

        # Terraform show/state structures can expose values beside a mask.
        if "values" in result and "sensitive_values" in result:
            result["values"] = _apply_sensitivity_mask(
                result["values"], result["sensitive_values"], f"{path}.values"
            )

        # Terraform JSON output values commonly use {sensitive: true, value: ...}.
        if result.get("sensitive") is True and "value" in result:
            result["value"] = REDACTED
        return result

    if isinstance(node, list):
        return [
            _sanitize_json_node(value, f"{path}[{index}]", inspect=inspect)
            for index, value in enumerate(node)
        ]

    return node


def _contains_recognizable_secret(node: Any) -> bool:
    if isinstance(node, str):
        return any(pattern.search(node) for pattern in _RECOGNIZABLE_SECRET_PATTERNS)
    if isinstance(node, Mapping):
        return any(
            _contains_recognizable_secret(key)
            or _contains_recognizable_secret(value)
            for key, value in node.items()
        )
    if isinstance(node, list):
        return any(_contains_recognizable_secret(value) for value in node)
    return False


class Sanitizer:
    """Apply explicit, versioned metadata rules and Terraform JSON content rules.

    Metadata sanitization preserves the legacy API. Content sanitization is a
    separate operation that only accepts plan.json/state.json and requires an
    explicit ``terraform_json_content`` rule. Unknown or ambiguous content fails
    closed. The content rules redact sensitive-looking keys, honor Terraform's
    explicit sensitive-value masks, and reject certain recognizable credentials
    that remain. This is not a guarantee that all arbitrary secrets are found.
    """

    def __init__(self, rules: Sequence[SanitizationRule] | None = None) -> None:
        self._rules = list(rules or [])

    @property
    def rules(self) -> Sequence[SanitizationRule]:
        return tuple(self._rules)

    def sanitize_metadata(self, metadata: Mapping[str, Any] | None) -> SanitizationResult:
        if not isinstance(metadata, Mapping):
            # Preserve the legacy behavior: no sanitization is claimed.
            return SanitizationResult(sanitized={}, applied_rules=[])

        result: MutableMapping[str, Any] = dict(metadata)
        applied: list[str] = []
        for rule in self._rules:
            if rule.name == "strip_secrets":
                for key in list(result.keys()):
                    if key.lower() in {"secret", "password", "token"}:
                        result[key] = "<redacted>"
                applied.append(f"{rule.name}@{rule.version}")
            elif rule.name == "normalize_paths":
                root = result.get("root")
                if isinstance(root, str):
                    result["root"] = root.strip()
                applied.append(f"{rule.name}@{rule.version}")
            else:
                # Keep the existing metadata API's audit semantics.
                applied.append(f"{rule.name}@{rule.version}")

        return SanitizationResult(sanitized=result, applied_rules=applied)

    def sanitize_artifact_content(
        self,
        name: str,
        content: bytes,
    ) -> ArtifactSanitizationResult:
        """Sanitize JSON content for plan.json/state.json without touching disk.

        The caller must write the returned bytes to a distinct output artifact
        and only then create a manifest hashing those exact bytes.
        """
        if name not in {"plan.json", "state.json"}:
            raise ArtifactSanitizationError(
                "Content sanitization only supports plan.json and state.json"
            )
        if not isinstance(content, bytes):
            raise ArtifactSanitizationError("Artifact content must be bytes")

        rules = [rule for rule in self._rules if rule.name == TERRAFORM_JSON_CONTENT_RULE]
        if len(rules) != 1 or not isinstance(rules[0].version, str) or not rules[0].version.strip():
            raise ArtifactSanitizationError(
                "Exactly one versioned terraform_json_content rule is required"
            )

        try:
            decoded = content.decode("utf-8", errors="strict")
            document = json.loads(
                decoded,
                object_pairs_hook=_reject_duplicate_pairs,
                parse_constant=_reject_nonstandard_constant,
            )
        except ArtifactSanitizationError:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise ArtifactSanitizationError(
                "Artifact is not valid strict UTF-8 JSON"
            ) from exc

        if not isinstance(document, dict):
            raise ArtifactSanitizationError(
                "Terraform artifact JSON root must be an object"
            )

        _validate_terraform_document(name, document)
        sanitized_document = _sanitize_json_node(document)
        if _contains_recognizable_secret(sanitized_document):
            raise ArtifactSanitizationError(
                "Recognizable credential pattern remains after sanitization"
            )

        try:
            sanitized_bytes = canonical_json_bytes(sanitized_document)
        except (TypeError, ValueError) as exc:
            raise ArtifactSanitizationError(
                "Sanitized artifact could not be serialized"
            ) from exc

        return ArtifactSanitizationResult(
            content=sanitized_bytes,
            applied_rules=(f"{TERRAFORM_JSON_CONTENT_RULE}@{rules[0].version}",),
        )
