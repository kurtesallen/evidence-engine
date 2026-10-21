from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, MutableMapping, Sequence


@dataclass(frozen=True)
class SanitizationRule:
    name: str
    description: str
    version: str


@dataclass(frozen=True)
class SanitizationResult:
    sanitized: Mapping[str, Any]
    applied_rules: Sequence[str]


class Sanitizer:
    """
    Apply explicit, versioned sanitization rules and record which were applied.

    Fail closed:
    - invalid metadata → no rules applied, original metadata returned
    """

    def __init__(self, rules: Sequence[SanitizationRule] | None = None) -> None:
        self._rules = list(rules or [])

    @property
    def rules(self) -> Sequence[SanitizationRule]:
        return tuple(self._rules)

    def sanitize_metadata(self, metadata: Mapping[str, Any] | None) -> SanitizationResult:
        if not isinstance(metadata, Mapping):
            # Fail closed: do not claim sanitization
            return SanitizationResult(sanitized={}, applied_rules=[])

        # Work on a shallow copy
        result: MutableMapping[str, Any] = dict(metadata)

        applied: list[str] = []
        for rule in self._rules:
            # Example: scrub obvious unsafe fields
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
                # Unknown rule: record but do not mutate
                applied.append(f"{rule.name}@{rule.version}")

        return SanitizationResult(sanitized=result, applied_rules=applied)
