from evidence_engine.sanitization import SanitizationRule, Sanitizer


def test_sanitizer_no_rules_returns_original_metadata():
    sanitizer = Sanitizer(rules=[])
    metadata = {"root": "/tmp", "files": ["a.txt"]}

    result = sanitizer.sanitize_metadata(metadata)

    assert result.sanitized == metadata
    assert result.applied_rules == []


def test_sanitizer_applies_strip_secrets_rule():
    rule = SanitizationRule(
        name="strip_secrets",
        description="Redact obvious secret fields.",
        version="1.0",
    )
    sanitizer = Sanitizer(rules=[rule])
    metadata = {"secret": "value", "password": "p", "token": "t", "other": "x"}

    result = sanitizer.sanitize_metadata(metadata)

    assert result.sanitized["secret"] == "<redacted>"
    assert result.sanitized["password"] == "<redacted>"
    assert result.sanitized["token"] == "<redacted>"
    assert result.sanitized["other"] == "x"
    assert result.applied_rules == ["strip_secrets@1.0"]


def test_sanitizer_fail_closed_on_invalid_metadata():
    sanitizer = Sanitizer()
    result = sanitizer.sanitize_metadata(metadata=None)

    assert result.sanitized == {}
    assert result.applied_rules == []
