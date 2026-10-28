
import pytest

from evidence_engine.ci_provenance import capture_ci_context


@pytest.fixture
def valid_ci_environment(monkeypatch):
    values = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": "example-org/evidence-engine",
        "GITHUB_SHA": "a" * 40,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_RUN_ID": "123456789",
        "GITHUB_RUN_NUMBER": "42",
        "GITHUB_RUN_ATTEMPT": "1",
        "EVIDENCE_ENGINE_STREAM_ID": "terraform-production",
        "GITHUB_WORKFLOW_REF": (
            "example-org/evidence-engine/.github/workflows/ci.yml@refs/heads/main"
        ),
    }

    for name, value in values.items():
        monkeypatch.setenv(name, value)


def test_captures_valid_ci_context(valid_ci_environment):
    result = capture_ci_context()

    assert result["repository"] == "example-org/evidence-engine"
    assert result["commit_sha"] == "a" * 40
    assert result["ref"] == "refs/heads/main"
    assert result["run_id"] == "123456789"
    assert result["run_number"] == "42"
    assert result["run_attempt"] == "1"
    assert result["stream_id"] == "terraform-production"


def test_rejects_local_execution(monkeypatch):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)

    with pytest.raises(ValueError, match="environment is required"):
        capture_ci_context()


def test_rejects_invalid_commit_sha(valid_ci_environment, monkeypatch):
    monkeypatch.setenv("GITHUB_SHA", "not-a-commit")

    with pytest.raises(ValueError, match="commit SHA"):
        capture_ci_context()


def test_rejects_missing_workflow_reference(valid_ci_environment, monkeypatch):
    monkeypatch.setenv("GITHUB_WORKFLOW_REF", "")

    with pytest.raises(ValueError, match="workflow reference"):
        capture_ci_context()


def _set_valid_ci_environment(monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "example-org/evidence-engine")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    monkeypatch.setenv("GITHUB_RUN_ID", "123456789")
    monkeypatch.setenv(
        "GITHUB_WORKFLOW_REF",
        "example-org/evidence-engine/.github/workflows/ci.yml@refs/heads/main",
    )
    monkeypatch.setenv("GITHUB_RUN_NUMBER", "42")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "2")
    monkeypatch.setenv(
        "EVIDENCE_ENGINE_STREAM_ID", "terraform-production"
    )


def test_capture_ci_context_includes_ordering_fields(monkeypatch):
    _set_valid_ci_environment(monkeypatch)

    context = capture_ci_context()

    assert context["run_number"] == "42"
    assert context["run_attempt"] == "2"
    assert context["stream_id"] == "terraform-production"


@pytest.mark.parametrize(
    ("variable", "value"),
    [
        ("GITHUB_RUN_NUMBER", ""),
        ("GITHUB_RUN_NUMBER", "0"),
        ("GITHUB_RUN_NUMBER", "-1"),
        ("GITHUB_RUN_NUMBER", "1.5"),
        ("GITHUB_RUN_NUMBER", "abc"),
        ("GITHUB_RUN_ATTEMPT", ""),
        ("GITHUB_RUN_ATTEMPT", "0"),
        ("GITHUB_RUN_ATTEMPT", "-1"),
        ("GITHUB_RUN_ATTEMPT", "1.5"),
        ("GITHUB_RUN_ATTEMPT", "abc"),
    ],
)
def test_capture_ci_context_rejects_invalid_ordering_fields(
    monkeypatch, variable, value
):
    _set_valid_ci_environment(monkeypatch)
    monkeypatch.setenv(variable, value)

    with pytest.raises(ValueError):
        capture_ci_context()

@pytest.mark.parametrize(
    "value",
    ["", " ", "../production", "production workspace", "x" * 129],
)
def test_capture_ci_context_rejects_invalid_stream_id(
    valid_ci_environment, monkeypatch, value
):
    monkeypatch.setenv("EVIDENCE_ENGINE_STREAM_ID", value)

    with pytest.raises(ValueError, match="stream ID"):
        capture_ci_context()


def test_capture_ci_context_requires_stream_id(
    valid_ci_environment, monkeypatch
):
    monkeypatch.delenv("EVIDENCE_ENGINE_STREAM_ID", raising=False)

    with pytest.raises(ValueError, match="stream ID"):
        capture_ci_context()
