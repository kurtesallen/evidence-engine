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