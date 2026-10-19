import hashlib
import subprocess
from unittest import result

import pytest

from evidence_engine.provenance import capture_provenance


def git(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def make_repository(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    git_init = subprocess.run(
        ["git", "init", str(repo)],
        check=True,
        capture_output=True,
        text=True,
    )

    git(repo, "config", "user.name", "EvidenceEngine Test")
    git(repo, "config", "user.email", "evidence-test@example.invalid")

    (repo / "README.md").write_text("test repository\n", encoding="utf-8")
    git(repo, "add", "README.md")
    git(repo, "commit", "-m", "initial test commit")

    git(repo, "remote", "add", "origin", "https://example.invalid/org/repo.git")

    return repo


def test_captures_commit_and_repository(tmp_path, monkeypatch):
    repo = make_repository(tmp_path)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.delenv("GITHUB_RUN_ID", raising=False)
    monkeypatch.delenv("EVIDENCE_TERRAFORM_VERSION", raising=False)

    result = capture_provenance(repo)

    assert result["commit_sha"] == git(repo, "rev-parse", "HEAD")
    assert result["repository"] == "https://example.invalid/org/repo.git"
    assert result["workflow_run_id"] == "not-captured"
    assert result["source"] == "local-claimed"


def test_hashes_provider_lock_file(tmp_path, monkeypatch):
    repo = make_repository(tmp_path)

    lock_contents = 'provider "registry.terraform.io/hashicorp/aws" {}\n'
    lock_path = repo / ".terraform.lock.hcl"

    # Write exact bytes so the test behaves consistently on Windows and Unix.
    lock_bytes = lock_contents.encode("utf-8")
    lock_path.write_bytes(lock_bytes)

    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)

    result = capture_provenance(repo)

    expected = hashlib.sha256(lock_bytes).hexdigest()
    assert result["provider_lock_sha256"] == expected


def test_requires_configured_remote(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    subprocess.run(
        ["git", "init", str(repo)],
        check=True,
        capture_output=True,
    )
    git(repo, "config", "user.name", "EvidenceEngine Test")
    git(repo, "config", "user.email", "evidence-test@example.invalid")
    (repo / "README.md").write_text("test\n", encoding="utf-8")
    git(repo, "add", "README.md")
    git(repo, "commit", "-m", "initial commit")

    with pytest.raises(ValueError, match="origin is not configured"):
        capture_provenance(repo)