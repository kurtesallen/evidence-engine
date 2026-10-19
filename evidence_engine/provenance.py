"""Capture provenance claims for EvidenceEngine.

These values provide traceability, not independent authentication.
GitHub Actions claims require additional verification in a later stage.
"""

import hashlib
import os
import re
import subprocess
from pathlib import Path


SHA_RE = re.compile(r"^[0-9a-f]{40,64}$")


def git_output(repository: Path, *args: str) -> str:
    """Run a fixed Git command and return stripped stdout."""
    result = subprocess.run(
        ["git", "-C", str(repository), *args],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout.strip()


def capture_provenance(repository: Path) -> dict[str, str]:
    """Capture local provenance fields required by manifest v1.1."""
    repository = repository.resolve()

    commit_sha = git_output(repository, "rev-parse", "HEAD").lower()

    if not SHA_RE.fullmatch(commit_sha):
        raise ValueError("Git returned an invalid commit SHA")

    # Use the configured Git origin as a repository identity claim.
    try:
        remote = git_output(repository, "remote", "get-url", "origin")
    except subprocess.CalledProcessError:
        remote = ""

    if not remote:
        raise ValueError(
            "Git origin is not configured; set up the repository remote first"
        )

    workflow_run_id = os.environ.get("GITHUB_RUN_ID", "").strip()
    source = (
        "github-actions-claimed"
        if os.environ.get("GITHUB_ACTIONS", "").lower() == "true"
        else "local-claimed"
    )

    terraform_version = os.environ.get(
        "EVIDENCE_TERRAFORM_VERSION", ""
    ).strip()

    if not terraform_version:
        terraform_version = "not-captured"

    lock_path = repository / ".terraform.lock.hcl"

    if lock_path.is_file():
        lock_digest = hashlib.sha256(lock_path.read_bytes()).hexdigest()
    else:
        lock_digest = ""

    return {
        "repository": remote,
        "commit_sha": commit_sha,
        "workflow_run_id": workflow_run_id or "not-captured",
        "terraform_version": terraform_version,
        "provider_lock_sha256": lock_digest,
        "source": source,
    }