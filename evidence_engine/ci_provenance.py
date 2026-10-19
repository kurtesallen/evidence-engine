"""Capture and validate GitHub Actions provenance claims.

These checks establish consistency of supplied metadata. They do not
independently authenticate the workflow that supplied the metadata.
"""

import os
import re


SHA_RE = re.compile(r"^[0-9a-f]{40,64}$")
RUN_ID_RE = re.compile(r"^[0-9]+$")


def capture_ci_context() -> dict[str, str]:
    """Capture required GitHub Actions context or reject local execution."""
    if os.environ.get("GITHUB_ACTIONS", "").lower() != "true":
        raise ValueError("GitHub Actions environment is required")

    repository = os.environ.get("GITHUB_REPOSITORY", "").strip()
    commit_sha = os.environ.get("GITHUB_SHA", "").strip().lower()
    ref = os.environ.get("GITHUB_REF", "").strip()
    run_id = os.environ.get("GITHUB_RUN_ID", "").strip()
    workflow_ref = os.environ.get("GITHUB_WORKFLOW_REF", "").strip()

    if not repository or "/" not in repository:
        raise ValueError("Invalid GitHub repository")

    if not SHA_RE.fullmatch(commit_sha):
        raise ValueError("Invalid GitHub commit SHA")

    if not ref.startswith("refs/"):
        raise ValueError("Invalid GitHub ref")

    if not RUN_ID_RE.fullmatch(run_id):
        raise ValueError("Invalid GitHub run ID")

    if not workflow_ref:
        raise ValueError("Missing GitHub workflow reference")

    return {
        "repository": repository,
        "commit_sha": commit_sha,
        "ref": ref,
        "run_id": run_id,
        "workflow_ref": workflow_ref,
    }