
"""Capture and validate GitHub Actions provenance claims.

These checks establish consistency of supplied metadata. They do not
independently authenticate the workflow that supplied the metadata.
"""

import os
import re


SHA_RE = re.compile(r"^[0-9a-f]{40,64}$")
RUN_ID_RE = re.compile(r"^[0-9]+$")
POSITIVE_INTEGER_RE = re.compile(r"^[1-9][0-9]*$")
STREAM_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")


def capture_ci_context() -> dict[str, str]:
    """Capture validated GitHub Actions metadata from the process environment."""
    if os.environ.get("GITHUB_ACTIONS", "").lower() != "true":
        raise ValueError("GitHub Actions environment is required")

    repository = os.environ.get("GITHUB_REPOSITORY", "").strip()
    commit_sha = os.environ.get("GITHUB_SHA", "").strip().lower()
    ref = os.environ.get("GITHUB_REF", "").strip()
    run_id = os.environ.get("GITHUB_RUN_ID", "").strip()
    workflow_ref = os.environ.get("GITHUB_WORKFLOW_REF", "").strip()
    run_number = os.environ.get("GITHUB_RUN_NUMBER", "").strip()
    run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "").strip()
    stream_id = os.environ.get("EVIDENCE_ENGINE_STREAM_ID", "").strip()

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

    if not POSITIVE_INTEGER_RE.fullmatch(run_number):
        raise ValueError("Invalid GitHub run number")

    if not POSITIVE_INTEGER_RE.fullmatch(run_attempt):
        raise ValueError("Invalid GitHub run attempt")

    if not STREAM_ID_RE.fullmatch(stream_id):
        raise ValueError("Invalid or missing EvidenceEngine stream ID")

    return {
        "repository": repository,
        "commit_sha": commit_sha,
        "ref": ref,
        "run_id": run_id,
        "workflow_ref": workflow_ref,
        "run_number": run_number,
        "run_attempt": run_attempt,
        "stream_id": stream_id,
    }
