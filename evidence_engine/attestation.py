"""Independently verify GitHub artifact attestations."""

import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


def require_subject_digest(
    subject: Path,
    results: list[dict[str, Any]],
) -> None:
    """Require an attestation to identify the exact subject bytes."""
    if subject.is_symlink() or not subject.is_file():
        raise ValueError("Attestation subject must be a regular file")

    try:
        expected = hashlib.sha256(subject.read_bytes()).hexdigest()
    except OSError as exc:
        raise ValueError("Cannot read attestation subject") from exc

    for item in results:
        if not isinstance(item, dict):
            continue

        verification = item.get("verificationResult")
        if not isinstance(verification, dict):
            continue

        statement = verification.get("statement")
        if not isinstance(statement, dict):
            continue

        subjects = statement.get("subject")
        if not isinstance(subjects, list):
            continue

        for entry in subjects:
            if not isinstance(entry, dict):
                continue

            digest = entry.get("digest")
            if not isinstance(digest, dict):
                continue

            actual = digest.get("sha256")
            if isinstance(actual, str) and actual.lower() == expected:
                return

    raise ValueError(
        "No independently verified attestation matches the subject digest"
    )


def verify_github_attestation(
    subject: Path,
    *,
    repository: str,
    signer_workflow: str,
    timeout: int = 30,
) -> dict[str, Any]:
    """Verify a GitHub artifact attestation and bind it to a subject.

    The repository and workflow are explicit consumer policy, not values
    learned from the attestation being verified.
    """
    if subject.is_symlink() or not subject.is_file():
        raise ValueError("Attestation subject must be a regular file")

    if not repository or not signer_workflow:
        raise ValueError(
            "Expected repository and signer workflow are required"
        )

    gh = shutil.which("gh")
    if gh is None:
        raise ValueError("GitHub CLI (gh) is required for attestation verification")

    command = [
        gh,
        "attestation",
        "verify",
        str(subject),
        "--repo",
        repository,
        "--signer-workflow",
        signer_workflow,
        "--format",
        "json",
    ]

    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("Attestation verification could not run") from exc

    if completed.returncode != 0:
        raise ValueError("GitHub attestation verification failed")

    try:
        results = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError(
            "Attestation verifier returned malformed JSON"
        ) from exc

    if not isinstance(results, list) or not results:
        raise ValueError("Attestation verifier returned no verification results")

    require_subject_digest(subject, results)

    return {
        "status": "independently_verified",
        "repository": repository,
        "signer_workflow": signer_workflow,
        "subject_sha256": hashlib.sha256(subject.read_bytes()).hexdigest(),
    }