import hashlib
import json
import subprocess

import pytest

from evidence_engine import attestation


def write_subject(tmp_path, content=b"manifest bytes"):
    subject = tmp_path / "manifest.json"
    subject.write_bytes(content)
    return subject


def valid_result(subject):
    digest = hashlib.sha256(subject.read_bytes()).hexdigest()
    return [
        {
            "verificationResult": {
                "statement": {
                    "subject": [
                        {
                            "name": "manifest.json",
                            "digest": {"sha256": digest},
                        }
                    ]
                }
            }
        }
    ]


def test_matching_subject_digest_passes(tmp_path):
    subject = write_subject(tmp_path)

    attestation.require_subject_digest(
        subject,
        valid_result(subject),
    )


def test_mismatched_subject_digest_fails(tmp_path):
    subject = write_subject(tmp_path)
    results = valid_result(subject)
    results[0]["verificationResult"]["statement"]["subject"][0][
        "digest"
    ]["sha256"] = "0" * 64

    with pytest.raises(ValueError, match="subject digest"):
        attestation.require_subject_digest(subject, results)


@pytest.mark.parametrize(
    "results",
    [
        [],
        [{}],
        [{"verificationResult": {}}],
        [{"verificationResult": {"statement": {"subject": []}}}],
        [{"verificationResult": {"statement": {"subject": "invalid"}}}],
    ],
)
def test_malformed_or_missing_subject_results_fail(tmp_path, results):
    subject = write_subject(tmp_path)

    with pytest.raises(ValueError, match="subject digest"):
        attestation.require_subject_digest(subject, results)


def test_symlink_subject_is_rejected(tmp_path):
    original = write_subject(tmp_path, b"original")
    link = tmp_path / "link.json"

    try:
        link.symlink_to(original)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation is unavailable on this system")

    with pytest.raises(ValueError, match="regular file"):
        attestation.require_subject_digest(link, valid_result(original))


def test_github_verification_passes_and_returns_subject_digest(
    tmp_path, monkeypatch
):
    subject = write_subject(tmp_path)
    results = valid_result(subject)

    monkeypatch.setattr(attestation.shutil, "which", lambda _: "gh")

    def fake_run(command, **kwargs):
        assert command[1:4] == [
            "attestation",
            "verify",
            str(subject),
        ]
        assert "--repo" in command
        assert "--signer-workflow" in command
        assert "--format" in command
        assert kwargs["timeout"] == 30

        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout=json.dumps(results),
            stderr="",
        )

    monkeypatch.setattr(attestation.subprocess, "run", fake_run)

    result = attestation.verify_github_attestation(
        subject,
        repository="example-org/evidence-engine",
        signer_workflow=(
            "example-org/evidence-engine/.github/workflows/ci.yml"
        ),
    )

    assert result == {
        "status": "independently_verified",
        "repository": "example-org/evidence-engine",
        "signer_workflow": (
            "example-org/evidence-engine/.github/workflows/ci.yml"
        ),
        "subject_sha256": hashlib.sha256(
            subject.read_bytes()
        ).hexdigest(),
    }


def test_github_verification_fails_without_gh(tmp_path, monkeypatch):
    subject = write_subject(tmp_path)
    monkeypatch.setattr(attestation.shutil, "which", lambda _: None)

    with pytest.raises(ValueError, match="CLI.*required"):
        attestation.verify_github_attestation(
            subject,
            repository="example-org/evidence-engine",
            signer_workflow="example-org/evidence-engine/.github/workflows/ci.yml",
        )


def test_github_verification_rejects_command_failure(
    tmp_path, monkeypatch
):
    subject = write_subject(tmp_path)
    monkeypatch.setattr(attestation.shutil, "which", lambda _: "gh")

    monkeypatch.setattr(
        attestation.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=args[0],
            returncode=1,
            stdout="",
            stderr="verification failed",
        ),
    )

    with pytest.raises(ValueError, match="verification failed"):
        attestation.verify_github_attestation(
            subject,
            repository="example-org/evidence-engine",
            signer_workflow="example-org/evidence-engine/.github/workflows/ci.yml",
        )


def test_github_verification_rejects_malformed_json(
    tmp_path, monkeypatch
):
    subject = write_subject(tmp_path)
    monkeypatch.setattr(attestation.shutil, "which", lambda _: "gh")

    monkeypatch.setattr(
        attestation.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=args[0],
            returncode=0,
            stdout="{not-json",
            stderr="",
        ),
    )

    with pytest.raises(ValueError, match="malformed JSON"):
        attestation.verify_github_attestation(
            subject,
            repository="example-org/evidence-engine",
            signer_workflow="example-org/evidence-engine/.github/workflows/ci.yml",
        )
