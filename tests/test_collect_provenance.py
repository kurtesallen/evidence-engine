import hashlib

import pytest

from evidence_engine.collect import provenance_for


def test_provenance_for_hashes_explicit_terraform_root(
    tmp_path,
    monkeypatch,
):
    repository = tmp_path / "repository"
    terraform_root = repository / "infra" / "terraform"
    terraform_root.mkdir(parents=True)

    lock_contents = b'provider "registry.terraform.io/hashicorp/aws" {}\n'
    (terraform_root / ".terraform.lock.hcl").write_bytes(lock_contents)

    monkeypatch.setattr(
        "evidence_engine.collect.git_value",
        lambda root, *args: {
            ("rev-parse", "HEAD"): "a" * 40,
            ("remote", "get-url", "origin"): (
                "https://example.invalid/org/repo.git"
            ),
        }.get(args, ""),
    )

    result = provenance_for(
        repository,
        terraform_root=terraform_root,
        require_provider_lock=True,
    )

    assert result["provider_lock_sha256"] == hashlib.sha256(
        lock_contents
    ).hexdigest()
    assert result["commit_sha"] == "a" * 40
    assert result["repository"] == "https://example.invalid/org/repo"


def test_provenance_for_preserves_optional_lockfile_behavior(tmp_path):
    result = provenance_for(tmp_path)

    assert result["provider_lock_sha256"] == ""


def test_provenance_for_requires_terraform_root_when_lock_required(
    tmp_path,
):
    with pytest.raises(ValueError, match="Terraform root is required"):
        provenance_for(tmp_path, require_provider_lock=True)


def test_provenance_for_requires_lockfile_when_configured(
    tmp_path,
):
    terraform_root = tmp_path / "infra" / "terraform"
    terraform_root.mkdir(parents=True)

    with pytest.raises(ValueError, match="Required Terraform provider lockfile"):
        provenance_for(
            tmp_path,
            terraform_root=terraform_root,
            require_provider_lock=True,
        )