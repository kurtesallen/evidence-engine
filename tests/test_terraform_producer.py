from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

import evidence_engine.terraform_producer as terraform_producer
from evidence_engine.agents.base import AgentResult
from evidence_engine.schema import REQUIRED_ARTIFACTS


def make_prepared_root(
    tmp_path: Path,
    *,
    include_plan: bool = False,
    include_state: bool = False,
) -> Path:
    """Create a prepared artifact root with required metadata files."""
    root = tmp_path / "prepared-artifacts"
    root.mkdir()

    (root / "commit.txt").write_text(
        "0123456789abcdef0123456789abcdef01234567\n",
        encoding="utf-8",
    )
    (root / "version.txt").write_text(
        "EvidenceEngine test fixture\n",
        encoding="utf-8",
    )

    if include_plan:
        (root / "plan.json").write_text("{}", encoding="utf-8")

    if include_state:
        (root / "state.json").write_text("{}", encoding="utf-8")

    return root


def make_collection(
    *,
    terraform_version: str = "1.9.0",
    provider_lock_sha256: str = "a" * 64,
) -> SimpleNamespace:
    return SimpleNamespace(
        plan_path=Path("/tmp/plan.json"),
        state_path=Path("/tmp/state.json"),
        terraform_version=terraform_version,
        provider_lock_sha256=provider_lock_sha256,
        backend_type="s3",
    )


def make_provenance() -> dict[str, str]:
    return {
        "repository": "https://github.com/example/evidence-engine",
        "commit_sha": "0123456789abcdef0123456789abcdef01234567",
        "workflow_run_id": "not-captured",
        "terraform_version": "caller-supplied-version",
        "provider_lock_sha256": "caller-supplied-digest",
        "source": "local-claimed",
    }


def make_producer(result: AgentResult | None = None) -> Mock:
    producer = Mock()
    producer.run.return_value = result or AgentResult(
        success=True,
        data={
            "receipt": {"bundle_digest": "b" * 64},
            "manifest_path": "/tmp/output/manifest.json",
        },
        error=None,
        audit={"stages": ["collection", "manifest", "signing"]},
    )
    return producer


def test_requires_existing_artifact_root(tmp_path: Path) -> None:
    missing_root = tmp_path / "does-not-exist"

    with pytest.raises(
        ValueError,
        match="existing directory",
    ):
        terraform_producer._validate_prepared_artifact_root(missing_root)


def test_rejects_symlink_artifact_root(tmp_path: Path) -> None:
    actual_root = make_prepared_root(tmp_path)
    symlink_root = tmp_path / "artifact-link"

    try:
        symlink_root.symlink_to(actual_root, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Directory symlinks are unavailable on this platform")

    with pytest.raises(
        ValueError,
        match="must not be a symlink",
    ):
        terraform_producer._validate_prepared_artifact_root(symlink_root)


@pytest.mark.parametrize(
    "missing_name",
    ["commit.txt", "version.txt"],
)
def test_rejects_missing_metadata_file(
    tmp_path: Path,
    missing_name: str,
) -> None:
    root = make_prepared_root(tmp_path)
    (root / missing_name).unlink()

    with pytest.raises(
        ValueError,
        match="missing required files",
    ):
        terraform_producer._validate_prepared_artifact_root(root)


def test_rejects_symlink_entry(tmp_path: Path) -> None:
    root = make_prepared_root(tmp_path)
    target = tmp_path / "target.txt"
    target.write_text("target", encoding="utf-8")

    try:
        (root / "unexpected.txt").symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("File symlinks are unavailable on this platform")

    with pytest.raises(
        ValueError,
        match="must not be a symlink",
    ):
        terraform_producer._validate_prepared_artifact_root(root)


def test_rejects_directory_entry(tmp_path: Path) -> None:
    root = make_prepared_root(tmp_path)
    (root / "unexpected-directory").mkdir()

    with pytest.raises(
        ValueError,
        match="regular file",
    ):
        terraform_producer._validate_prepared_artifact_root(root)


def test_rejects_unexpected_file(tmp_path: Path) -> None:
    root = make_prepared_root(tmp_path)
    (root / "unexpected.txt").write_text(
        "unexpected",
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="Artifact root must contain",
    ):
        terraform_producer._validate_prepared_artifact_root(root)


@pytest.mark.parametrize(
    ("include_plan", "include_state"),
    [
        (True, False),
        (False, True),
    ],
)
def test_rejects_partial_existing_collection(
    tmp_path: Path,
    include_plan: bool,
    include_state: bool,
) -> None:
    root = make_prepared_root(
        tmp_path,
        include_plan=include_plan,
        include_state=include_state,
    )

    with pytest.raises(
        ValueError,
        match="Artifact root must contain",
    ):
        terraform_producer._validate_prepared_artifact_root(root)


def test_accepts_fresh_prepared_artifact_root(tmp_path: Path) -> None:
    root = make_prepared_root(tmp_path)

    validated = terraform_producer._validate_prepared_artifact_root(root)

    assert validated == root.resolve()
    assert {path.name for path in validated.iterdir()} == {
        "commit.txt",
        "version.txt",
    }


def test_accepts_complete_existing_collection(tmp_path: Path) -> None:
    root = make_prepared_root(
        tmp_path,
        include_plan=True,
        include_state=True,
    )

    validated = terraform_producer._validate_prepared_artifact_root(root)

    assert validated == root.resolve()
    assert {path.name for path in validated.iterdir()} == REQUIRED_ARTIFACTS


def test_rejects_non_mapping_provenance(tmp_path: Path) -> None:
    root = make_prepared_root(tmp_path)

    with pytest.raises(
        TypeError,
        match="provenance must be a mapping",
    ):
        terraform_producer.run_terraform_producer(
            terraform_root=tmp_path,
            artifacts_root=root,
            provenance=[],  # type: ignore[arg-type]
        )


def test_rejects_non_string_provenance_values(tmp_path: Path) -> None:
    root = make_prepared_root(tmp_path)

    with pytest.raises(
        ValueError,
        match="keys and values must be strings",
    ):
        terraform_producer.run_terraform_producer(
            terraform_root=tmp_path,
            artifacts_root=root,
            provenance={
                "repository": "https://github.com/example/repo",
                "invalid": 123,  # type: ignore[dict-item]
            },
        )


def test_collection_receives_terraform_and_artifact_roots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = make_prepared_root(tmp_path)
    terraform_root = tmp_path / "terraform"
    terraform_root.mkdir()

    collection = make_collection()
    collect_mock = Mock(return_value=collection)
    producer = make_producer()
    factory_mock = Mock(return_value=producer)

    monkeypatch.setattr(
        terraform_producer,
        "collect_terraform",
        collect_mock,
    )
    monkeypatch.setattr(
        terraform_producer,
        "create_producer",
        factory_mock,
    )

    terraform_producer.run_terraform_producer(
        terraform_root=terraform_root,
        artifacts_root=root,
        provenance=make_provenance(),
        terraform_executable="terraform-custom",
        timeout_seconds=120,
        allow_remote_backend=True,
        trust_registry_path=Path("trust-registry.json"),
        output_dir=Path("output"),
        signing_mode="local",
        artifact_metadata={},
    )

    collect_mock.assert_called_once_with(
        terraform_root=terraform_root,
        output_dir=root.resolve(),
        terraform_executable="terraform-custom",
        timeout_seconds=120,
        allow_remote_backend=True,
    )


def test_collection_metadata_overrides_caller_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = make_prepared_root(tmp_path)
    terraform_root = tmp_path / "terraform"
    terraform_root.mkdir()

    observed_lock_digest = "c" * 64
    collection = make_collection(
        terraform_version="1.10.2",
        provider_lock_sha256=observed_lock_digest,
    )

    monkeypatch.setattr(
        terraform_producer,
        "collect_terraform",
        Mock(return_value=collection),
    )

    producer = make_producer()
    factory_mock = Mock(return_value=producer)

    monkeypatch.setattr(
        terraform_producer,
        "create_producer",
        factory_mock,
    )

    caller_provenance = make_provenance()

    terraform_producer.run_terraform_producer(
        terraform_root=terraform_root,
        artifacts_root=root,
        provenance=caller_provenance,
        trust_registry_path=Path("trust-registry.json"),
        output_dir=Path("output"),
        signing_mode="local",
        artifact_metadata={},
    )

    factory_kwargs = factory_mock.call_args.kwargs
    received_provenance = factory_kwargs["provenance"]

    assert received_provenance["terraform_version"] == "1.10.2"
    assert received_provenance["provider_lock_sha256"] == (
        observed_lock_digest
    )

    # The wrapper must not mutate the caller's original mapping.
    assert caller_provenance["terraform_version"] == (
        "caller-supplied-version"
    )
    assert caller_provenance["provider_lock_sha256"] == (
        "caller-supplied-digest"
    )


def test_passes_prepared_root_and_producer_options(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = make_prepared_root(tmp_path)
    terraform_root = tmp_path / "terraform"
    terraform_root.mkdir()

    monkeypatch.setattr(
        terraform_producer,
        "collect_terraform",
        Mock(return_value=make_collection()),
    )

    producer = make_producer()
    factory_mock = Mock(return_value=producer)

    monkeypatch.setattr(
        terraform_producer,
        "create_producer",
        factory_mock,
    )

    options: dict[str, Any] = {
        "trust_registry_path": Path("trust-registry.json"),
        "output_dir": Path("output"),
        "signing_mode": "kms",
        "kms_key_id": "test-signing-key",
        "aws_region": "us-east-1",
        "bundle_prefix": "evidence-engine/test",
        "artifact_metadata": {},
    }

    terraform_producer.run_terraform_producer(
        terraform_root=terraform_root,
        artifacts_root=root,
        provenance=make_provenance(),
        **options,
    )

    factory_mock.assert_called_once()

    factory_args = factory_mock.call_args.kwargs

    assert factory_args["artifacts_root"] == root.resolve()

    for key, value in options.items():
        assert factory_args[key] == value

    producer.run.assert_called_once_with()


def test_collection_failure_does_not_create_producer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = make_prepared_root(tmp_path)
    terraform_root = tmp_path / "terraform"
    terraform_root.mkdir()

    collection_error = RuntimeError("Terraform collection failed")

    collect_mock = Mock(side_effect=collection_error)
    factory_mock = Mock()

    monkeypatch.setattr(
        terraform_producer,
        "collect_terraform",
        collect_mock,
    )
    monkeypatch.setattr(
        terraform_producer,
        "create_producer",
        factory_mock,
    )

    with pytest.raises(
        RuntimeError,
        match="Terraform collection failed",
    ):
        terraform_producer.run_terraform_producer(
            terraform_root=terraform_root,
            artifacts_root=root,
            provenance=make_provenance(),
        )

    factory_mock.assert_not_called()


def test_returns_producer_result_unchanged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = make_prepared_root(tmp_path)
    terraform_root = tmp_path / "terraform"
    terraform_root.mkdir()

    expected_result = AgentResult(
        success=False,
        data=None,
        error="bundle-upload-failed",
        audit={
            "stage": "s3-upload",
            "exception_type": "RuntimeError",
        },
    )

    monkeypatch.setattr(
        terraform_producer,
        "collect_terraform",
        Mock(return_value=make_collection()),
    )

    producer = make_producer(result=expected_result)

    monkeypatch.setattr(
        terraform_producer,
        "create_producer",
        Mock(return_value=producer),
    )

    result = terraform_producer.run_terraform_producer(
        terraform_root=terraform_root,
        artifacts_root=root,
        provenance=make_provenance(),
    )

    assert result is expected_result
    producer.run.assert_called_once_with()


def test_collection_failure_leaves_producer_uninvoked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed collection must never proceed to sealing or publication."""
    root = make_prepared_root(tmp_path)
    terraform_root = tmp_path / "terraform"
    terraform_root.mkdir()

    producer = make_producer()
    factory_mock = Mock(return_value=producer)

    monkeypatch.setattr(
        terraform_producer,
        "collect_terraform",
        Mock(side_effect=ValueError("invalid Terraform plan")),
    )
    monkeypatch.setattr(
        terraform_producer,
        "create_producer",
        factory_mock,
    )

    with pytest.raises(ValueError, match="invalid Terraform plan"):
        terraform_producer.run_terraform_producer(
            terraform_root=terraform_root,
            artifacts_root=root,
            provenance=make_provenance(),
        )

    factory_mock.assert_not_called()
    producer.run.assert_not_called()
