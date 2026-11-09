
import hashlib
import json
import subprocess
from pathlib import Path

import pytest

import evidence_engine.terraform_collect as collector
from evidence_engine.terraform_collect import (
    TerraformCollectionError,
    collect_terraform,
)


def make_root(tmp_path: Path, backend_type: str = "local") -> Path:
    root = tmp_path / "terraform"
    metadata = root / ".terraform"
    metadata.mkdir(parents=True)

    (metadata / "terraform.tfstate").write_text(
        json.dumps({
            "version": 3,
            "backend": {
                "type": backend_type,
                "config": {},
            },
        }),
        encoding="utf-8",
    )

    (root / ".terraform.lock.hcl").write_text(
        'provider "registry.terraform.io/hashicorp/aws" {}\n',
        encoding="utf-8",
    )

    return root


def terraform_documents(version="1.9.0", state_version=None):
    if state_version is None:
        state_version = version

    state = {
        "format_version": "1.0",
        "terraform_version": state_version,
        "values": {
            "root_module": {},
        },
    }

    plan = {
        "format_version": "1.2",
        "terraform_version": version,
        "planned_values": {
            "root_module": {},
        },
        "resource_changes": [],
        "prior_state": state,
    }

    return (
        json.dumps(plan).encode("utf-8"),
        json.dumps(state).encode("utf-8"),
    )


def install_fake_terraform(
    monkeypatch,
    plan_json: bytes | None = None,
    *,
    plan_error: Exception | None = None,
    show_error: Exception | None = None,
):
    if plan_json is None:
        plan_json, _ = terraform_documents()

    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))

        if command[1] == "plan":
            if plan_error is not None:
                raise plan_error

            return subprocess.CompletedProcess(
                command,
                0,
                b"",
                b"",
            )

        if command[1] == "show":
            if show_error is not None:
                raise show_error

            return subprocess.CompletedProcess(
                command,
                0,
                plan_json,
                b"",
            )

        raise AssertionError(f"Unexpected command: {command}")

    monkeypatch.setattr(
        "evidence_engine.terraform_collect.subprocess.run",
        fake_run,
    )

    return calls


def seed_existing_pair(output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    (output / "plan.json").write_bytes(b"old plan")
    (output / "state.json").write_bytes(b"old state")


def assert_no_published_pair(output: Path) -> None:
    assert not (output / "plan.json").exists()
    assert not (output / "state.json").exists()


def test_collect_terraform_writes_plan_and_state(
    tmp_path,
    monkeypatch,
):
    root = make_root(tmp_path)
    output = tmp_path / "evidence" / "capture"
    plan_json, state_json = terraform_documents()
    calls = install_fake_terraform(monkeypatch, plan_json)

    result = collect_terraform(root, output)

    assert result.terraform_version == "1.9.0"
    assert result.backend_type == "local"
    assert result.plan_path.read_bytes() == plan_json

    written_state = json.loads(
        result.state_path.read_text(encoding="utf-8")
    )
    expected_state = json.loads(state_json)

    assert written_state == expected_state

    # The collector uses the saved plan's prior_state.
    # It must not execute a separate "terraform state pull".
    assert len(calls) == 2
    assert calls[0][0][1] == "plan"
    assert calls[1][0][1] == "show"

    expected_digest = hashlib.sha256(
        (root / ".terraform.lock.hcl").read_bytes()
    ).hexdigest()

    assert result.provider_lock_sha256 == expected_digest


def test_collect_terraform_rejects_version_mismatch(
    tmp_path,
    monkeypatch,
):
    root = make_root(tmp_path)
    output = tmp_path / "evidence"

    plan_json, _ = terraform_documents(
        version="1.9.0",
        state_version="1.8.0",
    )

    install_fake_terraform(monkeypatch, plan_json)

    with pytest.raises(
        TerraformCollectionError,
        match="version mismatch",
    ):
        collect_terraform(root, output)

    assert_no_published_pair(output)


def test_collect_terraform_rejects_missing_prior_state(
    tmp_path,
    monkeypatch,
):
    root = make_root(tmp_path)
    output = tmp_path / "evidence"

    plan_json, _ = terraform_documents()
    plan_document = json.loads(plan_json)
    del plan_document["prior_state"]

    install_fake_terraform(
        monkeypatch,
        json.dumps(plan_document).encode("utf-8"),
    )

    with pytest.raises(
        TerraformCollectionError,
        match="prior_state",
    ):
        collect_terraform(root, output)

    assert_no_published_pair(output)


def test_collect_terraform_refuses_remote_backend_by_default(
    tmp_path,
):
    root = make_root(tmp_path, backend_type="s3")

    with pytest.raises(
        TerraformCollectionError,
        match="requires allow_remote_backend",
    ):
        collect_terraform(root, tmp_path / "evidence")


def test_collect_terraform_rejects_missing_backend_metadata(
    tmp_path,
):
    root = tmp_path / "terraform"
    root.mkdir()

    (root / ".terraform.lock.hcl").write_text(
        "lock\n",
        encoding="utf-8",
    )

    with pytest.raises(
        TerraformCollectionError,
        match="backend metadata is missing",
    ):
        collect_terraform(root, tmp_path / "evidence")


def test_collect_terraform_rejects_output_inside_root(
    tmp_path,
):
    root = make_root(tmp_path)

    with pytest.raises(
        TerraformCollectionError,
        match="outside the Terraform root",
    ):
        collect_terraform(root, root / "evidence")


@pytest.mark.parametrize(
    "plan_json",
    [
        # Duplicate top-level key.
        b"""
        {
          "format_version": "1.2",
          "terraform_version": "1.9.0",
          "terraform_version": "1.8.0",
          "planned_values": {"root_module": {}},
          "resource_changes": [],
          "prior_state": {
            "format_version": "1.0",
            "terraform_version": "1.9.0",
            "values": {"root_module": {}}
          }
        }
        """,
        # Non-standard JSON numeric constant.
        b"""
        {
          "format_version": "1.2",
          "terraform_version": "1.9.0",
          "planned_values": {
            "root_module": {},
            "unexpected": NaN
          },
          "resource_changes": [],
          "prior_state": {
            "format_version": "1.0",
            "terraform_version": "1.9.0",
            "values": {"root_module": {}}
          }
        }
        """,
        # Invalid UTF-8.
        b"\xff\xfe\xfa",
        # Valid JSON, but not an object.
        b"[]",
    ],
    ids=[
        "duplicate-key",
        "nonstandard-number",
        "invalid-utf8",
        "non-object-json",
    ],
)
def test_collect_terraform_rejects_non_strict_plan_json(
    tmp_path,
    monkeypatch,
    plan_json,
):
    root = make_root(tmp_path)
    output = tmp_path / "evidence"

    install_fake_terraform(monkeypatch, plan_json)

    with pytest.raises(TerraformCollectionError):
        collect_terraform(root, output)

    assert_no_published_pair(output)


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(
            lambda document: document.pop("planned_values"),
            id="missing-planned-values",
        ),
        pytest.param(
            lambda document: document.pop("resource_changes"),
            id="missing-resource-changes",
        ),
        pytest.param(
            lambda document: document.update(format_version="2.0"),
            id="unsupported-format-version",
        ),
        pytest.param(
            lambda document: document.update(terraform_version=""),
            id="empty-terraform-version",
        ),
    ],
)
def test_collect_terraform_rejects_invalid_plan_structure(
    tmp_path,
    monkeypatch,
    mutate,
):
    root = make_root(tmp_path)
    output = tmp_path / "evidence"

    plan_json, _ = terraform_documents()
    plan_document = json.loads(plan_json)
    mutate(plan_document)

    install_fake_terraform(
        monkeypatch,
        json.dumps(plan_document).encode("utf-8"),
    )

    with pytest.raises(TerraformCollectionError):
        collect_terraform(root, output)

    assert_no_published_pair(output)


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(
            lambda state: state.pop("values"),
            id="missing-values",
        ),
        pytest.param(
            lambda state: state.update(format_version="2.0"),
            id="unsupported-format-version",
        ),
        pytest.param(
            lambda state: state.update(terraform_version=""),
            id="empty-terraform-version",
        ),
    ],
)
def test_collect_terraform_rejects_invalid_prior_state(
    tmp_path,
    monkeypatch,
    mutate,
):
    root = make_root(tmp_path)
    output = tmp_path / "evidence"

    plan_json, _ = terraform_documents()
    plan_document = json.loads(plan_json)
    mutate(plan_document["prior_state"])

    install_fake_terraform(
        monkeypatch,
        json.dumps(plan_document).encode("utf-8"),
    )

    with pytest.raises(TerraformCollectionError):
        collect_terraform(root, output)

    assert_no_published_pair(output)


@pytest.mark.parametrize("failed_command", ["plan", "show"])
def test_collect_terraform_handles_command_failure(
    tmp_path,
    monkeypatch,
    failed_command,
):
    root = make_root(tmp_path)
    output = tmp_path / "evidence"
    seed_existing_pair(output)

    error = subprocess.CalledProcessError(
        returncode=1,
        cmd=["terraform", failed_command],
        stderr=b"sensitive diagnostic output",
    )

    if failed_command == "plan":
        install_fake_terraform(
            monkeypatch,
            plan_error=error,
        )
    else:
        install_fake_terraform(
            monkeypatch,
            show_error=error,
        )

    with pytest.raises(
        TerraformCollectionError,
        match=f"Terraform command failed: {failed_command}",
    ) as exc_info:
        collect_terraform(root, output)

    # Sensitive subprocess output must not be included in the exception.
    assert "sensitive diagnostic output" not in str(exc_info.value)

    # Failure before publication must preserve the previous complete pair.
    assert (output / "plan.json").read_bytes() == b"old plan"
    assert (output / "state.json").read_bytes() == b"old state"


@pytest.mark.parametrize("failed_command", ["plan", "show"])
def test_collect_terraform_handles_command_timeout(
    tmp_path,
    monkeypatch,
    failed_command,
):
    root = make_root(tmp_path)
    output = tmp_path / "evidence"

    timeout = subprocess.TimeoutExpired(
        cmd=["terraform", failed_command],
        timeout=300,
    )

    if failed_command == "plan":
        install_fake_terraform(
            monkeypatch,
            plan_error=timeout,
        )
    else:
        install_fake_terraform(
            monkeypatch,
            show_error=timeout,
        )

    with pytest.raises(
        TerraformCollectionError,
        match=f"Terraform command timed out: {failed_command}",
    ):
        collect_terraform(root, output)

    assert_no_published_pair(output)


def test_collect_terraform_rejects_non_bytes_command_output(
    tmp_path,
    monkeypatch,
):
    root = make_root(tmp_path)
    output = tmp_path / "evidence"

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            0,
            "unexpected text output",
            "",
        )

    monkeypatch.setattr(
        "evidence_engine.terraform_collect.subprocess.run",
        fake_run,
    )

    with pytest.raises(
        TerraformCollectionError,
        match="unexpected output",
    ):
        collect_terraform(root, output)

    assert_no_published_pair(output)


def test_collect_terraform_removes_partial_pair_on_publish_failure(
    tmp_path,
    monkeypatch,
):
    root = make_root(tmp_path)
    output = tmp_path / "evidence"
    plan_json, _ = terraform_documents()

    install_fake_terraform(monkeypatch, plan_json)

    real_replace = collector.os.replace

    def fail_state_publish(source, destination):
        source = Path(source)
        destination = Path(destination)

        if (
            source.name == "state.json"
            and destination == output / "state.json"
        ):
            raise OSError("simulated state publication failure")

        return real_replace(source, destination)

    monkeypatch.setattr(
        collector.os,
        "replace",
        fail_state_publish,
    )

    with pytest.raises(
        TerraformCollectionError,
        match="Unable to publish the Terraform evidence pair",
    ):
        collect_terraform(root, output)

    # The plan rename may have succeeded, but the incomplete pair
    # must not remain available to a downstream consumer.
    assert_no_published_pair(output)


def test_collect_terraform_replaces_old_pair_after_success(
    tmp_path,
    monkeypatch,
):
    root = make_root(tmp_path)
    output = tmp_path / "evidence"
    seed_existing_pair(output)

    plan_json, state_json = terraform_documents()
    install_fake_terraform(monkeypatch, plan_json)

    result = collect_terraform(root, output)

    assert result.plan_path.read_bytes() == plan_json
    assert json.loads(result.state_path.read_bytes()) == json.loads(state_json)
    assert result.plan_path.read_bytes() != b"old plan"
    assert result.state_path.read_bytes() != b"old state"


def make_symlink_or_skip(
    link: Path,
    target: Path,
    *,
    target_is_directory: bool = False,
) -> None:
    try:
        link.symlink_to(
            target,
            target_is_directory=target_is_directory,
        )
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"Symlinks are unavailable in this environment: {exc}")


@pytest.mark.parametrize(
    "symlink_target",
    ["terraform_root", "output_directory"],
)
def test_collect_terraform_rejects_symlinked_roots(
    tmp_path,
    symlink_target,
):
    root = make_root(tmp_path)
    output = tmp_path / "evidence"
    link = tmp_path / f"{symlink_target}-link"

    if symlink_target == "terraform_root":
        make_symlink_or_skip(
            link,
            root,
            target_is_directory=True,
        )
        root_arg = link
        output_arg = output
    else:
        output.mkdir()
        make_symlink_or_skip(
            link,
            output,
            target_is_directory=True,
        )
        root_arg = root
        output_arg = link

    with pytest.raises(TerraformCollectionError):
        collect_terraform(root_arg, output_arg)


def test_collect_terraform_rejects_symlinked_terraform_metadata_directory(
    tmp_path,
):
    root = make_root(tmp_path)
    real_metadata = tmp_path / "real-terraform-metadata"
    real_metadata.mkdir()

    (real_metadata / "terraform.tfstate").write_text(
        json.dumps({
            "version": 3,
            "backend": {
                "type": "local",
                "config": {},
            },
        }),
        encoding="utf-8",
    )

    metadata = root / ".terraform"
    import shutil
    shutil.rmtree(metadata)

    make_symlink_or_skip(
        metadata,
        real_metadata,
        target_is_directory=True,
    )

    with pytest.raises(TerraformCollectionError):
        collect_terraform(root, tmp_path / "evidence")


def test_collect_terraform_rejects_symlinked_backend_metadata_file(
    tmp_path,
):
    root = make_root(tmp_path)
    metadata = root / ".terraform"
    backend_file = metadata / "terraform.tfstate"

    real_backend_file = tmp_path / "real-terraform.tfstate"
    real_backend_file.write_text(
        json.dumps({
            "version": 3,
            "backend": {
                "type": "local",
                "config": {},
            },
        }),
        encoding="utf-8",
    )

    backend_file.unlink()
    make_symlink_or_skip(backend_file, real_backend_file)

    with pytest.raises(TerraformCollectionError):
        collect_terraform(root, tmp_path / "evidence")


def test_collect_terraform_rejects_symlinked_provider_lockfile(
    tmp_path,
):
    root = make_root(tmp_path)
    lockfile = root / ".terraform.lock.hcl"

    real_lockfile = tmp_path / "real-lockfile.hcl"
    real_lockfile.write_text(
        'provider "registry.terraform.io/hashicorp/aws" {}\n',
        encoding="utf-8",
    )

    lockfile.unlink()
    make_symlink_or_skip(lockfile, real_lockfile)

    with pytest.raises(TerraformCollectionError):
        collect_terraform(root, tmp_path / "evidence")



def test_collect_terraform_removes_injected_cli_arguments(
    tmp_path,
    monkeypatch,
):
    root = make_root(tmp_path)
    output = tmp_path / "evidence"
    plan_json, _ = terraform_documents()

    monkeypatch.setenv("TF_CLI_ARGS", "-lock=false")
    monkeypatch.setenv("TF_CLI_ARGS_plan", "-destroy")
    monkeypatch.setenv("TF_CLI_ARGS_show", "-json=false")

    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test-access-key")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test-secret-key")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "test-session-token")
    monkeypatch.setenv("EVIDENCE_ENGINE_TEST_SETTING", "preserve-me")

    calls = install_fake_terraform(monkeypatch, plan_json)

    collect_terraform(root, output)

    assert len(calls) == 2

    for command, kwargs in calls:
        assert "env" in kwargs
        subprocess_env = kwargs["env"]

        # No inherited Terraform CLI argument injection is permitted.
        assert "TF_CLI_ARGS" not in subprocess_env
        assert "TF_CLI_ARGS_plan" not in subprocess_env
        assert "TF_CLI_ARGS_show" not in subprocess_env

        # AWS credentials and unrelated settings must remain available.
        assert subprocess_env["AWS_ACCESS_KEY_ID"] == "test-access-key"
        assert subprocess_env["AWS_SECRET_ACCESS_KEY"] == "test-secret-key"
        assert subprocess_env["AWS_SESSION_TOKEN"] == "test-session-token"
        assert (
            subprocess_env["EVIDENCE_ENGINE_TEST_SETTING"]
            == "preserve-me"
        )

    assert calls[0][0][1] == "plan"
    assert calls[1][0][1] == "show"


def test_collect_terraform_does_not_mutate_parent_environment(
    tmp_path,
    monkeypatch,
):
    root = make_root(tmp_path)
    output = tmp_path / "evidence"
    plan_json, _ = terraform_documents()

    monkeypatch.setenv("TF_CLI_ARGS", "-lock=false")
    monkeypatch.setenv("TF_CLI_ARGS_plan", "-destroy")
    monkeypatch.setenv("TF_CLI_ARGS_show", "-json=false")

    original_environment = {
        "TF_CLI_ARGS": "-lock=false",
        "TF_CLI_ARGS_plan": "-destroy",
        "TF_CLI_ARGS_show": "-json=false",
    }

    install_fake_terraform(monkeypatch, plan_json)

    collect_terraform(root, output)

    for name, value in original_environment.items():
        assert collector.os.environ[name] == value
