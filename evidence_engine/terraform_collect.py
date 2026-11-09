
from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from evidence_engine.provenance import provider_lock_digest
from evidence_engine.sanitization import (
    ArtifactSanitizationError,
    _validate_terraform_document,
)


class TerraformCollectionError(RuntimeError):
    """Raised when Terraform evidence cannot be collected safely."""


@dataclass(frozen=True)
class TerraformCollection:
    plan_path: Path
    state_path: Path
    terraform_version: str
    provider_lock_sha256: str
    backend_type: str


def _reject_symlink(path: Path, label: str) -> None:
    """Reject a symbolic link without first resolving its target."""
    if path.is_symlink():
        raise TerraformCollectionError(
            f"{label} must not be a symbolic link"
        )


def _reject_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}

    for key, value in pairs:
        if key in result:
            raise TerraformCollectionError(
                "JSON contains a duplicate object key"
            )
        result[key] = value

    return result


def _reject_nonstandard_constant(value: str) -> None:
    raise TerraformCollectionError(
        "JSON contains a non-standard numeric constant"
    )


def _strict_json_loads(
    data: bytes | str,
    label: str,
) -> Mapping[str, Any]:
    try:
        if isinstance(data, bytes):
            data = data.decode("utf-8", errors="strict")

        document = json.loads(
            data,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonstandard_constant,
        )
    except TerraformCollectionError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TerraformCollectionError(
            f"{label} is not valid UTF-8 JSON"
        ) from exc

    if not isinstance(document, dict):
        raise TerraformCollectionError(
            f"{label} must be a JSON object"
        )

    return document


def _validate_document(
    name: str,
    document: Mapping[str, Any],
) -> None:
    try:
        _validate_terraform_document(name, document)
    except ArtifactSanitizationError as exc:
        raise TerraformCollectionError(
            f"Invalid Terraform {name}: {exc}"
        ) from exc


def _backend_type(terraform_root: Path) -> str:
    """Read initialized backend metadata without exposing its configuration."""
    metadata_path = (
        terraform_root / ".terraform" / "terraform.tfstate"
    )

    if not metadata_path.is_file():
        raise TerraformCollectionError(
            "Initialized Terraform backend metadata is missing; "
            "initialize the Terraform root separately before collection"
        )

    try:
        metadata = _strict_json_loads(
            metadata_path.read_bytes(),
            "Terraform backend metadata",
        )
    except OSError as exc:
        raise TerraformCollectionError(
            "Unable to read initialized Terraform backend metadata"
        ) from exc

    backend = metadata.get("backend")
    if not isinstance(backend, dict):
        raise TerraformCollectionError(
            "Terraform backend type cannot be established"
        )

    backend_type = backend.get("type")
    if not isinstance(backend_type, str) or not backend_type.strip():
        raise TerraformCollectionError(
            "Terraform backend type is missing"
        )

    return backend_type.strip()


def _run_terraform(
    command: list[str],
    *,
    terraform_root: Path,
    timeout_seconds: int,
) -> bytes:
    """Run a controlled Terraform command without inherited CLI arguments."""
    environment = os.environ.copy()

    # Prevent inherited variables from injecting additional Terraform
    # arguments into the collector's explicitly constructed commands.
    environment.pop("TF_CLI_ARGS", None)

    subcommand = command[1] if len(command) > 1 else None
    if subcommand:
        environment.pop(f"TF_CLI_ARGS_{subcommand}", None)

    try:
        result = subprocess.run(
            command,
            cwd=terraform_root,
            env=environment,
            check=True,
            capture_output=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise TerraformCollectionError(
            f"Terraform command timed out: {command[1]}"
        ) from exc
    except subprocess.CalledProcessError as exc:
        # Do not include stdout or stderr: either can contain sensitive data.
        raise TerraformCollectionError(
            f"Terraform command failed: {command[1]} "
            f"(exit code {exc.returncode})"
        ) from exc
    except OSError as exc:
        raise TerraformCollectionError(
            "Unable to execute the Terraform CLI"
        ) from exc

    if not isinstance(result.stdout, bytes):
        raise TerraformCollectionError(
            f"Terraform command returned unexpected output: {command[1]}"
        )

    return result.stdout


def _write_private_file(path: Path, content: bytes) -> None:
    """Write a private file atomically within its staging directory."""
    descriptor = -1
    temporary_path: Path | None = None

    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
        )
        temporary_path = Path(temporary_name)

        os.chmod(temporary_path, 0o600)

        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())

        os.replace(temporary_path, path)
        temporary_path = None
        os.chmod(path, 0o600)

    finally:
        if descriptor >= 0:
            os.close(descriptor)

        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _publish_artifact_pair(
    staging_dir: Path,
    output_dir: Path,
) -> tuple[Path, Path]:
    """Publish a validated plan/state pair, failing closed on partial failure.

    The two final renames are not a single filesystem transaction. Existing
    files are invalidated before publication, and both are removed if either
    replacement fails. A consumer should only use the pair after this function
    has returned successfully.
    """
    staged_plan = staging_dir / "plan.json"
    staged_state = staging_dir / "state.json"

    final_plan = output_dir / "plan.json"
    final_state = output_dir / "state.json"

    try:
        # Invalidate any prior evidence before publishing the new generation.
        final_plan.unlink(missing_ok=True)
        final_state.unlink(missing_ok=True)

        os.replace(staged_plan, final_plan)
        os.chmod(final_plan, 0o600)

        os.replace(staged_state, final_state)
        os.chmod(final_state, 0o600)

    except OSError as exc:
        # Never leave a partial or apparently complete pair after failure.
        final_plan.unlink(missing_ok=True)
        final_state.unlink(missing_ok=True)

        raise TerraformCollectionError(
            "Unable to publish the Terraform evidence pair"
        ) from exc

    return final_plan, final_state


def collect_terraform(
    terraform_root: Path,
    output_dir: Path,
    *,
    terraform_executable: str = "terraform",
    timeout_seconds: int = 300,
    allow_remote_backend: bool = False,
) -> TerraformCollection:
    """Collect a real Terraform plan and its prior-state snapshot.

    The state artifact is extracted from the saved plan's ``prior_state``
    field. This preserves the relationship between the state snapshot and
    the plan that Terraform generated from it.

    Raw plan and state JSON can contain sensitive values. The output
    directory and files are therefore created with restrictive permissions
    where the operating system supports them.

    Remote backends require explicit opt-in because planning can refresh
    remote state and acquire a backend lock.

    A plan without a usable prior_state snapshot is rejected. The collector
    does not fall back to a separate ``terraform state pull`` operation.
    """
    root_input = Path(terraform_root)
    output_input = Path(output_dir)

    # Reject the supplied paths before resolving them, so a symlink cannot
    # silently redirect collection or evidence publication.
    _reject_symlink(root_input, "Terraform root")
    _reject_symlink(output_input, "Evidence output directory")

    if not root_input.is_dir():
        raise TerraformCollectionError(
            "Terraform root must be an existing directory"
        )

    root = root_input.resolve()
    output = output_input.resolve()

    if output == root or root in output.parents:
        raise TerraformCollectionError(
            "Evidence output directory must be outside the Terraform root"
        )

    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")

    if (
        not isinstance(terraform_executable, str)
        or not terraform_executable.strip()
    ):
        raise ValueError(
            "terraform_executable must be a non-empty string"
        )

    terraform_metadata_dir = root / ".terraform"
    metadata_path = terraform_metadata_dir / "terraform.tfstate"
    lockfile = root / ".terraform.lock.hcl"

    _reject_symlink(
        terraform_metadata_dir,
        "Terraform metadata directory",
    )
    _reject_symlink(
        metadata_path,
        "Terraform backend metadata",
    )
    _reject_symlink(
        lockfile,
        "Terraform provider lockfile",
    )

    if not metadata_path.is_file():
        raise TerraformCollectionError(
            "Initialized Terraform backend metadata is missing; "
            "initialize the Terraform root separately before collection"
        )

    if not lockfile.is_file():
        raise TerraformCollectionError(
            "Terraform provider lockfile is required"
        )

    backend = _backend_type(root)

    if backend != "local" and not allow_remote_backend:
        raise TerraformCollectionError(
            f"Remote Terraform backend '{backend}' requires "
            "allow_remote_backend=True"
        )

    output.mkdir(parents=True, exist_ok=True)

    try:
        os.chmod(output, 0o700)
    except OSError:
        # Some platforms do not implement POSIX directory permissions.
        pass

    try:
        lock_digest = provider_lock_digest(root, required=True)
    except (OSError, ValueError) as exc:
        raise TerraformCollectionError(
            "Unable to calculate the Terraform provider lockfile digest"
        ) from exc

    # Keep the temporary plan and staging files outside the Terraform root.
    with tempfile.TemporaryDirectory(
        prefix=".terraform-evidence-",
        dir=output,
    ) as temporary_directory:
        temporary_root = Path(temporary_directory)
        binary_plan = temporary_root / "capture.tfplan"
        staging_dir = temporary_root / "staged"
        staging_dir.mkdir(mode=0o700)

        _run_terraform(
            [
                terraform_executable,
                "plan",
                "-input=false",
                "-lock-timeout=30s",
                f"-out={binary_plan}",
            ],
            terraform_root=root,
            timeout_seconds=timeout_seconds,
        )

        plan_json = _run_terraform(
            [
                terraform_executable,
                "show",
                "-json",
                str(binary_plan),
            ],
            terraform_root=root,
            timeout_seconds=timeout_seconds,
        )

        plan_document = _strict_json_loads(
            plan_json,
            "Terraform plan JSON",
        )
        _validate_document("plan.json", plan_document)

        prior_state = plan_document.get("prior_state")
        if not isinstance(prior_state, dict):
            raise TerraformCollectionError(
                "Terraform plan JSON has no usable prior_state snapshot"
            )

        try:
            state_json = json.dumps(
                prior_state,
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise TerraformCollectionError(
                "Terraform prior_state could not be serialized"
            ) from exc

        state_document = _strict_json_loads(
            state_json,
            "Terraform prior state JSON",
        )
        _validate_document("state.json", state_document)

        plan_version = plan_document["terraform_version"].strip()
        state_version = state_document["terraform_version"].strip()

        if plan_version != state_version:
            raise TerraformCollectionError(
                "Terraform version mismatch between plan.json and prior_state"
            )

        # Stage both artifacts before invalidating any previously published pair.
        _write_private_file(staging_dir / "plan.json", plan_json)
        _write_private_file(staging_dir / "state.json", state_json)

        plan_path, state_path = _publish_artifact_pair(
            staging_dir,
            output,
        )

    return TerraformCollection(
        plan_path=plan_path,
        state_path=state_path,
        terraform_version=plan_version,
        provider_lock_sha256=lock_digest,
        backend_type=backend,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Collect real Terraform plan and prior-state evidence"
    )
    parser.add_argument("--terraform-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--terraform-executable", default="terraform")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument(
        "--allow-remote-backend",
        action="store_true",
        help="Explicitly permit plan collection against a remote backend",
    )

    args = parser.parse_args()

    try:
        result = collect_terraform(
            args.terraform_root,
            args.output,
            terraform_executable=args.terraform_executable,
            timeout_seconds=args.timeout,
            allow_remote_backend=args.allow_remote_backend,
        )
    except (TerraformCollectionError, ValueError) as exc:
        parser.exit(1, f"Terraform collection failed: {exc}\n")

    print(f"Plan: {result.plan_path}")
    print(f"State: {result.state_path}")
    print(f"Terraform version: {result.terraform_version}")
    print(f"Provider lock SHA-256: {result.provider_lock_sha256}")
    print(f"Backend type: {result.backend_type}")


if __name__ == "__main__":
    main()
