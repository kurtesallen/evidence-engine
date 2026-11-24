"""Executable regression tests for the AWS E2E trust preflight gate."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest


WORKFLOW = (
    Path(__file__).resolve().parents[1]
    / ".github"
    / "workflows"
    / "evidence-e2e-integration.yml"
)

PREFLIGHT_STEP = (
    "Stage trust material and enforce deployment preflight"
)
CONSUMER_STEP = (
    "Verify tampering, trust policy, rollback, concurrency, acceptance, and replay"
)


def workflow_script(step_name: str) -> str:
    """Extract the literal Bash script from a named workflow step."""
    workflow = WORKFLOW.read_text(encoding="utf-8")
    lines = workflow.splitlines()

    step_marker = f"      - name: {step_name}"
    matches = [
        index for index, line in enumerate(lines)
        if line == step_marker
    ]
    assert len(matches) == 1, step_name

    start = matches[0]
    run_line = None

    for index in range(start + 1, len(lines)):
        line = lines[index]

        if line.startswith("      - name: "):
            break

        if line == "        run: |":
            run_line = index + 1
            break

    assert run_line is not None, step_name

    script_lines = []

    for line in lines[run_line:]:
        if line and not line.startswith("          "):
            break
        script_lines.append(line[10:] if line else "")

    assert script_lines
    return "\n".join(script_lines) + "\n"


@pytest.mark.skipif(
    os.name != "posix" or shutil.which("bash") is None,
    reason="Requires POSIX Bash and filesystem permissions",
)
def test_failed_preflight_prevents_consumer_execution(tmp_path: Path):
    """A failed preflight must not export trust or invoke consumption."""
    preflight = workflow_script(PREFLIGHT_STEP)
    consumer = workflow_script(CONSUMER_STEP)

    assert "python -m evidence_engine.trust_preflight" in preflight
    assert "python scripts/e2e_synthetic_aws.py consume" in consumer

    home = tmp_path / "home"
    home.mkdir(mode=0o700)

    workspace = tmp_path / "workspace"
    key_dir = workspace / "trust" / "keys"
    key_dir.mkdir(parents=True)

    (workspace / "trust" / "registry.json").write_text(
        '{"schema_version":"1.0","keys":[]}',
        encoding="utf-8",
    )
    (
        key_dir / "evidence-engine-signing-public.pem"
    ).write_text("invalid-public-key", encoding="utf-8")

    github_env = tmp_path / "github_env"
    github_env.touch()

    marker = tmp_path / "consumer-invoked"

    # Use a Bash function to intercept Python calls without AWS access.
    # The preflight fails; any attempted consumer call writes a marker.
    harness = f"""
python() {{
    if [[ "$1 $2" == "-m evidence_engine.trust_preflight" ]]; then
        return 42
    fi
    if [[ "$1 $2" == "scripts/e2e_synthetic_aws.py consume" ]]; then
        touch "$CONSUMER_MARKER"
        return 0
    fi
    return 99
}}

{preflight}
"""

    env = os.environ.copy()
    env.update(
        {
            "HOME": str(home),
            "GITHUB_ENV": str(github_env),
            "CONSUMER_MARKER": str(marker),
            "EVIDENCE_ENGINE_SIGNING_KEY_ID": "test-signing-key",
        }
    )
    env.pop("EVIDENCE_ENGINE_TRUST_REGISTRY_PATH", None)

    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail"],
        input=harness,
        cwd=workspace,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 42
    assert github_env.read_text(encoding="utf-8") == ""
    assert not marker.exists()

    # Simulate GitHub's next step with only successfully exported
    # environment values. The required registry path is absent.
    next_step = subprocess.run(
        ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail"],
        input=f"""
python() {{
    touch "$CONSUMER_MARKER"
    return 0
}}
{consumer}
""",
        cwd=workspace,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert next_step.returncode != 0
    assert not marker.exists()


@pytest.mark.skipif(
    os.name != "posix" or shutil.which("bash") is None,
    reason="Requires POSIX Bash and filesystem permissions",
)
def test_real_preflight_failure_blocks_consumer(tmp_path: Path):
    """Invalid deployed trust material must block real preflight."""
    import sys

    preflight = workflow_script(PREFLIGHT_STEP)
    consumer = workflow_script(CONSUMER_STEP)

    home = tmp_path / "home"
    home.mkdir(mode=0o700)

    workspace = tmp_path / "workspace"
    key_dir = workspace / "trust" / "keys"
    key_dir.mkdir(parents=True)

    # Deliberately malformed registry.
    (workspace / "trust" / "registry.json").write_text(
        "{invalid-json",
        encoding="utf-8",
    )

    (
        key_dir / "evidence-engine-signing-public.pem"
    ).write_text(
        "invalid-public-key",
        encoding="utf-8",
    )

    github_env = tmp_path / "github_env"
    github_env.touch()

    marker = tmp_path / "consumer-invoked"

    project_root = Path(__file__).resolve().parents[1]

    env = os.environ.copy()
    env.update(
        {
            "HOME": str(home),
            "GITHUB_ENV": str(github_env),
            "CONSUMER_MARKER": str(marker),
            "EVIDENCE_ENGINE_SIGNING_KEY_ID": "test-signing-key",
            "PREFLIGHT_PYTHON": sys.executable,
            "PYTHONPATH": str(project_root),
        }
    )

    env.pop("EVIDENCE_ENGINE_TRUST_REGISTRY_PATH", None)
    env.pop("BASH_ENV", None)

    # Execute the real production preflight module.
    # Intercept consumption to prevent any AWS interaction.
    harness = f"""
python() {{
    if [[ "$1 $2" == "-m evidence_engine.trust_preflight" ]]; then
        "$PREFLIGHT_PYTHON" "$@"
        return $?
    fi

    if [[ "$1 $2" == "scripts/e2e_synthetic_aws.py consume" ]]; then
        touch "$CONSUMER_MARKER"
        return 0
    fi

    return 99
}}

{preflight}
"""

    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail"],
        input=harness,
        cwd=workspace,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )

    diagnostics = result.stdout + result.stderr

    assert result.returncode == 1, diagnostics
    assert "FAIL:" in diagnostics, diagnostics
    assert "PASS: trust deployment validation succeeded" not in diagnostics

    assert github_env.read_text(encoding="utf-8") == ""
    assert not marker.exists()

    # Independently verify the consumer's defensive guard.
    next_step = subprocess.run(
        ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail"],
        input=f"""
python() {{
    touch "$CONSUMER_MARKER"
    return 0
}}

{consumer}
""",
        cwd=workspace,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )

    assert next_step.returncode != 0
    assert not marker.exists()


@pytest.mark.skipif(
    os.name != "posix" or shutil.which("bash") is None,
    reason="Requires POSIX Bash and filesystem permissions",
)
def test_valid_preflight_allows_consumer_execution(tmp_path: Path):
    """Valid staged trust must permit the consumer to execute."""
    import json
    import sys

    preflight = workflow_script(PREFLIGHT_STEP)
    consumer = workflow_script(CONSUMER_STEP)

    project_root = Path(__file__).resolve().parents[1]

    home = tmp_path / "home"
    home.mkdir(mode=0o700)

    workspace = tmp_path / "workspace"
    workspace.mkdir()

    # Copy the actual repository trust deployment material.
    shutil.copytree(
        project_root / "trust",
        workspace / "trust",
    )

    registry = json.loads(
        (workspace / "trust" / "registry.json").read_text(
            encoding="utf-8"
        )
    )

    authorized_keys = [
        key
        for key in registry["keys"]
        if key["status"] == "active"
        and "github-actions-claimed" in key["allowed_sources"]
    ]

    assert len(authorized_keys) == 1

    signing_key_id = authorized_keys[0]["key_id"]

    github_env = tmp_path / "github_env"
    github_env.touch()

    marker = tmp_path / "consumer-invoked"

    env = os.environ.copy()
    env.update(
        {
            "HOME": str(home),
            "GITHUB_ENV": str(github_env),
            "CONSUMER_MARKER": str(marker),
            "EVIDENCE_ENGINE_SIGNING_KEY_ID": signing_key_id,
            "PREFLIGHT_PYTHON": sys.executable,
            "PYTHONPATH": str(project_root),
        }
    )

    env.pop("EVIDENCE_ENGINE_TRUST_REGISTRY_PATH", None)
    env.pop("BASH_ENV", None)

    harness = f"""
python() {{
    if [[ "$1 $2" == "-m evidence_engine.trust_preflight" ]]; then
        "$PREFLIGHT_PYTHON" "$@"
        return $?
    fi

    return 99
}}

{preflight}
"""

    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail"],
        input=harness,
        cwd=workspace,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )

    diagnostics = result.stdout + result.stderr

    assert result.returncode == 0, diagnostics
    assert (
        "PASS: trust deployment validation succeeded"
        in diagnostics
    )
    assert not marker.exists()

    # Verify the workflow exported exactly one registry path.
    exported = github_env.read_text(
        encoding="utf-8"
    ).splitlines()

    assert len(exported) == 1

    name, separator, value = exported[0].partition("=")

    assert separator == "="
    assert name == "EVIDENCE_ENGINE_TRUST_REGISTRY_PATH"

    staged_registry = Path(value)

    assert staged_registry.is_absolute()
    assert staged_registry.is_file()
    assert staged_registry.is_relative_to(home)
    assert staged_registry.name == "registry.json"

    staged_root = staged_registry.parent
    staged_keys = staged_root / "keys"
    staged_public_key = (
        staged_keys / "evidence-engine-signing-public.pem"
    )

    assert staged_public_key.is_file()

    # Confirm private deployment permissions.
    assert staged_root.stat().st_mode & 0o777 == 0o700
    assert staged_keys.stat().st_mode & 0o777 == 0o700
    assert staged_registry.stat().st_mode & 0o777 == 0o600
    assert staged_public_key.stat().st_mode & 0o777 == 0o600

    # Confirm staging preserved the original trust material.
    assert staged_registry.read_bytes() == (
        workspace / "trust" / "registry.json"
    ).read_bytes()

    assert staged_public_key.read_bytes() == (
        workspace
        / "trust"
        / "keys"
        / "evidence-engine-signing-public.pem"
    ).read_bytes()

    # Simulate GitHub Actions propagating the exported environment.
    consumer_env = env.copy()
    consumer_env[name] = value

    next_step = subprocess.run(
        ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail"],
        input=f"""
python() {{
    if [[ "$1 $2" == "scripts/e2e_synthetic_aws.py consume" ]]; then
        printf '%s\\n' "$EVIDENCE_ENGINE_TRUST_REGISTRY_PATH" \
            > "$CONSUMER_MARKER"
        return 0
    fi

    return 99
}}

{consumer}
""",
        cwd=workspace,
        env=consumer_env,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )

    assert next_step.returncode == 0, (
        next_step.stdout + next_step.stderr
    )

    assert marker.is_file()
    assert marker.read_text(encoding="utf-8").strip() == value
