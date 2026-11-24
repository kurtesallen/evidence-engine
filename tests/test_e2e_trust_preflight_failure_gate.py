"""Executable regression tests for independent E2E trust gates."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


PROJECT_ROOT = Path(__file__).resolve().parents[1]

WORKFLOW = (
    PROJECT_ROOT
    / ".github"
    / "workflows"
    / "evidence-e2e-integration.yml"
)

REGISTRY_ENV = "EVIDENCE_ENGINE_TRUST_REGISTRY_PATH"

KEY_A = "synthetic-rotation-key-a"
KEY_B = "synthetic-rotation-key-b"

STAGE_STEPS = {
    "produce": (
        "Stage producer trust material "
        "and enforce deployment preflight"
    ),
    "consume": (
        "Stage trust material "
        "and enforce deployment preflight"
    ),
}

EXECUTION_STEPS = {
    "produce": (
        "Create, sanitize, sign, and upload synthetic bundle"
    ),
    "consume": (
        "Verify tampering, trust policy, rollback, "
        "concurrency, acceptance, and replay"
    ),
}

pytestmark = pytest.mark.skipif(
    os.name != "posix" or shutil.which("bash") is None,
    reason="Requires POSIX Bash and filesystem permissions",
)


def workflow_script(step_name: str) -> str:
    """Extract the actual Bash script from a named workflow step."""
    lines = WORKFLOW.read_text(
        encoding="utf-8"
    ).splitlines()

    marker = f"      - name: {step_name}"

    matches = [
        index
        for index, line in enumerate(lines)
        if line == marker
    ]

    assert len(matches) == 1, step_name

    run_line = None

    for index in range(matches[0] + 1, len(lines)):
        line = lines[index]

        if line.startswith("      - name: "):
            break

        if line == "        run: |":
            run_line = index + 1
            break

    assert run_line is not None, step_name

    script = []

    for line in lines[run_line:]:
        if line and not line.startswith("          "):
            break

        script.append(line[10:] if line else "")

    assert script

    return "\n".join(script) + "\n"


def write_private(path: Path, content: bytes) -> None:
    path.write_bytes(content)
    path.chmod(0o600)


def public_key_bytes() -> bytes:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


class GateEnvironment:
    """Isolated synthetic deployment and execution environment."""

    def __init__(self, root: Path):
        self.root = root
        self.root.chmod(0o700)

        self.home = root / "home"
        self.workspace = root / "workspace"
        self.trust = self.workspace / "trust"
        self.keys = self.trust / "keys"

        for directory in (
            self.home,
            self.workspace,
            self.trust,
            self.keys,
        ):
            directory.mkdir(mode=0o700)
            directory.chmod(0o700)

        self.registry = self.trust / "registry.json"

        self.key_a = self.keys / "rotation-a.pem"
        self.key_b = self.keys / "rotation-b.pem"

        write_private(self.key_a, public_key_bytes())
        write_private(self.key_b, public_key_bytes())

        self.unreferenced_key = self.keys / "unreferenced.pem"

        write_private(
            self.unreferenced_key,
            public_key_bytes(),
        )

        self.registry_document = {
            "schema_version": "1.0",
            "keys": [
                {
                    "key_id": KEY_A,
                    "public_key": "keys/rotation-a.pem",
                    "status": "retired",
                    "allowed_sources": [
                        "github-actions-claimed"
                    ],
                },
                {
                    "key_id": KEY_B,
                    "public_key": "keys/rotation-b.pem",
                    "status": "active",
                    "allowed_sources": [
                        "github-actions-claimed"
                    ],
                },
            ],
        }

        self.write_registry()

        self.github_env = root / "github_env"
        self.github_env.touch()

        self.marker = root / "execution-marker"
        self.trace = root / "trust-gate-trace"

        self.env = os.environ.copy()

        for name in (
            REGISTRY_ENV,
            "BASH_ENV",
            "ENV",
        ):
            self.env.pop(name, None)

        self.env.update(
            {
                "HOME": str(self.home),
                "GITHUB_WORKSPACE": str(self.workspace),
                "GITHUB_ENV": str(self.github_env),
                "EXECUTION_MARKER": str(self.marker),
                "GATE_TRACE": str(self.trace),
                "EVIDENCE_ENGINE_SIGNING_KEY_ID": KEY_B,
                "GATE_PYTHON": sys.executable,
                "PYTHONPATH": str(PROJECT_ROOT),
                "GATE_SCENARIO": "real",
            }
        )

    def write_registry(self) -> None:
        write_private(
            self.registry,
            json.dumps(
                self.registry_document,
                sort_keys=True,
            ).encode("utf-8"),
        )

    def run_script(
        self,
        script: str,
        env: dict[str, str],
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                "bash",
                "--noprofile",
                "--norc",
                "-e",
                "-o",
                "pipefail",
            ],
            input=script,
            cwd=self.workspace,
            env=env,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )

    def stage(
        self,
        mode: str,
        scenario: str = "real",
    ) -> subprocess.CompletedProcess:
        env = self.env.copy()
        env["GATE_SCENARIO"] = scenario

        harness = r'''
python() {
    case "$1 $2" in
        "-m evidence_engine.trust_deployment")
            printf '%s\n' "deployment" >> "$GATE_TRACE"

            if [[ "$GATE_SCENARIO" == "stage-failure" ]]; then
                return 41
            fi

            "$GATE_PYTHON" "$@"

            if [[ "$GATE_SCENARIO" == "late-stage-failure" ]]; then
                return 43
            fi

            return 0
            ;;

        "-m evidence_engine.trust_preflight")
            printf '%s\n' "preflight" >> "$GATE_TRACE"

            if [[ "$GATE_SCENARIO" == "preflight-failure" ]]; then
                return 42
            fi

            "$GATE_PYTHON" "$@"
            return $?
            ;;

        "scripts/e2e_synthetic_aws.py produce"|"scripts/e2e_synthetic_aws.py consume")
            touch "$EXECUTION_MARKER"
            return 97
            ;;

        *)
            return 99
            ;;
    esac
}
'''

        return self.run_script(
            harness + workflow_script(STAGE_STEPS[mode]),
            env,
        )

    def execute(
        self,
        mode: str,
        registry: str | None = None,
    ) -> subprocess.CompletedProcess:
        env = self.env.copy()
        env["EXPECTED_MODE"] = mode

        if registry is not None:
            env[REGISTRY_ENV] = registry

        harness = r'''
python() {
    if [[ "$1" != "scripts/e2e_synthetic_aws.py" ]]; then
        return 99
    fi

    if [[ "$2" != "$EXPECTED_MODE" ]]; then
        return 98
    fi

    printf '%s\n' "$EVIDENCE_ENGINE_TRUST_REGISTRY_PATH" \
        > "$EXECUTION_MARKER"

    return 0
}
'''

        return self.run_script(
            harness + workflow_script(EXECUTION_STEPS[mode]),
            env,
        )

    def trace_lines(self) -> list[str]:
        if not self.trace.exists():
            return []

        return self.trace.read_text(
            encoding="utf-8"
        ).splitlines()

    def exported_lines(self) -> list[str]:
        return self.github_env.read_text(
            encoding="utf-8"
        ).splitlines()

    def assert_blocked(self, mode: str) -> None:
        assert self.exported_lines() == []
        assert not self.marker.exists()

        result = self.execute(mode)

        assert result.returncode != 0
        assert not self.marker.exists()


@pytest.fixture
def gate(tmp_path: Path) -> GateEnvironment:
    return GateEnvironment(tmp_path)


def diagnostics(result: subprocess.CompletedProcess) -> str:
    return result.stdout + result.stderr


@pytest.mark.parametrize("mode", ["produce", "consume"])
def test_staging_failure_blocks_execution(gate, mode):
    result = gate.stage(mode, "stage-failure")

    assert result.returncode == 41, diagnostics(result)
    assert gate.trace_lines() == ["deployment"]

    gate.assert_blocked(mode)


@pytest.mark.parametrize("mode", ["produce", "consume"])
def test_late_staging_failure_blocks_execution(gate, mode):
    """Complete-looking staged files must not authorize execution."""
    result = gate.stage(mode, "late-stage-failure")

    assert result.returncode == 43, diagnostics(result)
    assert gate.trace_lines() == ["deployment"]

    staged = list(
        gate.home.glob(
            "evidence-engine-trust.*/staged/registry.json"
        )
    )

    assert len(staged) == 1

    registry = staged[0]

    assert registry.read_bytes() == gate.registry.read_bytes()

    for source in (gate.key_a, gate.key_b):
        target = registry.parent / "keys" / source.name

        assert target.is_file()
        assert target.read_bytes() == source.read_bytes()

    gate.assert_blocked(mode)


@pytest.mark.parametrize("mode", ["produce", "consume"])
def test_preflight_failure_blocks_execution(gate, mode):
    result = gate.stage(mode, "preflight-failure")

    assert result.returncode == 42, diagnostics(result)

    assert gate.trace_lines() == [
        "deployment",
        "preflight",
    ]

    gate.assert_blocked(mode)


@pytest.mark.parametrize("mode", ["produce", "consume"])
def test_real_malformed_registry_blocks_execution(gate, mode):
    write_private(gate.registry, b"{invalid-json")

    result = gate.stage(mode)

    assert result.returncode == 1, diagnostics(result)
    assert "FAIL: trust deployment staging:" in diagnostics(result)

    assert gate.trace_lines() == ["deployment"]

    gate.assert_blocked(mode)


@pytest.mark.parametrize("mode", ["produce", "consume"])
def test_real_revoked_key_blocks_execution(gate, mode):
    gate.registry_document["keys"][1]["status"] = "revoked"
    gate.write_registry()

    result = gate.stage(mode)

    assert result.returncode == 1, diagnostics(result)
    assert "PASS: trust deployment staging succeeded" in result.stdout
    assert "FAIL:" in result.stderr

    assert gate.trace_lines() == [
        "deployment",
        "preflight",
    ]

    gate.assert_blocked(mode)


@pytest.mark.parametrize("mode", ["produce", "consume"])
def test_real_unauthorized_source_blocks_execution(gate, mode):
    gate.registry_document["keys"][1]["allowed_sources"] = [
        "local-claimed"
    ]

    gate.write_registry()

    result = gate.stage(mode)

    assert result.returncode == 1, diagnostics(result)
    assert "PASS: trust deployment staging succeeded" in result.stdout
    assert "FAIL:" in result.stderr

    assert gate.trace_lines() == [
        "deployment",
        "preflight",
    ]

    gate.assert_blocked(mode)


@pytest.mark.parametrize("mode", ["produce", "consume"])
def test_real_missing_expected_key_blocks_execution(gate, mode):
    gate.env["EVIDENCE_ENGINE_SIGNING_KEY_ID"] = "unknown-key"

    result = gate.stage(mode)

    assert result.returncode == 1, diagnostics(result)
    assert "PASS: trust deployment staging succeeded" in result.stdout
    assert "FAIL:" in result.stderr

    assert gate.trace_lines() == [
        "deployment",
        "preflight",
    ]

    gate.assert_blocked(mode)


@pytest.mark.parametrize("mode", ["produce", "consume"])
def test_real_missing_referenced_key_blocks_execution(gate, mode):
    gate.key_a.unlink()

    result = gate.stage(mode)

    assert result.returncode == 1, diagnostics(result)
    assert "FAIL: trust deployment staging:" in diagnostics(result)

    assert gate.trace_lines() == ["deployment"]

    gate.assert_blocked(mode)


@pytest.mark.parametrize("mode", ["produce", "consume"])
def test_valid_rotation_deployment_allows_execution(gate, mode):
    result = gate.stage(mode)

    assert result.returncode == 0, diagnostics(result)

    assert "PASS: trust deployment staging succeeded" in result.stdout

    assert (
        "PASS: trust deployment validation succeeded"
        in result.stdout
    )

    assert gate.trace_lines() == [
        "deployment",
        "preflight",
    ]

    assert not gate.marker.exists()

    exported = gate.exported_lines()

    assert len(exported) == 1

    name, separator, value = exported[0].partition("=")

    assert separator == "="
    assert name == REGISTRY_ENV

    registry = Path(value)

    assert registry.is_absolute()
    assert registry.is_relative_to(gate.home)
    assert registry.name == "registry.json"
    assert registry.parent.name == "staged"

    staged_root = registry.parent
    staged_keys = staged_root / "keys"

    assert registry.read_bytes() == gate.registry.read_bytes()

    assert {
        path.name
        for path in staged_keys.iterdir()
    } == {
        "rotation-a.pem",
        "rotation-b.pem",
    }

    for directory in (
        staged_root.parent,
        staged_root,
        staged_keys,
    ):
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700

    assert stat.S_IMODE(registry.stat().st_mode) == 0o600

    for source in (gate.key_a, gate.key_b):
        target = staged_keys / source.name

        assert target.read_bytes() == source.read_bytes()
        assert stat.S_IMODE(target.stat().st_mode) == 0o600

    execution = gate.execute(mode, registry=value)

    assert execution.returncode == 0, diagnostics(execution)
    assert gate.marker.is_file()

    assert gate.marker.read_text(
        encoding="utf-8"
    ).strip() == value


@pytest.mark.parametrize("mode", ["produce", "consume"])
@pytest.mark.parametrize("registry", [None, ""])
def test_execution_requires_exported_registry(gate, mode, registry):
    result = gate.execute(mode, registry=registry)

    assert result.returncode != 0
    assert not gate.marker.exists()
    assert gate.trace_lines() == []
    assert gate.exported_lines() == []
