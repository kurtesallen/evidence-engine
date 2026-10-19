"""Generate sample evidence and claimed local provenance."""

import argparse
import json
import subprocess
from pathlib import Path


def git_value(root: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""


def collect(output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)

    plan = {
        "format": "sample-terraform-plan-v1",
        "resource_changes": [
            {
                "address": "aws_s3_bucket.evidence",
                "actions": ["create"],
            }
        ],
        "note": "Synthetic teaching data; not a real Terraform plan.",
    }

    state = {
        "format": "sample-terraform-state-v1",
        "resources": [],
        "note": "Synthetic teaching data; not a real Terraform state.",
    }

    (output / "plan.json").write_text(
        json.dumps(plan, indent=2) + "\n",
        encoding="utf-8",
    )
    (output / "state.json").write_text(
        json.dumps(state, indent=2) + "\n",
        encoding="utf-8",
    )
    (output / "commit.txt").write_text(
        (git_value(Path.cwd(), "rev-parse", "HEAD") or
         "UNCOMMITTED-LOCAL-EXERCISE") + "\n",
        encoding="utf-8",
    )
    (output / "version.txt").write_text(
        "evidence-engine-0.2.0\n",
        encoding="utf-8",
    )

    print(f"Sample evidence written to {output.resolve()}")


def provenance_for(root: Path) -> dict:
    commit = git_value(root, "rev-parse", "HEAD")

    remote = git_value(root, "remote", "get-url", "origin")
    if remote.endswith(".git"):
        remote = remote[:-4]

    return {
        "repository": remote or "LOCAL-UNCONFIGURED",
        "commit_sha": commit or "UNCOMMITTED-LOCAL-EXERCISE",
        "workflow_run_id": "LOCAL",
        "terraform_version": "NOT-CAPTURED",
        "provider_lock_sha256": "",
        "source": "local-claimed",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("evidence/artifacts"),
    )
    args = parser.parse_args()

    collect(args.output)


if __name__ == "__main__":
    main()