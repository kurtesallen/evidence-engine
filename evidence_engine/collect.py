"""Generate sample evidence for the local learning exercise."""

import argparse
import json
import subprocess
from pathlib import Path


def git_commit(root: Path) -> str:
    """Return the current commit or a clear local placeholder."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "UNCOMMITTED-LOCAL-EXERCISE"


def collect(output: Path) -> None:
    """Write deterministic sample artifacts to an output directory."""
    output.mkdir(parents=True, exist_ok=True)

    plan = {
        "format": "sample-terraform-plan-v1",
        "resource_changes": [
            {
                "address": "aws_s3_bucket.evidence",
                "actions": ["create"],
            }
        ],
        "note": "Synthetic teaching data; not an actual Terraform plan.",
    }

    state = {
        "format": "sample-terraform-state-v1",
        "resources": [],
        "note": "Synthetic teaching data; not an actual Terraform state.",
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
        git_commit(Path.cwd()) + "\n",
        encoding="utf-8",
    )

    (output / "version.txt").write_text(
        "evidence-engine-0.1.0\n",
        encoding="utf-8",
    )

    print(f"Sample evidence written to {output.resolve()}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate sample EvidenceEngine artifacts."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("evidence/artifacts"),
        help="Directory for generated sample artifacts.",
    )
    args = parser.parse_args()
    collect(args.output)


if __name__ == "__main__":
    main()