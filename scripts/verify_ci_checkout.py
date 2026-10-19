"""Verify that CI context matches the checked-out Git commit."""

import subprocess
import sys

from evidence_engine.ci_provenance import capture_ci_context


def main() -> int:
    context = capture_ci_context()

    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )

    actual_sha = result.stdout.strip().lower()

    if actual_sha != context["commit_sha"]:
        print("FAIL: CI commit SHA does not match checked-out HEAD")
        return 1

    print("PASS: CI commit SHA matches checked-out HEAD")
    return 0


if __name__ == "__main__":
    sys.exit(main())