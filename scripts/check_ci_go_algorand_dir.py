#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Regression check for issue #1579.

`tools/cert-authenticate/run-in-docker.sh` falls back to a default
`$REPO_ROOT/../go-algorand` checkout when `GO_ALGORAND_DIR` is unset in its
environment (see that script's `GO_ALGORAND_DIR="${GO_ALGORAND_DIR:-...}"`
line). On a GitHub Actions runner there is no such sibling checkout, so any
Tier 2 workflow step that ends up invoking that script (directly, or via a
`make` target like `p2p-interop-soak-test`/`consensus-cluster-test` that
shells out to `ops/*/scripts/verify-soak.sh` /
`ops/*/scripts/consensus-conformance.sh`) MUST set `GO_ALGORAND_DIR` in its
own `env:` block to the path the workflow's own "Clone pinned go-algorand"
step cloned into (`${{ runner.temp }}/go-algorand-src`).

`p2p-consensus-soak.yml`'s Tier 2 step omitted this (unlike
`consensus-cluster.yml`'s equivalent step), so `cert-authenticate` fell back
to the nonexistent default path and failed with:

    error: no go-algorand git checkout found next to the repo.
           expected $REPO_ROOT/../go-algorand, or set GO_ALGORAND_DIR.

This script statically verifies every workflow that clones go-algorand for
Tier 2 also threads `GO_ALGORAND_DIR` through to the step that consumes it,
so this class of wiring bug can't silently recur.
"""
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"

# workflow file -> substring identifying the Tier 2 step that (transitively)
# invokes tools/cert-authenticate/run-in-docker.sh and therefore needs
# GO_ALGORAND_DIR wired through from the "Clone pinned go-algorand" step.
CONSUMER_STEPS = {
    "consensus-cluster.yml": "make consensus-cluster-test",
    "p2p-consensus-soak.yml": "make p2p-interop-soak-test",
}

CLONE_STEP_NAME = "Clone pinned go-algorand"


def find_step(steps, predicate):
    for step in steps:
        run = step.get("run", "")
        if predicate(step, run):
            return step
    return None


def check_workflow(filename: str, consumer_marker: str) -> list[str]:
    errors: list[str] = []
    path = WORKFLOWS_DIR / filename
    with path.open("r", encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)

    for job_name, job in doc.get("jobs", {}).items():
        steps = job.get("steps", [])

        clone_step = find_step(
            steps, lambda s, _run: s.get("name") == CLONE_STEP_NAME
        )
        if clone_step is None:
            # This workflow's job doesn't clone go-algorand at all — nothing
            # to check (e.g. a smoke-only job).
            continue
        clone_dir = (clone_step.get("env") or {}).get("GO_ALGORAND_DIR")
        if not clone_dir:
            errors.append(
                f"{filename}:{job_name}: '{CLONE_STEP_NAME}' step has no "
                "GO_ALGORAND_DIR in its env block"
            )
            continue

        consumer_step = find_step(
            steps, lambda _s, run, marker=consumer_marker: marker in run
        )
        if consumer_step is None:
            errors.append(
                f"{filename}:{job_name}: no step found running "
                f"'{consumer_marker}'"
            )
            continue

        consumer_dir = (consumer_step.get("env") or {}).get("GO_ALGORAND_DIR")
        if not consumer_dir:
            step_name = consumer_step.get("name", "<unnamed>")
            errors.append(
                f"{filename}:{job_name}: step '{step_name}' runs "
                f"'{consumer_marker}' (which shells out to "
                "tools/cert-authenticate/run-in-docker.sh) but does not set "
                "GO_ALGORAND_DIR in its own env block, so run-in-docker.sh "
                "falls back to the nonexistent $REPO_ROOT/../go-algorand "
                "default on a GitHub Actions runner (issue #1579)"
            )
        elif consumer_dir != clone_dir:
            step_name = consumer_step.get("name", "<unnamed>")
            errors.append(
                f"{filename}:{job_name}: step '{step_name}' sets "
                f"GO_ALGORAND_DIR={consumer_dir!r} but the "
                f"'{CLONE_STEP_NAME}' step cloned into {clone_dir!r} — "
                "these must match"
            )

    return errors


def main() -> int:
    all_errors: list[str] = []
    for filename, marker in CONSUMER_STEPS.items():
        all_errors.extend(check_workflow(filename, marker))

    if all_errors:
        print("CI wiring check failed (issue #1579 regression):", file=sys.stderr)
        for err in all_errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print("OK: GO_ALGORAND_DIR is correctly threaded through to every "
          "cert-authenticate-consuming Tier 2 step.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
