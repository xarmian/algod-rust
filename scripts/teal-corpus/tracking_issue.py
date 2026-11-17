#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""The single tracking issue of the nightly TEAL corpus parity workflow
(issue #2372, epic #2364), following the discipline of
ops/mainnet-soak/file_issue.py: look for an already-open issue first, comment on
it instead of filing a second one, and let the first green run close it.

  tracking_issue.py fail  --repo R --body-file F --run-url URL [--dry-run]
  tracking_issue.py green --repo R --run-url URL [--dry-run]

`fail` creates the issue (labels conformance, avm, ...) or, when one is open,
comments the new body on it. `green` comments and closes the open issue, if any.
Real calls shell out to `gh` (the workflow sets GH_TOKEN); `--dry-run` prints
what would be done. Exit 0 on success, 2 on a `gh` failure.
"""
import argparse
import json
import subprocess
import sys

TITLE = "teal-corpus: nightly TEAL corpus parity check is failing"
LABELS = ["conformance", "avm", "bug", "ci", "phase:25", "team:a"]


def gh(args, run=subprocess.run):
    res = run(["gh"] + args, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args[:2])} failed ({res.returncode}): {res.stderr.strip()}")
    return res.stdout


def find_open(repo, run=subprocess.run):
    """The open tracking issue (exact title match), or None. Listed by label and
    matched client-side: the search index lags a just-created issue, a label
    listing does not."""
    out = gh(["issue", "list", "--repo", repo, "--state", "open", "--label", "conformance", "--label", "avm",
              "--json", "number,title", "--limit", "200"], run)
    for issue in json.loads(out or "[]"):
        if issue.get("title") == TITLE:
            return issue
    return None


def on_failure(repo, body, run_url, dry_run=False, run=subprocess.run):
    existing = find_open(repo, run)
    if existing:
        comment = f"Another run failed: {run_url}\n\n{body}"
        if dry_run:
            print(f"[dry-run] would comment on #{existing['number']}:\n{comment}")
        else:
            gh(["issue", "comment", str(existing["number"]), "--repo", repo, "--body", comment], run)
        return "commented", existing["number"]
    if dry_run:
        print(f"[dry-run] would create {TITLE!r} with labels {LABELS}:\n{body}")
        return "created", None
    args = ["issue", "create", "--repo", repo, "--title", TITLE, "--body", body]
    for label in LABELS:
        args += ["--label", label]
    url = gh(args, run).strip()
    return "created", url


def on_green(repo, run_url, dry_run=False, run=subprocess.run):
    existing = find_open(repo, run)
    if not existing:
        return "none", None
    comment = f"The nightly TEAL corpus parity check is green again: {run_url}. Closing."
    if dry_run:
        print(f"[dry-run] would comment and close #{existing['number']}:\n{comment}")
    else:
        gh(["issue", "comment", str(existing["number"]), "--repo", repo, "--body", comment], run)
        gh(["issue", "close", str(existing["number"]), "--repo", repo], run)
    return "closed", existing["number"]


def main(argv=None, run=subprocess.run):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fail")
    f.add_argument("--body-file", required=True)
    g = sub.add_parser("green")
    for p in (f, g):
        p.add_argument("--repo", required=True)
        p.add_argument("--run-url", required=True)
        p.add_argument("--dry-run", action="store_true")
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:
        return 2 if e.code else 0
    try:
        if a.cmd == "fail":
            with open(a.body_file, encoding="utf-8") as fh:
                body = fh.read()
            result = on_failure(a.repo, body, a.run_url, a.dry_run, run)
        else:
            result = on_green(a.repo, a.run_url, a.dry_run, run)
    except (OSError, RuntimeError, ValueError) as e:
        print(f"tracking_issue.py: {e}", file=sys.stderr)
        return 2
    print(f"tracking issue: {result[0]} {result[1] if result[1] is not None else ''}".rstrip())
    return 0


if __name__ == "__main__":
    sys.exit(main())
