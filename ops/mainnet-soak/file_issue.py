#!/usr/bin/env python3

# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# Issue #1598 -- file (or comment on) a GitHub issue for a mainnet-soak
# halt verdict from `monitor.py`. Dedups against an already-open issue for
# the same round before ever creating a new one, exactly the same
# discipline `algod-issue-create` requires of a human filing one by hand.
#
# Only called for a `stuck` or `node_failure` verdict (`monitor.py`'s exit
# code 1) -- `source_outage` (exit 2) and `ok` (exit 0) never reach this
# script; see `monitor.py`'s module doc comment for why.
#
# `--dry-run` prints the exact title/labels/body this would file (or the
# exact comment it would post, if a dedup match is found) instead of
# calling `gh`, so the whole path is testable without touching the
# tracker. Real (non-dry-run) calls shell out to the `gh` CLI, which must
# already be authenticated (the workflow sets `GH_TOKEN`).

import argparse
import json
import re
import subprocess
import sys
from string import Formatter

DEDUP_LABEL = "mainnet-soak"
ISSUE_LABELS = ["bug", "sync", "conformance", "mainnet-soak", "algod:v5.0.2-stable", "effort:medium"]


class _SafeDict(dict):
    """Formatter mapping that leaves an unknown/missing placeholder as
    literal text (`{whatever}`) instead of raising -- a template field the
    caller didn't supply (e.g. `catchpoint_line` for a follow-phase halt)
    degrades visibly rather than crashing the filer mid-run."""

    def __missing__(self, key):
        return "{" + key + "}"


def render_template(template_path: str, fields: dict) -> str:
    with open(template_path, encoding="utf-8") as f:
        template = f.read()
    return Formatter().vformat(template, (), _SafeDict(fields))


def build_fields(verdict: dict, run_url: str, artifacts_url: str, log_excerpt: str, peer_url: str) -> dict:
    round_ = verdict.get("round")
    phase = verdict.get("phase") or "unknown"
    stalled_s = verdict.get("stalled_since_s")
    catchpoint_label = verdict.get("catchpoint_label")
    return {
        "round": round_ if round_ is not None else "unknown",
        "phase": phase,
        "stalled_minutes": f"{(stalled_s or 0) / 60.0:.1f}",
        "catchpoint_line": (
            f"\n- Catchpoint label: `{catchpoint_label}`" if catchpoint_label else ""
        ),
        "node_last_round": verdict.get("node_last_round", "unknown"),
        "node_time_since_last_round": verdict.get("node_time_since_last_round", "unknown"),
        "peer_last_round": verdict.get("peer_last_round", "unknown"),
        "log_excerpt": log_excerpt.strip() or "(no log excerpt captured)",
        "run_url": run_url,
        "artifacts_url": artifacts_url,
        "peer_url": peer_url,
        "repro_start": max((round_ or 1) - 1, 0),
        "catchpoint_label": catchpoint_label or "(unknown -- see the run's status JSONL)",
    }


def issue_title(round_) -> str:
    r = round_ if round_ is not None else "unknown"
    from datetime import date

    return f"sync: mainnet participation node halted at round {r} — nightly mainnet soak {date.today().isoformat()}"


def find_existing_issue(repo: str, round_) -> dict | None:
    """Search open issues labelled `mainnet-soak` for the dedup marker for
    this round. Returns the matching issue's {"number", "url"} or None."""
    if round_ is None:
        return None
    marker = f"mainnet-soak:round={round_}"
    result = subprocess.run(
        [
            "gh",
            "issue",
            "list",
            "--repo",
            repo,
            "--label",
            DEDUP_LABEL,
            "--state",
            "open",
            "--search",
            marker,
            "--json",
            "number,url,title,body",
            "--limit",
            "20",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"warning: gh issue list failed ({result.returncode}): {result.stderr}", file=sys.stderr)
        return None
    try:
        issues = json.loads(result.stdout or "[]")
    except json.JSONDecodeError:
        return None
    marker_re = re.compile(re.escape(marker))
    for issue in issues:
        if marker_re.search(issue.get("body") or ""):
            return {"number": issue["number"], "url": issue["url"]}
    return None


def file_or_comment(
    repo: str,
    template_path: str,
    verdict: dict,
    run_url: str,
    artifacts_url: str,
    log_excerpt: str,
    peer_url: str,
    dry_run: bool,
) -> dict:
    """Returns {"action": "created"|"commented"|"dry_run_create"|
    "dry_run_comment", "number": int|None, "url": str|None}."""
    round_ = verdict.get("round")
    fields = build_fields(verdict, run_url, artifacts_url, log_excerpt, peer_url)
    body = render_template(template_path, fields)
    title = issue_title(round_)

    existing = find_existing_issue(repo, round_)
    comment_body = (
        f"Another nightly mainnet soak run hit the same halt.\n\n"
        f"- Run: {run_url}\n"
        f"- Artifacts: {artifacts_url}\n"
        f"- Phase: {verdict.get('phase')}, stalled for "
        f"{fields['stalled_minutes']} minutes\n"
    )

    if existing:
        if dry_run:
            print(f"[dry-run] would COMMENT on #{existing['number']} ({existing['url']}):")
            print(comment_body)
            return {"action": "dry_run_comment", "number": existing["number"], "url": existing["url"]}
        subprocess.run(
            ["gh", "issue", "comment", str(existing["number"]), "--repo", repo, "--body", comment_body],
            check=True,
        )
        return {"action": "commented", "number": existing["number"], "url": existing["url"]}

    if dry_run:
        print(f"[dry-run] would CREATE issue:")
        print(f"  title: {title}")
        print(f"  labels: {', '.join(ISSUE_LABELS)}")
        print("  body:")
        print(body)
        return {"action": "dry_run_create", "number": None, "url": None}

    args = ["gh", "issue", "create", "--repo", repo, "--title", title, "--body", body]
    for label in ISSUE_LABELS:
        args += ["--label", label]
    result = subprocess.run(args, check=True, capture_output=True, text=True)
    url = result.stdout.strip()
    number = None
    m = re.search(r"/issues/(\d+)", url)
    if m:
        number = int(m.group(1))
    return {"action": "created", "number": number, "url": url}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="owner/repo")
    parser.add_argument("--verdict-json", required=True, help="path to monitor.py's --json-out")
    parser.add_argument("--template", required=True, help="path to issue_template.md")
    parser.add_argument("--run-url", required=True)
    parser.add_argument("--artifacts-url", required=True)
    parser.add_argument("--log-excerpt-file", default=None)
    parser.add_argument("--peer-url", default="(see workflow inputs)")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    with open(args.verdict_json, encoding="utf-8") as f:
        verdict = json.load(f)

    if verdict.get("status") not in ("stuck", "node_failure"):
        print(
            f"verdict status is {verdict.get('status')!r}, not stuck/node_failure -- "
            "nothing to file",
            file=sys.stderr,
        )
        return 0

    log_excerpt = ""
    if args.log_excerpt_file:
        try:
            with open(args.log_excerpt_file, encoding="utf-8", errors="replace") as f:
                log_excerpt = f.read()
        except OSError:
            pass

    result = file_or_comment(
        repo=args.repo,
        template_path=args.template,
        verdict=verdict,
        run_url=args.run_url,
        artifacts_url=args.artifacts_url,
        log_excerpt=log_excerpt,
        peer_url=args.peer_url,
        dry_run=args.dry_run,
    )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
