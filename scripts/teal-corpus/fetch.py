#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Fetch the ARC56Registry at a recorded commit (issue #2365, epic #2364).

  python3 -I scripts/teal-corpus/fetch.py [--ref main|<sha>] [--work-dir DIR]

The registry (https://github.com/scholtz/ARC56Registry) is untrusted third-party
data. It is fetched shallow (one commit, only the two program directories) into
its own empty directory `<work-dir>/registry/`; nothing from it is ever
executed, no git hooks/LFS filters run, and the resolved commit SHA is written
to `<work-dir>/fetch.json` (outside the checkout, so the registry cannot forge
it). Pin the SHA with `--ref <40-hex-sha>` or `TEAL_CORPUS_REGISTRY_REF`.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time

DEFAULT_REPO = "https://github.com/scholtz/ARC56Registry.git"
DEFAULT_WORK = "teal-corpus-work"
SPARSE_DIRS = ["approval-programs", "clear-programs"]
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def git(args, cwd, capture=False):
    env = dict(os.environ)
    env["GIT_LFS_SKIP_SMUDGE"] = "1"
    env["GIT_TERMINAL_PROMPT"] = "0"
    cmd = [
        "git",
        "-c", "core.hooksPath=" + os.devnull,
        "-c", "core.fsmonitor=false",
        "-c", "filter.lfs.required=false",
        "-c", "filter.lfs.smudge=",
        "-c", "filter.lfs.process=",
    ] + args
    res = subprocess.run(cmd, cwd=cwd, env=env, check=True,
                         stdout=subprocess.PIPE if capture else None, text=True)
    return res.stdout.strip() if capture else None


def fetch(repo, ref, work_dir, clean):
    work_dir = os.path.abspath(work_dir)
    checkout = os.path.join(work_dir, "registry")
    if os.path.exists(checkout):
        if not clean:
            raise SystemExit("error: %s already exists; pass --clean to replace it" % checkout)
        shutil.rmtree(checkout)
    os.makedirs(checkout)
    git(["init", "-q", "."], checkout)
    git(["remote", "add", "origin", repo], checkout)
    git(["sparse-checkout", "init", "--no-cone"], checkout)
    git(["sparse-checkout", "set"] + ["/" + d + "/" for d in SPARSE_DIRS], checkout)
    git(["fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", ref], checkout)
    git(["checkout", "-q", "--detach", "FETCH_HEAD"], checkout)
    sha = git(["rev-parse", "HEAD"], checkout, capture=True)
    if not SHA_RE.match(sha):
        raise SystemExit("error: unexpected resolved revision %r" % sha)
    info = {
        "repo": repo,
        "ref": ref,
        "registry_sha": sha,
        "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    with open(os.path.join(work_dir, "fetch.json"), "w", newline="\n") as f:
        json.dump(info, f, indent=2, sort_keys=True)
        f.write("\n")
    return info


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--repo", default=os.environ.get("TEAL_CORPUS_REGISTRY_REPO", DEFAULT_REPO))
    ap.add_argument("--ref", default=os.environ.get("TEAL_CORPUS_REGISTRY_REF", "main"),
                    help="branch, tag or full commit SHA (default: main)")
    ap.add_argument("--work-dir", default=os.environ.get("TEAL_CORPUS_WORK_DIR", DEFAULT_WORK))
    ap.add_argument("--clean", action="store_true", help="replace an existing checkout")
    args = ap.parse_args(argv)
    info = fetch(args.repo, args.ref, args.work_dir, args.clean)
    print("registry %s @ %s" % (info["repo"], info["registry_sha"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
