#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

"""Set or clear `Archival` in the Rust node's config.json (issue #1777).

    rust_config_merge.py CONFIG_JSON 0|1

With CONFIG_JSON `-` it filters stdin to stdout. `1` sets `"Archival": true`; `0` REMOVES the key.  Run on every start so a
config.json kept by REUSE_NETROOT=1 can never carry a stale value.  Every other
key is preserved.  With `0` and no config file nothing is created.
"""

import json
import os
import sys


def merge(existing, archival):
    cfg = dict(existing)
    if archival:
        cfg["Archival"] = True
    else:
        cfg.pop("Archival", None)
    return cfg


def main(argv):
    if len(argv) != 3 or argv[2] not in ("0", "1"):
        sys.stderr.write(__doc__)
        return 2
    path, archival = argv[1], argv[2] == "1"
    if path == "-":
        # stdin -> stdout, for callers whose paths a native python cannot open
        # (Git Bash on Windows).
        text = sys.stdin.read().strip()
        print(json.dumps(merge(json.loads(text) if text else {}, archival)))
        return 0
    existing = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            text = f.read().strip()
        if text:
            existing = json.loads(text)
    elif not archival:
        return 0
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(merge(existing, archival), f)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
