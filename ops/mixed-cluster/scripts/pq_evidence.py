#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

"""Summarise a consensus-conformance.sh run directory into the PQ-workload
evidence JSON committed under docs/falcon/soak-data/ (issue #1958).

    pq_evidence.py RUN_DIR --backend "rust (default)" --commit <sha> \
        --command "<the command that produced RUN_DIR>" --out evidence.json

Reads RUN_DIR/workload.jsonl, blockcompare.jsonl and summary.json. `ok` is
true only when both PQ payments (via a Go node and via the Rust node) are
confirmed, every compared block is identical and complete, and the
conformance run passed.
"""
import argparse
import json
import os
import sys


def _jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def build(run_dir, backend, commit, command):
    pq_steps, workload = [], None
    for r in _jsonl(os.path.join(run_dir, "workload.jsonl")):
        if r.get("kind") == "workload_step" and r["op"].startswith("pq_pay_via_"):
            pq_steps.append({
                "op": r["op"], "outcome": r["outcome"], "ok": r["ok"], "round": r["round"], "txids": r["txids"],
                "submit_status": [s["status"] for s in r.get("submissions", [])],
            })
        elif r.get("kind") == "workload_summary":
            workload = {k: r[k] for k in ("steps", "confirmed", "rejected", "unexpected", "submit_divergence")}
    rounds = bad = 0
    for r in _jsonl(os.path.join(run_dir, "blockcompare.jsonl")):
        if r.get("kind") == "block_compare":
            rounds += 1
            bad += 0 if (r.get("identical") and r.get("complete")) else 1
    with open(os.path.join(run_dir, "summary.json"), encoding="utf-8") as f:
        c = json.load(f)
    conformance = {k: c[k] for k in ("result", "checks_total", "checks_failed") if k in c}
    ops = {s["op"]: s for s in pq_steps}
    ok = (
        all(ops.get(op, {}).get("ok") and ops[op]["outcome"] == "confirmed"
            for op in ("pq_pay_via_go-node-1", "pq_pay_via_rust-node-4"))
        and rounds > 0 and bad == 0 and conformance.get("result") == "PASS"
    )
    return {
        "ok": ok,
        "falcon_backend": backend,
        "commit": commit,
        "command": command,
        "pq_steps": pq_steps,
        "workload": workload,
        "block_compare": {"rounds": rounds, "not_identical_or_incomplete": bad},
        "conformance": conformance,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run_dir")
    ap.add_argument("--backend", required=True)
    ap.add_argument("--commit", required=True)
    ap.add_argument("--command", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    ev = build(a.run_dir, a.backend, a.commit, a.command)
    with open(a.out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(ev, f, indent=1)
        f.write("\n")
    print("ok" if ev["ok"] else "NOT ok", a.out)
    return 0 if ev["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
