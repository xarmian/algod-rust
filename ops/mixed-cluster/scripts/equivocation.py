#!/usr/bin/env python3
"""Equivocation detector for the algod-rust node's vote log (issue #471).

A node *equivocates* when it signs two different values at the same
consensus coordinate — the same `(round, period, step)`. That is the
safety violation a crash-recovery bug would produce: a node that comes
back up having forgotten it already voted, re-runs the step, and signs a
second, different value. go-algorand treats such a pair as a vote for
*any* value (`agreement/bundle.go`'s equivocation votes) precisely
because it is unforgeable evidence of misbehaviour.

The Rust node logs every vote it signs, immediately before handing it to
the pseudonode, as:

    attested to ProposalValue { original_period: Period(0),
        original_proposer: Address(<hex>), block_digest: Digest(<hex>),
        encoding_digest: Digest(<hex>) } at (<round>, <period>, <step>)

(`crates/core/algo-agreement/src/service.rs`, the `ActionType::Attest`
arm). Grouping those lines by coordinate and asserting one distinct value
per group is therefore a direct, implementation-side check for double
signing across a restart boundary — `docker logs` keeps the pre-restart
lines, so the scan spans the crash.

## Deliberately a superset

The check flags a divergence even when the second vote was never actually
broadcast (e.g. the process died between the log line and the send). A
false positive here still points at a real state-machine divergence and
is worth investigating; a false *negative* would make the whole
restart-rejoin suite vacuous, so the check errs the other way.

## Replay is not equivocation

Restarting replays the pending `Attest` action persisted in the crash DB,
so the *same* vote can legitimately be logged twice. Identical values at
one coordinate collapse into a single set entry and are not flagged —
matching go-algorand, which only counts a *pair of different* votes as an
equivocation (`agreement/voteTracker.go:160-210`).

Usage:
    equivocation.py rust-node-4.log [more.log ...]        # -> JSON
"""

import json
import re
import sys

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

ATTEST_RE = re.compile(
    r"attested to ProposalValue \{(?P<body>.*?)\} at "
    r"\((?P<round>\d+), (?P<period>\d+), (?P<step>[^)]+)\)"
)

# Both digests together identify the value being voted for. Including the
# encoding digest as well as the block digest means a node that voted for
# the same block under two different encodings is still caught.
DIGEST_RE = re.compile(r"(?:block_digest|encoding_digest): Digest\((?P<hex>[0-9a-fA-F]*)\)")


def scan(texts):
    """Return the equivocation report for an iterable of log texts."""
    votes = {}  # (round, period, step) -> {value fingerprint}
    total = 0

    for text in texts:
        for raw in text.splitlines():
            line = ANSI_RE.sub("", raw)
            match = ATTEST_RE.search(line)
            if not match:
                continue
            total += 1
            value = "|".join(d.group("hex").lower() for d in DIGEST_RE.finditer(match.group("body")))
            key = (
                int(match.group("round")),
                int(match.group("period")),
                match.group("step").strip(),
            )
            votes.setdefault(key, set()).add(value)

    conflicts = [
        {"round": r, "period": p, "step": s, "values": sorted(values)}
        for (r, p, s), values in sorted(votes.items())
        if len(values) > 1
    ]
    rounds = [k[0] for k in votes]

    return {
        "attests_scanned": total,
        "coordinates": len(votes),
        "first_round": min(rounds) if rounds else None,
        "last_round": max(rounds) if rounds else None,
        "equivocations": conflicts,
        "ok": not conflicts,
    }


def main(argv) -> int:
    texts = []
    for path in argv[1:]:
        with open(path, encoding="utf-8", errors="replace") as fh:
            texts.append(fh.read())
    print(json.dumps(scan(texts)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
