#!/usr/bin/env python3

# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

"""node.log analysis for the nightly mainnet node soak.

Two independent, pure, stdlib-only pieces (both tolerate a missing or
truncated log -- a field that cannot be derived is `None`, never an error):

* `parse_phase_log()` -- turns the node's own sync log lines into a
  contiguous timeline of the fast-catchup phases (`phase_seconds_detailed`
  in summary.json). The status-counter based `phase_seconds` in
  `monitor.summarize()` can only see time during which a `/v2/status`
  counter moves, which left ~2500 s of a ~3850 s catchup as "unattributed".
  Every segment below is the difference of two adjacent log timestamps (or
  an `elapsed_s=` the node itself logged), so the segments sum exactly to
  the covered window.

* `scan_log()` -- scans for broken-state signatures. "hard" signatures fail
  the job; "warn" signatures are surfaced but do not; "noise" signatures
  are known-benign mainnet gossip chatter, counted only so a change in
  volume is visible.
"""

import datetime
import json
import re
import sys

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
LINE_RE = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d+)?Z\s+([A-Z]+)\s+(.*)$")
TRANSITION_RE = re.compile(r"sync state transition from=(.+?) to=(.+?)\s*$")
FLOAT = r"([0-9]+(?:\.[0-9]+)?(?:e[+-]?[0-9]+)?)"
STAGED_RE = re.compile(r"pending-hashes staged elapsed_s=" + FLOAT)
INDEXED_RE = re.compile(r"pending-hashes indexed elapsed_s=" + FLOAT)
TRIE_DONE_RE = re.compile(r"trie rebuild complete.*?total_elapsed_s=" + FLOAT)
ELAPSED_SECS_RE = re.compile(r"elapsed_secs=" + FLOAT)
SYNC_ELAPSED_RE = re.compile(r"catchpoint sync completed elapsed=" + FLOAT)

S_DOWNLOAD = "Downloading ledger snapshot"
S_IMPORT = "Importing ledger into database"
S_VERIFY = "Verifying ledger integrity"
S_LOOKBACK = "Downloading lookback blocks"
S_REPLAY = "Replaying blocks"
S_DONE = "Sync complete"

# A WAL checkpoint belongs to the chain that follows "Sync complete" only if
# it starts within this many seconds of the previous link's end.
CHAIN_SLACK_S = 15.0


def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s)


def parse_line(raw: str):
    """(epoch_seconds, level, message) for a tracing line, else None."""
    m = LINE_RE.match(strip_ansi(raw).rstrip("\n"))
    if not m:
        return None
    base, frac, level, msg = m.groups()
    try:
        dt = datetime.datetime.strptime(base, "%Y-%m-%dT%H:%M:%S").replace(
            tzinfo=datetime.timezone.utc
        )
    except ValueError:
        return None
    ts = dt.timestamp() + (float(frac) if frac else 0.0)
    return ts, level, msg


def _r(v):
    return None if v is None else round(v, 1)


def _diff(a, b):
    return None if a is None or b is None else b - a


def parse_phase_log(lines) -> dict:
    """Derive `phase_seconds_detailed` from node.log lines (an iterable of
    str). Never raises; unknown pieces are `None`.

    Segments (all seconds, rounded to 0.1):
      startup_s                 node's first log line -> catchup request
      earlier_attempts_s        first request -> start of the final attempt
                                (0 unless the sync restarted)
      download_s                Downloading ledger snapshot -> Importing
      import_s                  Importing -> Verifying
      verify_s                  Verifying -> Downloading lookback blocks, split
        verify_staging_s / verify_indexing_s / verify_trie_build_s /
        verify_tail_s           (node-logged trie-rebuild elapsed_s markers;
                                tail = verify end minus the rebuild total)
      lookback_download_s       Downloading lookback blocks -> Replaying
      replay_s                  Replaying -> first post-sync WAL checkpoint
      post_sync_wal_checkpoint_s  first -> last post-sync WAL checkpoint
      invariant_validation_s    last post-sync checkpoint -> Sync complete
      final_wal_checkpoint_s    Sync complete -> end of the contiguous chain
                                of WAL checkpoints that follows
      catchup_log_total_s       first request -> end of the above
    """
    t_start = None
    trans = []  # (ts, to_state)
    staged = []  # (ts, v)
    indexed = []
    trie_done = []
    post_sync = []  # (ts, elapsed)
    wal = []  # (ts, elapsed) for non post-sync "WAL checkpoint:" lines
    sync_reported = None
    for raw in lines:
        p = parse_line(raw)
        if p is None:
            continue
        ts, _level, msg = p
        if t_start is None:
            t_start = ts
        if "sync state transition" in msg:
            m = TRANSITION_RE.search(msg)
            if m:
                trans.append((ts, m.group(2)))
        elif "pending-hashes staged" in msg:
            m = STAGED_RE.search(msg)
            if m:
                staged.append((ts, float(m.group(1))))
        elif "pending-hashes indexed" in msg:
            m = INDEXED_RE.search(msg)
            if m:
                indexed.append((ts, float(m.group(1))))
        elif "trie rebuild complete" in msg:
            m = TRIE_DONE_RE.search(msg)
            if m:
                trie_done.append((ts, float(m.group(1))))
        elif "post-sync WAL checkpoint" in msg:
            m = ELAPSED_SECS_RE.search(msg)
            if m:
                post_sync.append((ts, float(m.group(1))))
        elif "WAL checkpoint:" in msg:
            m = ELAPSED_SECS_RE.search(msg)
            if m:
                wal.append((ts, float(m.group(1))))
        elif "catchpoint sync completed" in msg:
            m = SYNC_ELAPSED_RE.search(msg)
            if m:
                sync_reported = float(m.group(1))

    out = {
        k: None
        for k in (
            "startup_s",
            "earlier_attempts_s",
            "download_s",
            "import_s",
            "verify_s",
            "verify_staging_s",
            "verify_indexing_s",
            "verify_trie_build_s",
            "verify_tail_s",
            "lookback_download_s",
            "replay_s",
            "post_sync_wal_checkpoint_s",
            "invariant_validation_s",
            "final_wal_checkpoint_s",
            "catchup_log_total_s",
            "sync_reported_elapsed_s",
        )
    }
    out["sync_attempts"] = 0
    if sync_reported is not None:
        out["sync_reported_elapsed_s"] = _r(sync_reported)

    firsts = [ts for ts, to in trans if to == S_DOWNLOAD]
    out["sync_attempts"] = len(firsts)
    if not firsts:
        return out
    t_req = firsts[0]
    t_att = firsts[-1]  # the final attempt's start
    out["startup_s"] = _r(_diff(t_start, t_req))
    out["earlier_attempts_s"] = _r(t_att - t_req)

    def first_after(state, after):
        for ts, to in trans:
            if to == state and ts >= after:
                return ts
        return None

    t_imp = first_after(S_IMPORT, t_att)
    t_ver = first_after(S_VERIFY, t_imp if t_imp is not None else t_att)
    t_lb = first_after(S_LOOKBACK, t_ver if t_ver is not None else t_att)
    t_rep = first_after(S_REPLAY, t_lb if t_lb is not None else t_att)
    t_done = first_after(S_DONE, t_rep if t_rep is not None else t_att)

    out["download_s"] = _r(_diff(t_att, t_imp))
    out["import_s"] = _r(_diff(t_imp, t_ver))
    out["verify_s"] = _r(_diff(t_ver, t_lb))
    out["lookback_download_s"] = _r(_diff(t_lb, t_rep))

    if t_ver is not None:
        hi = t_lb if t_lb is not None else float("inf")

        def within(items):
            for ts, v in items:
                if t_ver <= ts <= hi:
                    return v
            return None

        st, ix, td = within(staged), within(indexed), within(trie_done)
        out["verify_staging_s"] = _r(st)
        out["verify_indexing_s"] = _r(_diff(st, ix))
        out["verify_trie_build_s"] = _r(_diff(ix, td))
        if td is not None and out["verify_s"] is not None:
            out["verify_tail_s"] = _r(out["verify_s"] - td)

    end = t_done
    if t_rep is not None and t_done is not None:
        ck = [(ts, e) for ts, e in post_sync if t_rep <= ts <= t_done]
        if ck:
            wal_start = ck[0][0] - ck[0][1]
            wal_end = ck[-1][0]
            out["replay_s"] = _r(wal_start - t_rep)
            out["post_sync_wal_checkpoint_s"] = _r(wal_end - wal_start)
            out["invariant_validation_s"] = _r(t_done - wal_end)
        else:
            # No checkpoint markers: the whole window is replay (+ validation).
            out["replay_s"] = _r(t_done - t_rep)

    if t_done is not None:
        chain_end = t_done
        for ts, e in sorted(w for w in wal if w[0] >= t_done):
            if ts - e <= chain_end + CHAIN_SLACK_S:
                chain_end = ts
            else:
                break
        out["final_wal_checkpoint_s"] = _r(chain_end - t_done)
        end = chain_end
    if end is not None:
        out["catchup_log_total_s"] = _r(end - t_req)
    return out


def parse_phase_file(path: str) -> dict:
    """`parse_phase_log` over a file; an unreadable file yields all-None."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return parse_phase_log(f)
    except OSError:
        return parse_phase_log([])


# --- broken-state scan --------------------------------------------------

# Log sources that emit routine mainnet gossip rejections (user transactions
# that are expired, unsupported, underfunded, ...). Their messages routinely
# contain "below minimum balance" / "insufficient balance" and are NOT a
# block-apply problem.
GOSSIP_NOISE_RE = re.compile(
    r"algo_network::tx_tag_handler|algo_network::tx_syncer|algo_network::tx_sync_pool_adapter"
    r"|PoolSolicitedTxHandler|TxSyncer|TxTagHandler|TransactionPool"
)
BALANCE_RE = re.compile(r"below minimum balance|insufficient balance", re.IGNORECASE)
NO_ADVANCE_RE = re.compile(r"ensure_block.*did not advance|did not advance.*ensure_block")

# (key, regex, minimum count for the job to fail, description)
HARD_RULES = [
    ("permanent_error_writing_block", re.compile(r"permanent error writing block"), 1, "ensure_block hit a permanent ledger write error"),
    ("apply_block_failed", re.compile(r"apply_block failed"), 1, "a block failed to apply to the ledger"),
    ("panic", re.compile(r"panicked"), 1, "a thread panicked"),
    ("invariant_check_error", re.compile(r"invariant check: error"), 1, "post-catchup ledger invariant validation reported an error"),
    ("resource_temporarily_unavailable", re.compile(r"Resource temporarily unavailable"), 1, "EAGAIN from the OS (fd/thread/memory exhaustion)"),
    ("ensure_block_not_advancing", NO_ADVANCE_RE, 3, "ensure_block repeatedly failed to advance the ledger"),
]
# Special hard rule needing the noise exclusion (handled in scan_line).
BALANCE_KEY = "block_apply_balance_error"
BALANCE_DESC = "block apply hit 'below minimum balance' / 'insufficient balance' outside the gossip tx handlers"

WARN_RULES = [
    ("invariant_check_warning", re.compile(r"invariant check: warning"), "post-catchup ledger invariant validation warning"),
    (
        "proposal_group_id_mismatch",
        re.compile(r"group ID mismatch"),
        "demux dropped a gossiped proposal whose group IDs do not recompute; on mainnet "
        "(all proposals valid) roughly one distinct proposal per round failing is anomalous",
    ),
    ("agreement_persistence_write_failed", re.compile(r"persistence write failed"), "agreement persistence write failed"),
    ("agreement_persistence_write_timeout", re.compile(r"persistence write timed out"), "agreement persistence write timed out"),
    ("slow_ensure_block", re.compile(r"slow ensure_block"), "catchup ensure_block took >1s"),
]
NOISE_RULES = [
    ("dnssec_max_validation_depth", re.compile(r"exceeded max validation depth")),
    ("gossip_tx_rejections", re.compile(r"TxTagHandler: pool rejected|PoolSolicitedTxHandler: pool rejected|TxSyncer sync round failed")),
    ("ws_block_fetch_failed", re.compile(r"WS block fetch failed")),
]
GROUP_STORED_RE = re.compile(r"stored ([0-9a-f]{16,})")

# A line must contain one of these to be worth running the regexes on.
_PREFILTER = (
    "permanent error",
    "apply_block failed",
    "panicked",
    "invariant check",
    "Resource temporarily",
    "did not advance",
    "balance",
    "group ID mismatch",
    "persistence write",
    "slow ensure_block",
    "validation depth",
    "pool rejected",
    "TxSyncer",
    "WS block fetch failed",
)


def new_scan() -> dict:
    return {
        "hard": {},
        "warn": {},
        "noise": {},
        "samples": {},
        "proposal_group_id_mismatch_distinct": 0,
        "lines_scanned": 0,
    }


def scan_lines(lines) -> dict:
    scan = new_scan()
    distinct_groups = set()
    for raw in lines:
        scan["lines_scanned"] += 1
        if not any(p in raw for p in _PREFILTER):
            continue
        line = strip_ansi(raw).rstrip("\n")

        def bump(tier, key):
            scan[tier][key] = scan[tier].get(key, 0) + 1
            scan["samples"].setdefault(key, line[:300])

        for key, rx, _thr, _d in HARD_RULES:
            if rx.search(line):
                bump("hard", key)
        if BALANCE_RE.search(line) and not GOSSIP_NOISE_RE.search(line):
            bump("hard", BALANCE_KEY)
        for key, rx, _d in WARN_RULES:
            if rx.search(line):
                bump("warn", key)
                if key == "proposal_group_id_mismatch":
                    m = GROUP_STORED_RE.search(line)
                    if m:
                        distinct_groups.add(m.group(1))
        for key, rx in NOISE_RULES:
            if rx.search(line):
                bump("noise", key)
    scan["proposal_group_id_mismatch_distinct"] = len(distinct_groups)
    thresholds = {k: thr for k, _rx, thr, _d in HARD_RULES}
    thresholds[BALANCE_KEY] = 1
    scan["hard_failures"] = {
        k: n for k, n in scan["hard"].items() if n >= thresholds.get(k, 1)
    }
    scan["hard_total"] = sum(scan["hard_failures"].values())
    return scan


def scan_file(path: str) -> dict:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            scan = scan_lines(f)
        scan["log_found"] = True
    except OSError:
        scan = scan_lines([])
        scan["log_found"] = False
    return scan


# --- rendering -----------------------------------------------------------

_PHASE_ROWS = [
    ("startup_s", "Node start to catchup request (outside the catchup clock)"),
    ("earlier_attempts_s", "Earlier failed/restarted sync attempts"),
    ("download_s", "Download catchpoint file"),
    ("import_s", "Import into database (incl. cutover)"),
    ("verify_s", "Verify ledger integrity (total)"),
    ("verify_staging_s", "  - trie rebuild: stage pending hashes"),
    ("verify_indexing_s", "  - trie rebuild: index pending hashes"),
    ("verify_trie_build_s", "  - trie rebuild: build + final commit"),
    ("verify_tail_s", "  - after trie rebuild (label compare, bookkeeping)"),
    ("lookback_download_s", "Download lookback blocks"),
    ("replay_s", "Replay stored lookback blocks"),
    ("post_sync_wal_checkpoint_s", "Post-sync WAL checkpoints"),
    ("invariant_validation_s", "Ledger invariant validation"),
    ("final_wal_checkpoint_s", "Final WAL checkpoint (after Sync complete)"),
    ("catchup_log_total_s", "Catchup total per node log"),
    ("catchup_wall_s", "Catchup wall clock per status polling"),
    ("unaccounted_s", "Unaccounted (wall minus log total; poll latency)"),
]


def render_markdown(summary: dict) -> str:
    """Markdown tables for the detailed phases, follow window and scan."""
    lines = []
    d = summary.get("phase_seconds_detailed")
    if d:
        lines += ["", "### Catchup phases (from node.log)", "", "| phase | seconds |", "| --- | ---: |"]
        for key, label in _PHASE_ROWS:
            v = d.get(key)
            lines.append(f"| {label} | {'n/a' if v is None else v} |")
    f = summary.get("follow")
    if f:
        lines += [
            "",
            "### Follow window",
            "",
            f"requested {f.get('requested_s')} s, observed {f.get('observed_s')} s after reaching the tip "
            f"(time to tip {f.get('time_to_tip_s')} s); lag stats above cover this window.",
        ]
    s = summary.get("log_scan")
    if s:
        lines += ["", "### node.log broken-state scan", ""]
        if not s.get("log_found", True):
            lines.append("node.log was not found; nothing scanned.")
        elif s.get("hard_total", 0) == 0:
            lines.append(f"**No hard signatures** in {s.get('lines_scanned')} lines.")
        else:
            lines.append(f"**{s['hard_total']} hard signature hit(s)** - the job fails:")
        lines += ["", "| tier | signature | count |", "| --- | --- | ---: |"]
        for tier in ("hard", "warn", "noise"):
            for key, n in sorted(s.get(tier, {}).items()):
                lines.append(f"| {tier} | `{key}` | {n} |")
        if s.get("proposal_group_id_mismatch_distinct"):
            lines.append(
                f"| warn | distinct proposals dropped for group-ID mismatch | "
                f"{s['proposal_group_id_mismatch_distinct']} |"
            )
        for key in s.get("hard_failures", {}):
            lines.append("")
            lines.append(f"First `{key}` line: `{s.get('samples', {}).get(key, '')}`")
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) < 2 or argv[0] not in ("phases", "scan"):
        print("usage: nodelog.py phases|scan NODE_LOG", file=sys.stderr)
        return 64
    res = parse_phase_file(argv[1]) if argv[0] == "phases" else scan_file(argv[1])
    print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
