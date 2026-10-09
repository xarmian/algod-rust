#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

"""Cert cross-verify round window (issue #1777).

A non-archival node (go-algorand and algod-rust alike) keeps only the last
~MaxTxnLife + DeeperBlockHeaderHistory (1001) blocks, so a cert cross-verify
over a long run's whole range fails on the first pruned round.  The window is
derived from what the Rust ledger snapshot actually holds, not guessed:

    from = max(requested_from, earliest_retained + margin, to - window)

`margin` is derived from the consensus parameters, not a constant: verifying
the cert for round r needs the online stake at BalanceRound(r) =
r - BalanceLookback, BalanceLookback = 2 * SeedRefreshInterval * SeedLookback
(crates/core/algo-agreement/src/lookback.rs, go agreement/selector.go), and the
seed round (up to SeedRefreshInterval + SeedLookback behind r), plus slack.

When the earliest retained round cannot be determined the pass is NEVER
silently unclamped: it falls back to CERT_WINDOW, else the last
DEFAULT_UNKNOWN_WINDOW rounds, and says "earliest unknown".  A clamp that
leaves an empty/inverted range is flagged too.

    cert_window.py FROM TO EARLIEST MARGIN WINDOW [SEED_LOOKBACK SEED_REFRESH]
        MARGIN is a number or "auto" (derive from SEED_LOOKBACK/SEED_REFRESH,
        default 2 / 80 = v41).  Prints "<cert_from> <clamped:0|1> <reason>";
        exits 2 with a message on stderr on bad input.
"""

import sys

DEFAULT_UNKNOWN_WINDOW = 900
DEFAULT_SEED_LOOKBACK = 2
DEFAULT_SEED_REFRESH_INTERVAL = 80


def retain_margin(seed_lookback, seed_refresh_interval, slack=20):
    """Rounds to skip past the earliest retained block.

    BalanceLookback + seed round distance + slack.
    """
    balance_lookback = 2 * seed_refresh_interval * seed_lookback
    return balance_lookback + seed_refresh_interval + seed_lookback + slack


def cert_from(requested_from, to_round, earliest, margin, window):
    """Return (cert_from, reason); reason is "" when nothing was clamped.

    `earliest` is the lowest block round in the Rust snapshot, or None when it
    could not be determined.
    """
    lo = requested_from
    reasons = []
    if earliest is None:
        reasons.append("earliest unknown")
        if window <= 0:
            window = DEFAULT_UNKNOWN_WINDOW
            reasons.append("defaulting to the last %d rounds" % window)
    elif earliest > 1:
        retained_from = earliest + margin
        if retained_from > lo:
            lo = retained_from
            reasons.append(
                "Rust ledger retains blocks from round %d (non-archival; "
                "+%d margin)" % (earliest, margin)
            )
    if window > 0 and to_round - lo > window:
        lo = to_round - window
        reasons.append("CERT_WINDOW=%d" % window)
    if lo > to_round:
        reasons.append(
            "range is empty (from %d > to %d); verifying round %d only"
            % (lo, to_round, to_round)
        )
        lo = to_round
    return lo, "; ".join(reasons)


def main(argv):
    if len(argv) not in (6, 8):
        sys.stderr.write(__doc__)
        return 2
    try:
        frm, to, window = int(argv[1]), int(argv[2]), int(argv[5])
        earliest = int(argv[3]) if argv[3].strip().isdigit() else None
        sl = int(argv[6]) if len(argv) == 8 else DEFAULT_SEED_LOOKBACK
        sri = int(argv[7]) if len(argv) == 8 else DEFAULT_SEED_REFRESH_INTERVAL
        margin = retain_margin(sl, sri) if argv[4] == "auto" else int(argv[4])
    except ValueError as e:
        sys.stderr.write("cert_window.py: bad numeric argument: %s" % e + chr(10))
        return 2
    if min(frm, to, window, margin) < 0:
        sys.stderr.write("cert_window.py: negative argument" + chr(10))
        return 2
    lo, reason = cert_from(frm, to, earliest, margin, window)
    print("%d %d %s" % (lo, 1 if reason else 0, reason))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
