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

`margin` covers the older headers a cert at round r needs (the VRF seed round
is up to SeedRefreshInterval + SeedLookback behind r).  `window` is the
explicit opt-out (CERT_WINDOW=N, 0 = off).  The result says whether it was
clamped so the caller can emit a loud, never-silent warning.

    cert_window.py FROM TO EARLIEST MARGIN WINDOW
        prints "<cert_from> <clamped:0|1> <reason>"
"""

import sys


def cert_from(requested_from, to_round, earliest, margin, window):
    """Return (cert_from, reason); reason is "" when not clamped.

    `earliest` is the lowest block round in the Rust snapshot, or None when it
    could not be determined (then only the explicit window applies).
    """
    lo = requested_from
    reasons = []
    if earliest is not None and earliest > 1:
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
        lo = to_round
    return lo, "; ".join(reasons)


def main(argv):
    if len(argv) != 6:
        sys.stderr.write(__doc__)
        return 2
    frm, to, earliest, margin, window = argv[1:]
    e = int(earliest) if earliest.strip().isdigit() else None
    lo, reason = cert_from(int(frm), int(to), e, int(margin), int(window))
    print("%d %d %s" % (lo, 1 if reason else 0, reason))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
