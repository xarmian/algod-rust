# Phase 20 Validation — go-algorand v5.0.3-stable Parity

_Completed: 2026-10-12_

Phase 20 moved algod-rust's parity target from go-algorand `v5.0.2-stable`
to `v5.0.3-stable`, a one-change patch release: the IANA root KSK-2024
(key tag 38696) trust anchor is added to go-algorand's DNSSEC root anchor
set ahead of the root key rollover.

Evidence map for [`docs/PHASE20_PROPOSAL.md`](PHASE20_PROPOSAL.md) and
[`docs/epics/Epic-30-Go-Algorand-v5.0.3-Parity.md`](epics/Epic-30-Go-Algorand-v5.0.3-Parity.md).
Tracking epic: [#1864](https://github.com/xarmian/algod-rust/issues/1864).

## Completeness re-check (Stage 7)

- `git -C ../go-algorand fetch --tags`; `TAGS_IN_RANGE` = `{v5.0.3-stable}`
  (`v5.0.3-beta` only merges the stable branch back). Unchanged.
- `gh release view v5.0.3-stable -R algorand/go-algorand`: no changelog
  bullets; the diff (`git diff v5.0.2-stable v5.0.3-stable --stat`) is
  `buildnumber.dat`, `tools/network/dnssec/anchor.go` and the two tests
  asserting the anchor count.
- `gh issue list --label phase:20 --state open`: only the epic #1864.

## Criteria and evidence

| Criterion | Evidence |
|---|---|
| Root KSK-2024 anchor trusted (#1863) | `crates/node/algo-network/src/srv_resolver.rs::default_root_trust_anchors_match_go_v5_0_3_anchor_set` derives key tag + SHA-256 DS digest of every anchor hickory-proto 0.25.2 trusts and asserts exactly go's two live entries (20326 / `E06D44B8…EC8D`, 38696 / `683D2D0A…2B16`, algorithm 8, digest type 2). Verified by mutation: dropping the second anchor fails it. |
| Validation works across the rollover | Ignored live test `live_mainnet_srv_validates_with_default_resolver` (introduced in #1836) passes on 2026-10-12 (≈0.05–0.09 s, real mainnet SRV set, validating default resolver). |
| Pin swept | PR #1866: 74 files, `algod-rust/5.0.3` User-Agent prefixes, Go oracle/capture tool pins; history-citing files untouched. Live-parity, oracle and Dual-Node REST jobs ran green against `algorand/algod:5.0.3-stable`. |
| Test parity | `docs/phase20/test_parity_delta.md`: 0 added / 0 removed / 0 moved / 2 body-changed. `TestParseRootTrustAnchor` → `matched-1:1`; `TestQueryWrapper` stays `out-of-scope` with a re-verification note (go's hand-rolled trust-chain wrapper is delegated to hickory). |
| Parity map gate | `python3 scripts/phase17_parity_delta.py check --tag v5.0.3-stable --go-algorand ../go-algorand --allow-partial 3` → `OK - parity map is pinned, complete, and gap-free` (matched-1:1 1212, matched-1:many 953, matched-many:1 286, partial 3, out-of-scope 736; `not-implemented` = `missing-test` = `unclassified` = 0). |
| Live mixed-cluster vs v5.0.3 Go nodes | `consensus-conformance.sh` ROUNDS=200 WORKLOAD=rich on 3×`algorand/algod:5.0.3-stable` + 1×algod-rust: 200 rounds byte-identical on 4 nodes, fork-free, 0 Go-side agreement rejections, 23 Rust votes accepted by Go, rich workload steps=100 confirmed=88 divergences=0, cadence and proposer share within bounds. |

## Known limitations / sign-offs

- **3 `partial` rows** (`docs/phase17/parity_agreement.md`) remain, each needing a
  live multi-node `Fuzzer`+`Service`+`TopologyFilter` harness; the user
  explicitly signed off on closing Phase 20 with `--allow-partial 3`
  (2026-10-12), as in the prior sweeps.
- **Cert cross-verify checks** (`certs_authenticate_rust/go`) fail on harness
  runs whose tip exceeds ~320 rounds because the Rust `onlineaccounts` history
  retention is ~320 rounds vs go's ~640; filed as #1854 (team:a). They are
  unrelated to the v5.0.3 delta (identical failure on v5.0.2 nodes).
