# Intended divergences from go-algorand

algod-rust's premise is byte-level, behaviour-level parity with go-algorand
at the pinned reference version. This file is the **single register of the
places where algod-rust deliberately differs** from go-algorand — in how it
is built, implemented or configured — while staying wire- and
consensus-compatible. It exists for three readers:

1. **Parity sweeps, version-upgrade passes and Phase 17 test-parity audits**
   (human or AI): a difference listed here is *intended*. Do not file it as
   a bug, do not "fix" it back to the go-algorand shape, and do not classify
   its tests as gaps. If an upstream change touches an area listed here,
   re-verify the entry's "How parity is proven" evidence instead.
2. **algod-rust developers** adding a new deliberate difference: add a row
   and a section here **in the same PR**, put a `DIVERGENCE DIV-NNN: <why>`
   marker comment at every code site that embodies it, and keep
   `python3 scripts/check_divergences.py` green (it runs in CI and
   `make lint`).
3. **go-algorand maintainers**: each `### DIV-NNN` section below is written
   so that you can see exactly what changed relative to your tree, what
   stayed identical, which test proves it, and how you could port it if you
   like it.

## Rules

- **Scope.** A divergence is any place where algod-rust, *on purpose*, is
  not a straight translation of go-algorand: a different implementation of
  the same algorithm, an algod-rust-only configuration field, a different
  build/dependency choice with observable consequences, a deliberately
  different operational default. Bugs, not-yet-ported features and
  out-of-scope subsystems are **not** divergences — those are tracked as
  issues and in `docs/PHASE17_TEST_PARITY.md`.
- **Wire and consensus compatibility is not negotiable.** A divergence must
  not change what goes on the wire, what a block hashes to, or what a
  transaction/program evaluates to. The "Wire / consensus impact" column
  must say `none` and the section must say how that is proven.
- **IDs** are `DIV-001`, `DIV-002`, … allocated sequentially and never
  reused. A row may be added as `reserved` before the code lands.
- **Status** is one of `reserved` (id allocated, nothing landed),
  `in-progress` (partially landed), `landed`, `retired` (no longer differs;
  keep the row for history).
- **Marker grammar.** `DIVERGENCE DIV-NNN: <one line>` inside any comment
  (`//`, `///`, `#`, `/* */`, …). `grep -rn "DIVERGENCE DIV-"` lists every
  site. `scripts/check_divergences.py` asserts that every marker has a
  register entry, every non-`reserved` entry has at least one marker, ids are
  sequential, and every marker has a description.
- **Each section** answers, for a go-algorand reader: what changed, what is
  identical, why, how parity is proven (tests, fixtures, CI jobs), how to
  switch back (if there is a switch), and how to port it to go-algorand.

## Register

| ID | Title | Area | Status | Since | Wire / consensus impact | algod-rust files | Upstream files | Proof |
|---|---|---|---|---|---|---|---|---|
| DIV-001 | Falcon-1024 `det1024` implemented in pure Rust; vendored C kept as a runtime-selectable backend (`config.json` `FalconBackend`) | crypto / state proofs / PQ accounts / AVM `falcon_verify` | landed | 2026-10-14 | none (bit-identical keys, signatures, verify decisions, CT conversion) | `crates/core/algo-falcon/`, `crates/node/algo-config/src/lib.rs` (`FalconBackend`), `bin/algod-rust/src/commands/node.rs`, `crates/tools/algokey-rust` | `crypto/falconWrapper.go`, module `github.com/algorand/falcon` v0.1.0 (`falcon.go`, `deterministic.c`, Pornin's reference C) | Go-generated vector corpus diffed in CI, per-function differential tests vs the vendored C, fuzz target (epic #1926) |
| DIV-002 | `goal node pendingtxns` prints each pending transaction in the REST API's JSON form instead of Go's `encoding/json` dump of its decoded `SignedTxn` structs | goal-rust CLI output | landed | 2026-10-17 | none (client-side formatting of data the node already serves) | `crates/tools/goal-rust/src/cmd/node.rs` (`format_pending_txns`) | `cmd/goal/node.go` (`pendingTxnsCmd`), `libgoal/libgoal.go` (`GetParsedPendingTransactions`) | unit test of the exact text for the empty and non-empty pool, mock-node end-to-end test |
| DIV-003 | `algo-abi` rejects ABI types whose encoded head size overflows `usize` at parse time, and caps zero-size array element expansion in `decode` | ABI type parsing / decoding (REST `abi:` box names, goal CLI) | landed | 2026-10-24 | none (no such type can be encoded; valid ARC-4 vectors byte-identical) | `crates/core/algo-abi/src/lib.rs` (`check_static_size`, `MAX_ZERO_SIZE_ELEMS`) | `github.com/algorand/avm-abi` `abi/abi_type.go` (`TypeOf`, `GetEncodedSize`), `abi/abi_encode.go` | `algo-abi` unit tests (overflow/huge-array/zero-size cases) plus the unchanged ARC-4 vector suite (#2057) |
| DIV-004 | Hand-written msgpack struct readers decode the map form only (go also decodes struct-from-array) and replace, rather than merge into, a struct/array on a duplicated key | wire decoding of non-canonical msgpack (blocks, transactions, heartbeat, state proof, PQ structs) | landed | 2026-10-24 | none for canonical encodings (go's encoder never emits the array form or duplicate keys; hashes are over the canonical re-encode); only non-canonical input go accepts is rejected or decoded differently | `crates/core/algo-types/src/rmp_decode.rs` (`read_map_len`), the `decode_from_reader` struct readers in `crates/core/algo-types/src/{transaction,block,header,pq}.rs` | `data/transactions/msgp_gen.go` (`SignedTxn.UnmarshalMsgWithState` struct-from-array branch and key loop), algorand/msgp `msgp/read_bytes.go` | `docs/BYTES_DECODE_PARITY.md` "Issue #2065: final disposition"; `go_msgp_nil_scalars_test.rs` pins the parts that were implemented (nil -> zero) |
| DIV-005 | `algokey keyreg` and the `--network` presets accept `voimain` (Voi mainnet) and `aramidmain` (Aramid mainnet), networks absent from go-algorand's `validNetworks` map | network presets / algokey genesis-hash table | landed | 2026-10-25 | none (additive preset; the four go networks resolve exactly as before) | `crates/core/algo-types/src/networks.rs`, `bin/algod-rust/src/commands/network_common.rs` | `cmd/algokey/keyreg.go` (`validNetworks`) | genesis-hash pin tests (`networks_parity`, `genesis_test::test_voimain_genesis_hash_matches_fixture`) against the live Voi `/genesis` and `/versions` (epic #2068, #2069, #2070) |
| DIV-006 | A network preset's bundled `consensus.json` (aramidmain) contributes only protocol versions the binary does not already define; go loads every entry of a `consensus.json` wholesale | `--network aramidmain` consensus table | landed | 2026-10-25 | none (the aramidmain chain only ever uses `aramidmain-v1.0/1..3`, which are loaded exactly as go loads them; the file's stale copies of `future`/`v7`..`v12`/spec-URL protocols are never used by that chain) | `crates/core/algo-types/src/consensus.rs` (`preload_consensus_protocols_with_bundle`), `bin/algod-rust/src/commands/network_common.rs` | `config/config.go` (`PreloadConfigurableConsensusProtocols`), `config/consensus.go` (`ConsensusProtocols.Merge`) | `aramidmain_consensus_test.rs` (`custom_protocols_merge_like_go`, `bundle_adds_only_unknown_protocols`, `data_dir_file_overrides_bundle`) and the live aramidmain catchup + follow (#2070) |
| DIV-007 | `simulate` serves a past `Request.Round` only from undo data held in memory for the last 320 rounds, which starts empty at every node start; go serves back to its tracker `dbRound` (about `MaxAcctLookback` behind the latest round) at once after a restart | simulate (`POST /v2/transactions/simulate` with `round`) | landed | 2026-10-31 | none (affects only whether a simulate request with a past round is served; no block, state or consensus path) | `crates/core/algo-ledger/src/undo_journal.rs` (`UndoJournal`), `crates/core/algo-ledger/src/simulation/mod.rs` (`Simulator::rewind`), `crates/core/algo-ledger/src/sqlite.rs` (`undo_note_*`) | `ledger/simulation/simulator.go` (`Simulate`, `simulatorLedger.start`), `ledger/acctupdates.go` (`RoundOffsetError`) | `simulate_past_round_oracle_test.rs` (go oracle: rounds 1, 2 and the latest on a rewards-accruing chain), `simulate_past_round_test.rs` (state, window edge, header rewards state incl. a recalculation round), `undo_journal` unit tests, `simulation_gaps_test.rs` (store without undo data); the latest-round path stays proven by the #2118 go oracle (`simulation_rewards_oracle_test.rs`) |
| DIV-008 | The ledger checkpoints the tracker WAL (PASSIVE, `main` only) every time it opens a `ReadSnapshot`, under the ledger lock, and sets `journal_size_limit` (64 MiB) on the connections that write the tracker WAL so a long read pin leaves no peak-size WAL file behind; go has no long-lived read snapshot and sets no limit | ledger SQLite WAL maintenance (pool evaluator snapshot) | landed | 2026-11-02 | none (a checkpoint only copies committed pages from the WAL into the database file, `journal_size_limit` only truncates the WAL file after a restart; durability settings unchanged) | `crates/core/algo-ledger/src/sqlite.rs` (`SqliteLedger::open_read_snapshot`, `checkpoint_tracker_wal_for_snapshot`, `DEFAULT_TRACKER_WAL_SIZE_LIMIT`, `SqliteLedger::set_tracker_wal_size_limit`, `open_ledger_connection_with_sync_mode`), `crates/core/algo-ledger/src/follow_timing.rs` (metrics) | `util/db/dbutil.go` (`_journal_mode=wal`, default `wal_autocheckpoint`) | `wal_overlapping_reader_test.rs` (WAL bound, foreign-reader limit, 40 randomized kills, cost benchmark), live betanet follow, replay-corpus final-state equality (#2166); `sqlite::tests::the_tracker_wal_file_returns_to_its_limit_after_a_pinning_export_snapshot_ends`, `opening_a_file_backed_ledger_sets_the_default_tracker_wal_size_limit`, `a_negative_tracker_wal_size_limit_is_rejected` (#2206) |
| DIV-009 | A block's archive rows (`put_block` / `put_block_cert`) are buffered during the block span and committed to the block file on a second connection BEFORE the tracker transaction commits (go: blockdb commit, then trackers lag); a ledger crash leaves the archive at most one block ahead of the tracker | ledger SQLite commit order (`commit_block`) | landed | 2026-11-02 | none (same files, schema and rows; the archive rows become durable one commit earlier, durability settings unchanged) | `crates/core/algo-ledger/src/sqlite.rs` (`PendingArchive`, `SqliteLedger::flush_pending_archive`, `reconcile_orphans`, `begin_block`, `put_block`, `put_block_cert`, `forget_before`, `open_split`), `crates/core/algo-ledger/src/read_pool.rs` (`ArchiveInflight`, `in_flight`) | `ledger/ledger.go` (`AddValidatedBlock`: `blockQ.putBlock` before `trackers.newBlock`), `ledger/tracker.go` (`loadFromDisk`) | `wal_overlapping_reader_test.rs` (failpoint crash at every commit step in both write orders, randomized hard kills, abort/sync-ahead/savepoint tests, cost benchmark) (#2209) |
| DIV-010 | The catchup pass's fetch window is `CatchupParallelBlocks + min(CatchupParallelBlocks, 32)` rounds ahead of the apply cursor (in flight plus fetched and waiting; `1` stays 1, deliberately no prefetch for the serial setting) with at most `CatchupParallelBlocks` fetches in flight, and once a round's fetch has finally failed new claims are bounded by the apply cursor plus the started workers (rounds already claimed stay claimed); go's window holds `limitedParallelRequests` rounds in total | block catchup / replay scheduling (`CatchupService::sync_pass_core`) | landed | 2026-11-07 | none (the same blocks are fetched, authenticated and applied in round order; only how many fetched blocks may wait for an earlier slow round differs) | `crates/core/algo-ledger/src/catchup_service.rs` (`FETCH_AHEAD_MAX_EXTRA`, `fetch_window`, `sync_pass_core`) | `catchup/service.go` (`pipelinedFetch`, `limitedParallelRequests`, `fetchAndWrite`) | `catchup_service` tests (`a_slow_round_does_not_idle_the_other_workers`, `sync_range_fetch_window_never_exceeds_the_parallel_budget`, `the_tip_probe_is_not_multiplied_by_the_window`, `past_the_tip_no_round_beyond_the_cursor_plus_the_workers_is_requested`, `the_tip_gate_claims_exactly_up_to_the_limit_however_many_workers_race`, `the_fetch_window_is_exact_for_one_worker_and_capped_for_many`), live betanet replay with the block-hash gate (PR #2236, evidence in the entry) |

## Entries

### DIV-001 — Falcon-1024 `det1024` in pure Rust, C kept as a selectable backend

**Status:** landed — the pure-Rust backend is the default since Phase 21
stage 11 (#1937); epic
[#1926](https://github.com/xarmian/algod-rust/issues/1926),
`docs/PHASE21_PROPOSAL.md`. Long-form engineering notes:
`docs/falcon/FALCON_RUST_PORT.md`.

**What go-algorand does.** `crypto/falconWrapper.go` wraps the Go module
`github.com/algorand/falcon` v0.1.0, which is Thomas Pornin's reference
Falcon C implementation plus Algorand's deterministic `det1024` layer
(`deterministic.c`: seed-derived keygen via SHAKE256, deterministic signing
with a 1-byte salt version instead of a 40-byte random salt, header `0xBA`
for compressed and `0xDA` for CT signatures, `FALCON_FPEMU=1` emulated
floating point; `FALCON_KG_CHACHA20` is left disabled so key generation
samples directly from SHAKE256). The C is called through cgo.

**What algod-rust does instead.** The same `det1024` algorithm is
implemented in Rust (`crates/core/algo-falcon/src/rs/`), module for module
after the C files (`shake.c`, `codec.c`, `fpr.h/.c`, `fft.c`, `vrfy.c`,
`common.c`, `rng.c`, `sign.c`, `keygen.c`, `falcon.c`, `deterministic.c`).
The vendored C stays in the crate behind the cargo feature `c-backend`
(default on) and is selectable at runtime through the algod-rust-only
`config.json` field `FalconBackend` (`"rust"`, the default, or `"c"`), the
first configuration key that has no go-algorand counterpart.

**What is identical.** Every byte: public/private key encoding, the
compressed and CT signature encodings, the salt-version scheme, the accept
and reject decisions (including every malformed-input rejection) and the
numeric error codes. Floating point uses native IEEE-754 binary64 for
`+ - * / sqrt` (which Falcon's emulated FP is designed to match bit for bit)
and the C library's own 64-bit fixed-point `fpr_expm_p63` (the one routine
whose native-double variant is *not* bit-identical).

**Why.** Remove the only non-Rust code from the consensus path (no C
toolchain or cgo-equivalent needed to build a node), make the signing path
faster than emulated-FP C, and give the port a permanent oracle.

**How parity is proven.** (1) A vector corpus
(`crates/core/algo-falcon/tests/fixtures/falcon/vectors.jsonl`: seeds →
keys, messages → compressed + CT signatures, negative cases, and
go-algorand's own hard-coded `falcon_verify` vector) generated by a Go tool
that links go-algorand's `crypto` package (`tools/falcon-vector-capture`),
regenerated and `git diff --exit-code`-ed in CI; the same corpus is
reproduced byte-for-byte by the vendored C and by the Rust port. (2)
Per-function differential tests of every ported module against the C
internals (feature `c-internals-test`). (3) A differential fuzz target for
`falcon_verify`. (4) The existing go-algorand-ported unit tests run under
both backends. (5) An adversarial differential hunt of the floating-point
layer (`crates/core/algo-falcon/src/rs/fpr_adversarial.rs`, issue #2016)
proves every operation is bit-identical to the `FALCON_FPEMU` C on normal
finite operands, records the operand tuples where the two legitimately differ
(underflow flush-to-zero, subnormal/non-finite operands, overflow without an
infinity, the sign of zero for `fpr_div(0, negative)` and `fpr_half(-0)`) in
`tests/fixtures/falcon/fpr_divergences.jsonl`, and a domain tracker shows
keygen and signing never reach them
(`docs/falcon/FALCON_RUST_PORT.md`).

**How to switch back.** `"FalconBackend": "c"` in `config.json`
(requires a build with the default `c-backend` feature). `algokey-rust
--falcon-backend c`.

**How go-algorand could port it.** The Rust modules keep the C function
names and structure, so a Go port can be reviewed side by side against
`github.com/algorand/falcon`'s C. The corpus is the acceptance test; the
one trap is floating point: Go's `float64` is strict IEEE-754 for
`+ - * / sqrt` (no FMA contraction on amd64/arm64 when written as separate
statements), `math.Sqrt` is correctly rounded, and `expm_p63` must be the
fixed-point integer version. See `docs/falcon/FALCON_RUST_PORT.md` once it
lands.

### DIV-002 — `goal node pendingtxns` prints the REST JSON form of each transaction

**Status:** landed (#1992).

**What go-algorand does.** `goal node pendingtxns` fetches
`/v2/transactions/pending?format=msgpack`, decodes the response into Go
`transactions.SignedTxn` structs and prints each one with
`json.MarshalIndent(txn, "", "    ")`. Those structs carry only `codec:` tags,
so `encoding/json` falls back to the Go field names (`Sig`, `Msig`, `Txn`,
`Type`, `Header`, ...) and renders byte arrays and addresses according to
each type's `MarshalText` / array rules. The shape is an accident of the Go
struct layout rather than a documented format.

**What algod-rust does instead.** It fetches `format=json` and prints each
entry of `top-transactions` exactly as the REST API serves it (lowercase
canonical keys such as `txn`, `sig`, `type`), indented with the same four
spaces. The header line (`Pending Transactions (Truncated max=N, Total in
pool=M): `) and the `None` line for an empty pool are byte-identical to go.

**What is identical.** The header, the empty-pool text, the `-m/--maxPendingTxn`
flag and its semantics, the 4-space indentation, one document per
transaction, error messages and exit codes.

**Why.** Reproducing `encoding/json` over Go's struct layout would mean
re-implementing the Go field-name and `MarshalText` rules for every
transaction type to print data the node already serves in a documented,
stable JSON form that other tooling (the SDKs, `goal clerk inspect`) uses.

**How parity is proven.** Not applicable to the transaction bodies (that is
the divergence); `format_pending_txns` has unit tests for the header, the
empty-pool text and the indentation, and `node_ops_e2e.rs` runs the command
against a mock node.

**How to switch back.** There is no switch; the command line is unchanged.

**How go-algorand could port it.** Print `GetRawPendingTransactions` with
`format=json` instead of decoding to structs, if a stable JSON form is
preferred over the struct dump.

### DIV-003 — `algo-abi` bounds oversized ABI types and zero-size expansion

**Status:** landed (#2057, audit FIND-ba9c86e5-03).

**What go-algorand does.** `avm-abi` computes static type sizes with plain
`int` arithmetic and expands `[N]T` arrays during decode without bounding the
work by the input length, so `uint64[65535][65535][65535][65535][65535]`
wraps silently and nested zero-size arrays can expand without limit.

**What algod-rust does instead.** `AbiType::byte_len`/`head_len` use checked
arithmetic; `type_of` returns an error for any type whose head size overflows
`usize`; `decode` checks the minimum encoded size before expanding an array
and caps the total number of zero-byte array elements expanded per call at
1,048,576 (2^20, aggregate across the call).

**What is identical.** Every type with a representable size parses, encodes
and decodes byte-for-byte as before, except values that contain more than
2^20 zero-byte array elements in total (e.g. `()[65535][65535]`), which are
rejected; error behaviour for malformed data is otherwise unchanged apart
from earlier detection. Overflow boundaries assume a 64-bit `usize`.

**Why.** Closes a REST/CLI-reachable panic (debug) / wrap (release) and
allocation amplification. Not consensus-affecting.

**How parity is proven.** The whole existing `algo-abi` ARC-4 vector suite is
unchanged and green; new unit tests cover the rejected cases and the boundary
(`uint8[65535]^4` still parses, `()[65535]` still decodes).

**How to switch back.** No switch.

**How go-algorand could port it.** Use overflow-checked multiplication in the
size computation and validate `len*minElemSize <= len(data)` before decoding.

### DIV-004 — Map-form-only struct readers; no merge-into-existing on duplicate keys

**Status:** landed (#2065; audit chain #2046 -> #2063 -> #2065).

**What go-algorand does.** Every generated `UnmarshalMsgWithState` first
calls `msgp.ReadMapHeaderBytes`; on a `TypeError` it retries
`ReadArrayHeaderBytes` and decodes the fields positionally in Go declaration
order ("struct-from-array", `ErrTooManyArrayFields` on excess). In the map
branch there is no duplicate-key detection: a repeated key decodes into the
already-populated field, so a repeated nested struct merges and a repeated
fixed-size byte value shorter than the array keeps the earlier tail.

**What algod-rust does instead.** The hand-written `decode_from_reader`
struct readers accept the map form (and nil, as go does, since #2065) but not
the array form, and a repeated key replaces the field (nested struct /
fixed-size array zero-filled) instead of merging. The derived-serde path used
for catchup `decode_block*` and transaction-sync responses behaves likewise.

**What is identical.** All canonical input (go's encoder always writes a
map with unique keys), nil -> zero for integers/bools/map headers, every
byte-field form (`docs/BYTES_DECODE_PARITY.md`), unknown-key handling, and
every hash, ID and signature input (all are over the canonical re-encode of
the decoded struct in both implementations).

**Why.** Positional decoding needs a per-struct field-order table for ~100
readers and merge-on-duplicate needs decode-into-existing everywhere; the
only inputs that benefit are hand-crafted non-canonical encodings that no
node emits.

**How parity is proven / impact.** No safety impact: a non-canonical wrapper
cannot change a hash, so no fork. Worst case an adversary makes algod-rust
drop one proposal payload or gossiped transaction, or one catchup peer, that
go would decode (one-round liveness, repaired by catchup or another peer).
Reasoning and the source citations are in `docs/BYTES_DECODE_PARITY.md`
("Issue #2065: final disposition").

**How to switch back.** No switch.

**How go-algorand could port it.** Not applicable (go is the more permissive
side).

### DIV-005 — `voimain` network preset

**Status:** landed (#2069, epic #2068).

**What go-algorand does.** `algokey keyreg --network` only accepts the four
Algorand networks in `validNetworks`; go-algorand has no notion of Voi.

**What algod-rust does instead.** Adds a `voimain` preset (genesis id
`voimain-v1.0`, hash `r20fSQI8gWe/kFZziNonSPCXLwcQmH/nxROvnnueWOk=`, vendored
genesis, Voi REST endpoint, Voi DNS bootstrap template) to `--network` and to
the algokey hash table. See `docs/NETWORK_PRESETS.md`.

**What is identical.** Voi mainnet runs standard Algorand consensus versions;
all four go networks, their hashes, and the unknown-network error text
(which still lists only Go's four networks) are unchanged.

**Why.** Following Voi mainnet is a supported use case.

**How parity is proven.** Pinned-hash tests plus a byte-exact genesis fixture
from the live Voi node (hash recomputed and compared to `/versions`).

**Help text.** `algokey keyreg --network` help lists `voimain` while the
unknown-network error text deliberately does not (kept Go-identical).

**How to switch back.** Remove the preset row and enum variant.

**How go-algorand could port it.** Add the hash to `validNetworks`.

### DIV-006 — preset-bundled `consensus.json` adds unknown protocols only

**Status:** landed (#2070, epic #2068).

**What go-algorand does.** `PreloadConfigurableConsensusProtocols` reads
`<data_dir>/consensus.json` and `ConsensusProtocols.Merge` replaces (or deletes)
every version named in the file wholesale. The aramidmain operators ship a
`consensus.json` that, besides the custom `aramidmain-v1.0/1..3`, carries stale
copies of `future`, `v7`..`v12` and the spec-URL protocols from an older
go-algorand.

**What algod-rust does instead.** `--network aramidmain` embeds that file
(`bin/algod-rust/consensus/aramidmain-consensus.json`) and merges only the
protocol versions the binary does not already define (the three custom ones).
A `<data_dir>/consensus.json` is then merged on top exactly like go (wholesale,
wins per version). The bundle applies only when the genesis network name
AND (where known) genesis id and hash equal the preset's, so a private net
reusing the name `aramidmain` gets none; skipped versions are logged at
startup (warn).

**What is identical.** The three custom protocols are loaded field-for-field
like go; every field they set is modelled or is permanently on in algod-rust
(`ApplyData`, `TxnCounter`, and fields go itself no longer has). The standard
protocols the file also lists are never used by the aramidmain chain.

**Why.** Replacing `future` with a years-old definition would silently
downgrade this node's own `future` protocol for no benefit.

**How parity is proven.** `aramidmain_consensus_test.rs` plus live catchup and
follow against the public aramidmain network with zero apply failures.

**How to switch back.** Drop the `!base.contains_key` filter in
`preload_consensus_protocols_with_bundle`.

**How go-algorand could port it.** Not applicable (go has no network presets).

### DIV-007 — simulate serves a past round only from in-memory undo data

**Status:** landed (#2123 latest round only; #2148 undo data).

**What go-algorand does.** `Simulator.Simulate` sets `simulatorLedger.start =
Request.Round`, and every account, app, asset and box read, plus `Totals`, is
served as of `start` from the tracker's in-memory deltas. Any round back to
`dbRound` works; older rounds fail with `round %d before dbRound %d`
(`RoundOffsetError`). After a restart the tracker rebuilds its deltas from the
blocks after the committed round, so the window is there again at once.

**What algod-rust does instead.** The ledger store keeps only the latest state.
With the undo journal on (`LedgerStore::set_undo_window`, 320 rounds on a
node, go's default `MaxAcctLookback`), `SqliteLedger` records, for every
account, holding, asset/app param, local state and box a block writes, its
value before the block first touched it, plus the account totals before the
block (`UndoJournal`). `Simulator::simulate` rewinds the store to `start` by
writing the earliest pre-image after `start` of each touched key, takes the
rewards state and the transaction counter from the header of `start` and the
reward units from the totals before round `start + 1`, runs the simulation in
one SQL transaction, and puts the latest values back. A round older than the
journal fails with go's `round %d before dbRound %d`, `dbRound` being the oldest
retained round minus one.

**Where it differs.** The journal is memory-only: after a restart it is empty
and grows back one round per block, so until 320 blocks are applied the
earliest servable round is later than go's `dbRound`. The in-memory test
backend `LedgerState` keeps no journal and serves only its latest round.

**What is identical.** The simulated state, rewards and failure texts for every
retained round (proven by the go oracle), and the text and class of the
`before dbRound` and `does not have entry` errors.

**Why.** Persisting the pre-images would double the write volume of block apply;
go rebuilds its deltas by replaying blocks, which needs the same old values we
do not keep.

**How parity is proven.** The tests listed in the table row; the error text is
from `ledger/acctupdates.go`.

**How to switch back.** Not applicable (a node with `set_undo_window(0)` serves
only its latest round, as before #2148).

**How go-algorand could port it.** Not applicable (go already serves history).

### DIV-008 — checkpoint the tracker WAL before opening a read snapshot, and cap its file size

**Status:** landed (#2166 checkpoint, #2206 file-size limit).

**What go-algorand does.** `util/db/dbutil.go` opens the ledger databases with
`_journal_mode=wal` and leaves `wal_autocheckpoint` at SQLite's default: after
a commit that leaves the WAL at 1000 frames or more, SQLite runs a PASSIVE
checkpoint on the committing connection. go's readers are short transactions
(`Rdb.Atomic` / `Handle` calls), so there is almost always a moment with no
reader and the WAL restarts from its start.

**What algod-rust does instead.** The transaction pool's block evaluator keeps
a `ReadSnapshot` (one SQLite read transaction on its own connection, for
point-in-time account lookups) alive between blocks, and after each committed
block drops it and opens the next (`TransactionPool::on_new_block`). A snapshot
is therefore alive across every commit. SQLite restarts a WAL only when every
frame is backfilled and no reader holds a WAL read mark, so the WAL was never
restarted and grew with every block while the node followed the chain (about
80 KB a block on betanet: 1.28 GB after a 15 minute catchup against go's
126 MB). `SqliteLedger::open_read_snapshot` now runs
`PRAGMA main.wal_checkpoint(PASSIVE)` on the ledger connection first, in the
gap between the old snapshot's drop and the new one's first read. The new
snapshot then starts with every frame backfilled, reads straight from the
database file (WAL read mark 0), and does not stop the next commit from
restarting the WAL. Only the tracker file is checkpointed (`main.`): the
attached block archive is neither copied nor fsynced. Calling it inside a
`begin_block`..`commit_block` span skips the checkpoint (contract: call
between blocks).

**Residual file size after a long pin (#2206).** A catchpoint export, the lazy
trie loader or an external tool holds one read transaction for a long time and
pins the WAL; the growth during the pin (about 80 KB a block) is inherent to a
consistent snapshot (a snapshot opened right after a checkpoint grows just the
same, measured), but SQLite keeps the peak file size after the WAL restarts
unless `journal_size_limit` is set. The connections that write the tracker WAL
set `PRAGMA main.journal_size_limit` to 64 MiB
(`DEFAULT_TRACKER_WAL_SIZE_LIMIT`), so the next restart cuts the file back:
the `SqliteLedger` connection (`init`) and the raw rebuild connection
`open_ledger_connection_with_sync_mode` (catchpoint import/verify and other
bulk-loading maintenance). It is not set on read-only connections (snapshots,
the lazy trie loader, the read pool), which never restart the WAL, nor on the
block archive file. The limit bounds only the residual file, not growth during
the pin. There is no `config.json` field: it is a disk-space safety net far
above any working set, and a negative value (SQLite's "no limit") is rejected
by `SqliteLedger::set_tracker_wal_size_limit`. Wire and consensus impact: none
(a size hint of the local database file).

**Cost.** The checkpoint runs under the ledger mutex, once per snapshot open
(once per block on the follow path; the pool is paused during catchup). With
nothing to backfill a PASSIVE checkpoint does no I/O. Measured with the
`#[ignore]`d `bench_snapshot_checkpoint_cost` (release build, Windows NVMe,
300 blocks, per block): with `synchronous=FULL` the snapshot open went from
0.15 ms to 1.56 ms and the commit from 0.76 ms to 1.19 ms; with
`synchronous=NORMAL` 0.24 ms to 2.17 ms and 0.12 ms to 0.57 ms. That is about
2 ms of extra lock-hold time per block against a 2.8 s round, and it is
visible as `algod_rust_follow_block_snapshot_wal_checkpoint_seconds`. Running the
checkpoint with a lower `synchronous` would not save the fsync (a checkpoint
syncs the WAL and the database file under both NORMAL and FULL) and is not
done.

**Best effort.** Any other long-lived reader of the tracker file still pins the
WAL: the lazy trie loader's connection, a catchpoint export snapshot (#2206),
an external tool. The checkpoint then reports busy or partial, counted in
`algod_rust_follow_block_snapshot_wal_checkpoint_partial_total` and logged (warning,
at most once a minute). `a_foreign_long_lived_reader_still_pins_the_wal` pins
this limit (the WAL grows to MB while such a reader lives and is reclaimed when
it is released).

**What is identical.** Database contents, schema, journal mode, `synchronous`,
commit semantics and what every reader sees: a checkpoint copies committed
pages into the database file and changes no logical state. The snapshot is the
same point-in-time view as before.

**How parity is proven.** Nothing consensus-visible changes. Measured WAL:
ledger-level replay of the pool's handover (`wal_overlapping_reader_test`)
leaves a tracker WAL of 0.23 MB with the fix against 2.7 MB after 200 blocks
(99 MB after 6000) without it; native betanet follow (12 minutes after a
catchpoint catchup): tracker WAL 0.7 MB flat with the fix (the block
archive's own WAL stays at its normal ~4 MB autocheckpoint cycle), against
+0.8 MB per 25 s (tracker WAL 15.1 MB and rising) without it. Durability: 40 randomized hard kills of a
ledger process that commits with snapshot handovers (so kills land inside
commits and checkpoints) reopen with every reported round and pass
`PRAGMA integrity_check` on both files (a kill between the tracker and block
archive commits was a separate, older problem, fixed by DIV-009, #2209). The replay-corpus tier
(small, testnet-prefix50, testnet-head) ends on the same final state as
`corpus.json`.

**How to switch back.** Delete `checkpoint_tracker_wal_for_snapshot` and its
call in `open_read_snapshot`.

**How go-algorand could port it.** go has no such long-lived snapshot; the
lesson applies to any reader that is replaced rather than released between
commits: checkpoint in the gap between the two.

### DIV-009 — commit the block archive before the block's tracker transaction

**Status:** landed (#2209).

**What go-algorand does.** The block is written to the block database first
(`Ledger.AddValidatedBlock`: `l.blockQ.putBlock(blk, cert)`, which waits for the
blockdb commit) and only then handed to the trackers (`l.trackers.newBlock`).
The tracker database commits later in the background, so the tracker is always
behind or level with blockdb (`dbRound` plus in-memory deltas); at startup
`trackerRegistry.loadFromDisk` replays the missing blocks forward. A crash at
any point leaves trackers <= blocks.

**What algod-rust did.** `SqliteLedger` keeps the tracker as the `main` schema
and attaches the block file as `blockdb`; `begin_block` opened one
`BEGIN IMMEDIATE` over both and the block rows were written inside it. SQLite
commits the databases of one transaction file by file in attach order (tracker
first), and in WAL mode that is not atomic across files, so the block rows
became durable after the tracker commit that depends on them. A hard kill
between the two left the tracker one round ahead of the archive, and
`SqliteLedger::open` refused the ledger (`ledger inconsistency:
acctrounds.acctbase reports round N already committed, but blockdb.blocks has
no row for it`): 2 of 40 randomized kills in the #2166 kill test.

**What algod-rust does instead.**
- Inside a block span `put_block`, `put_block_cert`, the header
  `flush_chain_state` synthesizes for a block without `put_block`, and the
  block part of `forget_before` do not touch the block file: they are buffered
  in memory as an ORDERED list of writes (`PendingArchive`), so a
  `forget_before` between two puts keeps its place, exactly as the immediate
  statements had it. The span reads them back (`get_block_data` / `header_data`
  / `cert` / `proto`, honouring a later prune), so `apply_block` sees the block
  it stored; the other readers of `blockdb` on the main connection are either
  outside any span (`reconcile_cross_file`, `max_block_round_in_blockdb`,
  asserted), go through those getters (`block_header_digest_at_round`), or
  fold the buffer into their fingerprint (`tracker_rows_fingerprint`).
  Outside a span the writes go straight to the file as before. The buffer holds
  one copy of each payload (the trait takes slices); a read copies once.
- `begin_block` takes the TRACKER write lock only (`BEGIN DEFERRED` plus a
  no-op `UPDATE acctrounds`, whose lock wait is the busy handler's, like
  `BEGIN IMMEDIATE`); `BEGIN IMMEDIATE` would also lock the attached block file.
- `commit_block` first commits the buffer to the block file in ONE transaction
  on a second connection to it (`flush_pending_archive`, same `synchronous`
  level, opened on first use), then commits the tracker transaction. The
  ordering therefore lives in `commit_block` and holds for every caller (the
  follower, sync, replay, catchup, genesis seeding, devmode, the synthesized
  header). An aborted block just drops the buffer.
- The second connection opens the file that is really attached as `blockdb`
  (taken from `PRAGMA database_list` at `open_split`), not a path derived from
  the ledger prefix: the block DB directory is configurable, so it need not sit
  next to the tracker. The writer's own `database_list` is compared with the
  attached file when it opens and the commit fails loudly if they differ.
- A crash leaves the archive at most one block AHEAD of the tracker
  (`CrossFileState::Consistent`), which `open` already accepts; the follower
  commits that block again (the write is an upsert). If the tracker COMMIT
  fails (not a crash) after the archive commit, the rows that commit CREATED
  are deleted again (`reconcile_orphans`); a failed delete keeps the rounds in
  the in-flight marker, so the read pool keeps hiding them, and it is retried
  at the next `begin_block` and archive commit. Rows that already existed
  (written ahead by sync) are not touched, they were visible before.
- In-memory ledgers (no files, nothing to crash) and a span whose own
  connection already wrote the block file (test fixtures) write the buffer
  through the main connection inside the tracker transaction, as before.
- The lock-free read pool must keep serving committed state only. The writer
  publishes the range of rounds archived but not yet tracker-committed
  (`ArchiveInflight`, stored before the archive commit, cleared after the
  tracker commit or after the created rows are deleted), and
  `LedgerReadPool::in_flight` reports every row of that range above the
  committed round as absent; when the committed round cannot be read the pool
  answers `Fallback` and the locked path decides. Correctness: a reader that
  found a row either sees the marker (and then compares with the committed
  round, read after the row) or the marker was already cleared, which happens
  after the tracker commit. Rows above the tracker that are not in the range
  (written ahead by sync) are served as before.
- Pruning: the archive prune of a span (`forget_before`) is committed with the
  buffer, i.e. before the tracker's own `txtail` deletion of the same call. That
  is safe because both prune strictly BELOW a round far under the committed
  tracker round (`apply_block` calls `forget_before((round + 1) - (MaxTxnLife + DeeperBlockHeaderHistory))` or less),
  the only readers of old blocks are lookback reads of rounds at or above that
  bound, and the crash window only ever leaves the archive pruned FURTHER than
  the tracker (never the reverse); `crash_after_an_archive_commit_that_pruned_reopens_and_continues`
  kills right between the two commits of pruning blocks and reopens, continues,
  and ends on the uninterrupted state.

**Cost.** One extra archive commit per block (the block file was already
fsynced as part of the single multi-file commit; now it has its own commit).
Measured with the `#[ignore]`d `bench_block_commit_archive_first` (release,
Windows NVMe, 400 blocks of 60 KB, whole `begin_block`..`commit_block` with the
certificate write, three runs each): `synchronous=FULL` (the default)
0.97-1.03 ms on main, 1.02-1.06 ms after (about +0.05 ms); `synchronous=NORMAL`
0.40-0.43 ms on main, 0.46-0.49 ms after (about +0.06 ms).

**What is identical.** Files, schema, rows, journal mode, `synchronous`, and
what every reader sees after a block commits. A ledger written by this build is
byte-for-byte what a clean run produced before.

**How parity is proven.** Nothing consensus-visible changes. Failpoint aborts at
`before_archive_commit`, `after_archive_commit` and `after_tracker_commit` (five
block offsets each, for both the follower's write order and `apply_block`'s
state-first order, with the block file next to the tracker and in another
directory) and hundreds of randomized process kills in both layouts
(alternating the two orders) reopen, never have the tracker ahead of the
archive, keep every reported round with its block and certificate, pass
`PRAGMA integrity_check`, and after the follower resumes end on the state
(account, rounds, every block and certificate) of an uninterrupted run. Further
tests pin: an aborted block leaves the archive byte-identical (including a row
and certificate written ahead by sync), a block written ahead by sync is
committed over, a savepoint open in a span survives the commit, blocks go to
the attached file when it is in another directory (and no stray file appears),
a failed tracker commit neither exposes nor keeps the block, `forget_before`
keeps its order among buffered writes, the pool hides every in-flight round and
falls back on an unreadable committed round, and the pool tests
(`never_serves_uncommitted_data_during_an_open_block`,
`concurrent_readers_never_see_a_block_ahead_of_its_state`) still hold.

**How to switch back.** Make `main_wrote_blocks` true in
`flush_pending_archive`; the buffer is then written inside the tracker
transaction as before (and the kill window returns).

**How go-algorand could port it.** go already has this order; nothing to port.


### DIV-010 — a fetch window larger than the number of concurrent fetches

**Status:** landed (#2204, PR #2236, 2026-11-07). The live evidence below is a manual native run, not a CI result; the Docker catchup-tier row and the go-side comparison are tracked in #2205.

**What go-algorand does.** `catchup/service.go` `pipelinedFetch` keeps a
sliding window of `limitedParallelRequests` rounds (`CatchupParallelBlocks`,
16 by default) starting at the first round not yet written: a worker fetches
its round (`fetchAndWrite`), then waits for the previous round to be written
before writing its own, and a new round enters the window when the first one
is written. A fetched round that waits for an earlier slow one therefore
still occupies its slot, and the number of fetches actually in flight falls
below the window whenever one round is slower than the others. After the
first failed fetch (the tip) it launches no more.

**What algod-rust did.** The same: a permit pool of `parallel_blocks` permits,
returned when a round is applied. On the live betanet catchup (three relays,
a 160/173/303 ms request round trip per relay, blocks of about 600 bytes) the
fetches in flight averaged 11 of 16 (Little's law over the per-request
timings) and the replay ran at 56 blocks/s, the window divided by the
slowest-of-the-window latency rather than by the average latency.

**What algod-rust does instead.** `sync_pass_core` gives out
`fetch_window(workers) = workers + min(workers, FETCH_AHEAD_MAX_EXTRA = 32)`
permits (32 for the default 16 workers, 96 for 64), computed from the workers
that actually started; the number of workers (concurrent fetches) stays
`parallel_blocks`. The serial setting is deliberate: up to
`NO_PREFETCH_WORKERS = 1` worker keeps a window of 1 (`CatchupParallelBlocks:
1` stays strictly serial, no prefetch), while two workers already get a window
of 4, because with concurrency there is something for a slow round to idle. A
worker whose round is fetched takes the next round while an earlier one is
still slow, up to that window.

Once ANY round's fetch has finally failed (normally the network tip: the
lowest probing round out of attempts, or a higher round that gave up at once
because a lower one is probing; the apply loop stops the pass at the first
failed round whatever the lower rounds do; the flag is `fetch_failed`, a
transient "no block" answer a later attempt resolves does not set it), NEW
claims are bounded by `applied + started workers` (go's
window; go launches nothing after the first failure); rounds already claimed
stay claimed, so the claims in flight at that moment (up to the window) are
still fetched. The bound check and the claim are one atomic
compare-and-swap, and gated workers sleep on a condition variable that the
apply loop notifies (only once the gate is engaged) when the cursor moves, with
a version counter so a notification between the failed claim and the sleep is
not lost (a 100 ms timeout is only a safety net). One transient "no block"
answer that a later attempt resolves does not engage the gate. So the 404-bound
requests past the tip are not doubled (8 workers: 13 requests beyond the tip
in the unit test, 21 without the gate; with the cursor stuck at round 1 the
highest round ever requested is at most 8, it reaches 16 without the gate). If
no fetch worker can be started at all (a failing thread spawn, #1650) the pass
ends as a retryable `NoBlock`, not `Done` (the service loop treats it like any
`NoBlock` exit, the tip included: retry at the next tick, `sync_now` waiters
answered `NoBlock`, and the warning is rate limited to one per 30 s); with
fewer workers than requested
the window and the gate bound follow the workers that started. Apply order,
authentication, the commit path, the retry and tip-probe rules are unchanged.

**Memory and wasted work.** Bounded by a block COUNT, not bytes: at most
`min(workers, 32)` fetched blocks wait beyond the workers' own, i.e. 16 extra
blocks by default and 32 extra at `CatchupParallelBlocks >= 32` (96 rounds in
the window at 64; 288 at the clamp ceiling of 256 workers: with completely full
5 MiB blocks about 1.4 GiB, of which 1.25 GiB is the operator's own
`CatchupParallelBlocks` choice and at most 160 MiB is the extra prefetch of
this change; the extra is operator-visible only through that setting). The byte worst case is the window times the consensus block
maximum (`MaxTxnBytesPerBlock`, 5 MiB from consensus v33): 32 x 5 MiB = 160 MiB
by default (80 MiB more than a window of 16), 96 x 5 MiB = 480 MiB at 64
workers, and it needs consecutive completely full blocks (a betanet block is
about 600 bytes; mainnet blocks are far from the maximum). No byte bound and no
config switch were added: a byte bound would need the size of a block that is
still being fetched (unknown until it arrives), and a new `config.json` field
would be algod-rust-only configuration for a case `CatchupParallelBlocks`
already controls (it scales the window; `1` is strictly serial). The work
discarded when an invalid round stops the pass grows by the same number of
blocks.

**Wire / consensus impact.** None: the same rounds are requested and every
block is authenticated and applied in round order exactly as before.

**How parity is proven.** `catchup_service` tests: the window test bounds the
rounds claimed ahead by `fetch_window(parallel_blocks)` and asserts the
concurrent fetches never exceed `parallel_blocks`;
`a_slow_round_does_not_idle_the_other_workers` holds round 1 and asserts, by
notification and not by timing, that exactly rounds `1..=fetch_window` are
claimed (it fails with a window of `workers`); the tip-probe test bounds the
requests past the tip; `the_fetch_window_is_exact_for_one_worker_and_capped_for_many`
pins the window function (the serial setting included).

**Live evidence (PR #2236).** Native release builds on one Windows 11
machine, betanet over its three public relays (`r1s`, `r2s`, `r3s`
`.betanet.algodev.network:4162`), 2026-11-06 and 2026-11-07. Each run:
an empty data directory, the node started with the betanet `genesis.json`,
`POST /v2/catchup/<latest label of the betanet catchpoint index>`, then
`/v2/status` polled each second; the replay rate is the blocks applied between
the catchpoint clearing and the node being within 12 rounds of the public node
`betanet-api.4160.nodely.dev`'s head (6.4k to 7k blocks per run in the final set, 12k to 15k in the earlier ones). After each
run the hashes of five recent rounds (`/v2/blocks/{round}/hash`; a
non-archival node keeps only recent blocks) were compared with the public
node's: equal in every run (6 of 6 in each set). Alternating runs of `main`
and this change (final head), blocks/s: 53.7 / 53.8 / 54.7 (mean 54.1) against
86.5 / 85.8 / 87.9 (mean 86.7, +60 %); the set before it: 53.0 / 53.1 / 54.4
against 88.6 / 86.3 / 89.3; the set on the first version of the change:
55.9 -> 87.7.
Profile of the `main` runs: request round trip p50 160 / 173 / 303 ms for the
three relays, 11.1 fetches in flight on average. The process CPU over 60
seconds at the tip was no worse (final set: main 0.84 / 1.23 / 1.19 s, this
change 0.84 / 0.92 / 1.06 s; the set before: 1.07 s mean against 1.09 s; about
1.5 to 2 % of a core). The procedure is a MANUAL native betanet check, reproducible with
`python3 scripts/bench/catchup_native.py --bin <algod-rust> --genesis
docker/algod/genesis/betanet/genesis.json --follow-secs 60` (run it once per
binary, alternating, to compare); it needs the public network and is not part
of CI. go on the same host and the Docker `catchup` tier were not run (no go
build and no Docker daemon on that machine), and go's own `pipelinedFetch` tip
behaviour (no new fetches after the first failure) was reasoned from the
source, not run.

**How to switch back.** Make `fetch_window` return its argument.

**How go-algorand could port it.** Give `pipelinedFetch` a second, larger
bound on the number of rounds fetched ahead of the write cursor, keep the
worker count at `limitedParallelRequests`, and stop claiming beyond
`limitedParallelRequests` after the first failure.
