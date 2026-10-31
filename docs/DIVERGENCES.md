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
| DIV-007 | `simulate` serves only `Request.Round` = the latest round; an earlier round is rejected with go's `round %d before dbRound %d` (dbRound = latest), where go serves any round back to its tracker `dbRound` | simulate (`POST /v2/transactions/simulate` with `round`) | landed | 2026-10-31 | none (affects only whether a simulate request with a past round is served; no block, state or consensus path) | `crates/core/algo-ledger/src/simulation/mod.rs` (`Simulator::simulate`) | `ledger/simulation/simulator.go` (`Simulate`, `simulatorLedger.start`), `ledger/acctupdates.go` (`RoundOffsetError`) | `simulation_gaps_test.rs` (`start_round_selection`, `simulate_at_a_past_round_is_rejected_not_evaluated_on_latest_state`, `simulate_round_before_db_round_is_rejected`); the latest-round path stays proven by the #2118 go oracle (`simulation_rewards_oracle_test.rs`) |

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

### DIV-007 — simulate serves only the latest round

**Status:** landed (#2123).

**What go-algorand does.** `Simulator.Simulate` sets `simulatorLedger.start =
Request.Round`, and every account, app, asset and box read, plus `Totals`, is
served as of `start` from the tracker's in-memory deltas. Any round back to
`dbRound` works; older rounds fail with `round %d before dbRound %d`
(`RoundOffsetError`).

**What algod-rust does instead.** The ledger store keeps only the latest state
(no per-round account history), so `Simulator::simulate` treats the latest round
as the effective `dbRound`: `Request.Round` below it is rejected with go's exact
error text (an internal error, so a 500 like go's), and a round above it fails
with `ledger does not have entry N` as in go.

**What is identical.** Omitting the round, or giving the latest round, behaves
exactly as go, including the block-start rewards (proven by the #2118 oracle).
The error text and error class for an unservable round are go's.

**Why.** Evaluating a past round against the latest state under an older header
returns wrong balances and, on rewards-accruing chains, an inconsistent rewards
level; failing loudly is closer to go than a silently wrong result. Serving past
rounds needs undo data for every account, app, asset and box the evaluator can
read; that is tracked in #2148.

**How parity is proven.** The tests listed in the table row; the error text is
from `ledger/acctupdates.go`.

**How to switch back.** Remove the `.max(self.store.current_round())` in
`Simulator::simulate` once the store can serve historical state.

**How go-algorand could port it.** Not applicable (go already serves history).
