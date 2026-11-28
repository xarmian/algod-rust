# Byte-field decode parity: go msgp vs `rmp_decode` (issue #2046)

Audit of every byte-typed call site of the raw msgpack readers in
`crates/core/algo-types` against go-algorand `v5.0.5-stable`'s generated
decoders (`*_msgp.go`, algorand/msgp v1.1.64 `msgp/read_bytes.go`).
`docs/DIVERGENCES.md` was consulted: no registered divergence covers byte
decoding. Follow-up to PR #2044 (a blanket leniency in the shared readers
was reverted there because go's behaviour had not been verified per site).

## What go does

Across all `msgp_gen.go` files in the pin, byte data is read by exactly three
readers (counts of call sites in generated code): `msgp.ReadExactBytes` (115,
every `[N]byte` / `Address` / `Digest` / `Seed` / `Signature` field),
`msgp.ReadBytesBytes` (72, every `[]byte` field, preceded by
`ReadBytesBytesHeader` (84) for the max-size check), and
`msgp.ReadStringBytes` (75, every `string` field). There is no other byte
reader, so the table below collapses to two classes.

| go reader | accepts | length rule |
|---|---|---|
| `ReadExactBytes` (`[N]byte`) | `bin8/16/32`, `str` (fixstr/str8/16/32), `nil` (array zeroed), explicit array of uint8, (interleaved map) | **not enforced**: copies `min(encoded, N)` bytes, tail stays zero (the strict check is commented out in `read_bytes.go`) |
| `ReadBytesBytes` (`[]byte`) | same set; `nil` gives a nil slice (`msgp.AppendBytes` re-encodes it as `nil`, an empty one as `bin` 0: visible only where nil and empty are both encoded, i.e. list elements, issue #2430) | any |
| `ReadStringBytes` / `ReadStringZC` (`string`) | `str`, `nil` (empty string); **not** `bin` | any |

## Rust before / after

Before: `read_bytes` / `read_fixed_bytes` / `read_address` accepted only `bin`
(and `read_fixed_bytes` only the exact length); `read_string` /
`read_str_bytes` rejected `nil`. After: every consensus struct call site uses
`read_bytes_go_compat` / `read_bytes_as_bytebuf_go_compat` /
`read_fixed_bytes_go_compat` / `read_address_go_compat`, which reproduce the
table above. The strict
readers had no remaining caller and were removed. `read_string` /
`read_str_bytes` now map `nil` to empty like go; they still reject `bin`
exactly like go.

## Per-call-site table

"go reader" is verified for the field's Go type; all rows: accepts str = yes,
Rust before = no, Rust after = yes.

| Rust site (file: key) | go field / type | go reader |
|---|---|---|
| block.rs / header.rs: `gh` | `GenesisHash crypto.Digest` | ReadExactBytes |
| `prp`, `rwd`, `fees` | `Proposer`, `RewardsPool`, `FeeSink basics.Address` | ReadExactBytes (`Address.UnmarshalMsg`) |
| `txn`, `txn256`, `txn512` | `TxnCommitments` Digest / Digest / Sha512Digest | ReadExactBytes |
| `prev`, `prev512`, `seed` | `Branch BlockHash`, `Branch512`, `Seed committee.Seed` | ReadExactBytes |
| `partupdrmv`, `partupdabs` element | `ExpiredParticipationAccounts`/`AbsentParticipationAccounts []basics.Address` | ReadExactBytes per element |
| transaction.rs Transaction: `gh`, `lx`, `grp` | `GenesisHash`, `Lease [32]byte`, `Group Digest` | ReadExactBytes |
| `snd`, `rcv`, `close`, `rekey`, `aclose`, `arcv`, `asnd`, `fadd` | `Address` fields | ReadExactBytes |
| `apat` (each) | `Accounts []Address` | ReadExactBytes per element |
| `apap`, `apsu`, `apaa` (each arg) | `ApprovalProgram`, `ClearStateProgram []byte`, `ApplicationArgs [][]byte` | ReadBytesBytes |
| `am` | `MetadataHash [32]byte` | ReadExactBytes |
| `note` | `Note []byte` | ReadBytesBytes |
| `selkey`, `votekey`, `sprfkey` | `SelectionPK VRFVerifier`, `VotePK`, `StateProofPK Commitment [64]` | ReadExactBytes |
| AssetParams `m`,`r`,`f`,`c` | `Manager/Reserve/Freeze/Clawback Address` | ReadExactBytes |
| BoxRef `n`; `apbx` names | `Name []byte` | ReadBytesBytes |
| SignedTransaction `sig`, `sgnr` | `Sig crypto.Signature [64]`, `AuthAddr Address` | ReadExactBytes |
| LogicSig `l`, `arg` (each) | `Logic []byte`, `Args [][]byte` | ReadBytesBytes |
| LogicSig `sig` ; MultisigSubsig `pk`, `s` | `Sig`, `PK ed25519 [32]`, `Sig [64]` | ReadExactBytes |
| HeartbeatProof `s`,`p`,`p2`,`p1s`,`p2s` | `crypto.OneTimeSignature` fields | ReadExactBytes |
| HeartbeatTxnFields `a`, `sd`, `vid` | `HbAddress`, `HbSeed Seed`, `HbVoteID VotePK` | ReadExactBytes |
| MerkleProof path elements | `[]crypto.GenericDigest` (`[]byte`) | ReadBytesBytes |
| MerkleSignature `sig`; SigSlotCommit sig | `FalconSignature []byte` | ReadBytesBytes |
| MerkleSignatureVerifier `cmt` | `Commitment [64]byte` | ReadExactBytes |
| Participant / Reveal / StateProofBody `c`; StateProofMessage `b`,`v` | `GenericDigest` / `[]byte` commitments | ReadBytesBytes |
| HoldingRef / LocalsRef / ResourceRef `d`,`a` | `Address` | ReadExactBytes |
| pq.rs PQSig `sch` | `PQScheme [2]byte` | ReadExactBytes |
| pq.rs PQSig `pk`, `sig` | `PublicKey`, `Signature []byte` (`data/transactions/pqsig.go`, verified) | ReadBytesBytes |
| Falcon `FalconVerifier.k` | `FalconPublicKey [1793]byte` (`crypto/falconWrapper.go:49`) | ReadExactBytes: Rust now pads/truncates to 1793, all-zero = empty |
| `gen`, `proto`, `nextproto`, `upgradeprop`, `type`, AssetParams `un`/`an`/`au` | `string` fields | ReadStringBytes: nil now accepted; bin still rejected |

## Severity assessment

Honest-go peers always send `bin` of exact length (go's encoder), and
`/v2/blocks` re-encodes from the decoded struct, so no honest data was ever
rejected. The difference is reachable only by an adversary crafting a
non-canonical encoding that go accepts. Hash/signature inputs are the
canonical re-encoding of the decoded struct in both implementations, so a
non-canonical payload does not change IDs or hashes and cannot cause a
safety fork; a malicious proposer could at worst make algod-rust fail to
decode one proposal payload go nodes accept (a liveness blip for that round,
repaired by catchup of the canonical block). Severity: low; fixed because
the rule is "reject nothing go accepts".

## List elements, arrays, duplicate keys (review follow-ups)

* **nil elements of `[]byte` lists** (`apaa`, MerkleProof `pth`, LogicSig
  `arg`; at go v5.0.5-stable these are the only `[][]byte` /
  `[]crypto.GenericDigest` reachable from a consensus message, besides
  the local crash-recovery `agreement.diskState.Actions`, whose elements are
  each decoded into an action, never re-encoded as a list): go's `ReadBytesBytes` keeps a `nil` element a nil slice and
  `msgp.AppendBytes` re-encodes it as `nil` (`0xc0`); a `bin` / `str` of
  length 0 is a non-nil empty slice, re-encoded as `bin` 0 (`c4 00`). The two
  give different TxIDs / group IDs / payset commitments. Issue #2430 (which
  corrected the earlier, opposite reading of #2046 / PR #2062): every element
  is an `Option<ByteBuf>` (`LogicSig.args` included), `None` being go's nil,
  decoded and re-encoded losslessly by the canonical, serde and go-codec
  (tx-sync) paths; go-codec's JSON renders a nil element `null`, an empty one
  `""`, and so does the REST JSON. What a program sees (`txna
  ApplicationArgs i`, `arg i`) and the size checks treat a nil element as zero
  bytes, like go. Tests: `go_msgp_bytes_compat_lists_test.rs`,
  `algo-codec/tests/nil_byte_elements_go_txid_test.rs` (go's TxID and signed
  transaction bytes), `pre_encoded_tx_info_json_test.rs`, and the
  strict-decode oracle's nil-element cases (`go_val`, every consensus seed
  kind and tx-sync).
* **Explicit-array form**: elements are read like go `ReadUint8Bytes`
  (`ReadUint64Bytes` + `> 255` overflow check): fixint, uint8..64,
  non-negative int8..64 and nil (as 0); negative values and > 255 are
  rejected. Header forms: fixarray/array16/array32 and, because go's
  `ReadArrayHeaderBytes` flattens maps, fixmap/map16/map32 (2n elements).
  For `[N]byte`, go's `readExactBytesSlow` rejects more than N elements
  (`ArrayError`) while fewer leave the tail untouched; Rust does the same.
* **Duplicate map keys**: go's generated decoders loop over the map and
  `copy` into the existing struct, so a repeated key with a *shorter*
  `bin`/`str` keeps the earlier value's tail (and a zero-length value leaves
  the array unchanged). Rust's fresh-array reader zero-fills instead. This is
  observable only with a duplicated key AND a wrong-length value; no encoder
  produces either, hashes are over the re-encoded decoded struct, and go
  itself has no duplicate-key rejection. Judged benign and not changed
  (tracked in #2063).
* **`read_string` / `read_str_bytes` nil**: all callers are in `algo-types`
  (the readers are `pub(crate)`; no other crate uses them). Their go fields
  are `string` (`GenesisID`, `UnitName`, ...) read with `ReadStringBytes`
  (nil -> ""), or `protocol.TxType` / `protocol.ConsensusVersion`, whose
  `UnmarshalMsgWithState` does `ReadBytesBytesHeader` (size check only) then
  `ReadStringBytes`, so the same nil-accepted / bin-rejected behaviour.
  Nothing needed a stricter variant.

## Not changed / left open

* (Closed by issue #2065, see "Issue #2065: final disposition" below: nil ->
  zero implemented; struct-from-array registered as DIV-004.)
* Remaining raw decoders: see "Issue #2063: other crates" below.
* The go side was verified by reading `read_bytes.go` and the generated
  decoders; the Go oracle binaries cannot be executed on the audit machine
  (blocked exec), so the differential vectors in
  `crates/core/algo-types/src/rmp_decode.rs` (`go_compat_*`) and
  `crates/core/algo-types/tests/go_msgp_bytes_compat_*.rs` pin the
  source-derived expectations, not runtime go output.

## Issue #2063: other crates, fast path, string-reader audit

Follow-up to #2046. Go readers are the same two as above (`ReadExactBytes`
for `[N]byte`, `ReadBytesBytes` for `[]byte`); `algo_types::go_msgp` now
exports the go-compat readers so other crates reuse them.

| Rust site | go type / reader | Wire? | Outcome |
|---|---|---|---|
| `algo-agreement` `codec.rs` `read_bin_fixed` (all `[N]byte`: `oprop`, `sdpf`, `dig`, `encdig`, `snd`, `pf`, `h`, `m`, `v`, OTS `p`/`p1s`/`p2`/`p2s`/`ps`/`s`) | `Address`/`Digest`/`VrfProof`/`OneTimeSignature` -> `ReadExactBytes` | gossip | **changed**: go-compat (was bin + exact length only) |
| `algo-consensus-crypto` `merklesig.rs` `FalconVerifier.k` | `FalconPublicKey [1793]byte` -> `ReadExactBytes` | state-proof sig (peer) | **changed** |
| `merklesig.rs` `Verifier.cmt`, `Signature.sig` | `Commitment [64]byte`, `FalconSignature []byte` | state-proof sig (peer) | **changed** |
| `algo-ledger` `stateproof_worker.rs` `SigFromAddr` `a` | `basics.Address` -> `ReadExactBytes` | gossip (`stateproof_service`) | **changed**; also no longer silently zeroes a non-container |
| `algo-ledger` `catchpoint/msgp_compat.rs` `read_bytes_fixed`, `read_bytes_vec` | catchpoint blobs are `protocol.Decode`d by go: `ReadExactBytes`/`ReadBytesBytes`, length not enforced | go-written file | **changed** (was length-strict; array form added) |
| `merklesig.rs` `FalconSigner` pk/sk; `onetimesig.rs` subkey `PK`/`SK`/`PKSig`/`sig2`, `OneTimeSignatureSecrets` verifier/`offpk2`/`offpk2sig` | go reads these with `ReadExactBytes` too | **no**: local participation-DB secrets, only ever written by go's/our encoder (always `bin`, exact length) | unchanged; strictness is harmless and no producer exists for other forms (follow-up issue) |
| `algo-ledger` `voters.rs` `decode_participants` | algod-rust-internal LE-prefixed cache format | no | unchanged (not go format) |
| `algo-kmd`, `algokey-rust`, `participation/restore.rs` `read_bin` | key files / wallet formats, local operator input | no | unchanged |

**(c) array-form amplification**: elements of the uint8-array form were
decoded one at a time through the generic integer reader. The decoder now
takes positive-fixint and `uint8` elements through an inline fast path
(identical results; every other form falls through to the old reader).
The allocation was already bounded by remaining input (`rd.len() < n` check
before `Vec::with_capacity`), and go has the same input-size-bound shape, so
no additional cap was added (a cap smaller than the message limit would
reject input go accepts).

**(d) `read_string` / `read_str_bytes` nil acceptance**: `rmp_decode` is
`pub(crate)`, so there are no callers outside `algo-types`. Every in-crate
caller is a go `string` (or `protocol.TxType`/`ConsensusVersion`, string
typed) field: `gen`, `proto`, `nextproto`, `upgradeprop`, `type`, AssetParams
`un`/`an`/`au`. No non-string field uses them; nothing needed a stricter
variant. The catchpoint `read_string` has its own implementation (accepts
bin and str by design, internal blob).

**(a) PQSig / FalconVerifier in `algo-types`** were already done in #2046
(see the rows above); verified `PQSig.pk/sig` are `[]byte`
(`data/transactions/pqsig.go`) and `FalconVerifier.k` is `[1793]byte`.

## Issue #2065: final disposition (end of the #2046 -> #2063 -> #2065 chain)

Every item left open by #2063 is resolved below; no follow-up issue is needed.
Go side verified in algorand/msgp v1.1.64 `read_bytes.go` and the generated
`data/transactions/msgp_gen.go` (`SignedTxn.UnmarshalMsgWithState`, line
~5520 at `v5.0.5-stable`).

### 1. nil -> zero, struct-from-array

* **nil -> zero: implemented.** `ReadUint64Bytes` (and through it
  `ReadUint32/16/8Bytes`), `ReadInt64Bytes`, `ReadBoolBytes` and
  `ReadMapHeaderBytes` all map `0xc0` to the zero value / an empty struct
  (the map header additionally sets `isnil`, after which the generated code
  does `(*z) = T{}`). The shared readers `read_u64` / `read_u32` / `read_u16`
  / `read_u8_val` / `read_i64` / `read_bool` / `read_map_len` in
  `algo-types/src/rmp_decode.rs` now do the same (one extra match arm each;
  `read_map_len` one slice-pattern check). Every hand-written struct decoder
  (blocks, headers, transactions, heartbeat, state proofs, PQ) goes through
  these, so the change is central. Tests: `rmp_decode::tests::
  nil_reads_as_zero_like_go_msgp`, `tests/go_msgp_nil_scalars_test.rs`. Only the
  unit test was observed failing on the old code; the integration tests were
  not run before the fix (the run aborted at the first failing target), so
  they are regression pins for the struct-level paths.
  Out of scope (own, non-shared readers): `algo-agreement` `codec.rs`
  `read_uint64`/`read_bool` and `catchpoint/msgp_compat.rs` `read_u64`/
  `read_bool` keep their local semantics; the agreement ones only see
  go-encoded canonical votes (go's encoder omits zero fields, never emits
  nil), the catchpoint ones read go-written files.
* **struct-from-array: verified accepted by go, NOT implemented; registered
  as `DIV-004`.** Every generated struct decoder first calls
  `ReadMapHeaderBytes` and, on a `TypeError`, retries `ReadArrayHeaderBytes`
  and decodes fields positionally in Go struct-declaration order. Supporting
  it would need a per-struct positional field table in every one of the ~100
  hand-written readers (the order is go's declaration order, not the sorted
  wire-key order, and nothing in the Rust structs records it), i.e. a
  large feature, not a shared-reader tweak. Not required for consensus: (a)
  go's encoder never emits the array form (every `MarshalMsg` writes a map),
  so honest go peers never produce it; (b) IDs, group IDs, block digests and
  certificates are hashes of the canonical re-encode of the decoded struct in
  both implementations, so a non-canonical wrapper cannot change a hash and
  there is no safety (fork) impact; (c) catchup serves canonical blocks from
  go archivers; (d) the worst case is an adversary hand-crafting an
  array-form proposal/transaction that go decodes and algod-rust rejects,
  which costs algod-rust that one proposal payload for the round (liveness
  for one round, repaired by catchup) or that one gossiped transaction.
  Severity low.

### 2. Duplicate map keys

go's generated decoder (see `SignedTxn` above) has **no duplicate-key
detection**: it loops `for zb0001 > 0`, switches on the key, and decodes into
the existing struct. Scalar repeats are last-wins. A repeated nested-struct
key (`txn` twice) decodes *into* the already-populated struct (a merge), and a
repeated fixed-size byte key with a shorter value keeps the earlier tail
(`ReadExactBytes` copies `min(len, N)`). **Implemented** for every reader: the
non-consensus ones by #2421, the consensus ones and tx-sync by #2424 (see
"Issue #2424" below). Only the array form remained in `DIV-004` (retired by #2521, see "Issue #2521" below).

### 3. Local participation secrets

`onetimesig.rs` subkeys / `OneTimeSignatureSecrets`, `merklesig.rs`
`FalconSigner` (and the sk blobs) keep the strict `bin`/exact-length readers
**intentionally**. They are never wire data: they are the participation DB
blobs written only by go's own encoder or ours (always `bin`, exact length),
read at startup from the operator's own disk. Accepting `str`/nil/array/
wrong-length forms would only make a corrupt key file load as a silently
zero-padded secret, which is strictly worse than failing; there is no
interoperability case to serve. Not a consensus decode path; no change.

### 4. serde (`rmp_serde`) decode audit

`vpack.rs` (`algo-network`) has **no serde decode**: it is a hand-written
byte-level parser/compressor that mirrors go's own `vpack` (also strict: go
falls back to sending the vote uncompressed when it cannot parse a form, and
the decompressed output is then decoded by `algo-agreement`'s `codec.rs`).
Production `rmp_serde` decodes and their reachability:

| Site | Input source | Untrusted consensus input? | Outcome |
|---|---|---|---|
| `algo-codec` `decode_block` / `decode_block_response`; used by `algo-rest-client` `gossip_block_source::decode_block_cert` and `client.rs get_block` | catchup blocks from peers (WS / REST) | yes, but cert-verified: block digest = hash of the canonical re-encode, cert covers it | **documented** (DIV-004): derived-serde `Deserialize` rejects nil-for-zero and accepts/misreads array form; a peer serving a non-canonical but go-acceptable encoding is dropped and another peer is used (per-peer liveness only, no safety) |
| `algo-ledger` `apply.rs`, `heartbeat.rs`, `sqlite.rs`, `sync/mod.rs` `decode_block` | our own stored/canonical blobs (`blockdb`, catchpoint-written) | no (local DB; written by our canonical encoder) | none |
| `algo-agreement` proposal / vote / bundle decode | gossip | yes | **hand-written** decoders (`codec.rs`, `Block::decode_from_bytes`), covered by #2062/#2063 and this issue's shared-reader change; not serde |
| `algo-network` `tx_sync_client.rs` `Vec<SignedTransaction>` | peer txn-sync response | transaction gossip, not block/consensus input | hand-written reader in go-codec mode (`algo_types::go_codec_reflect`, #2424): go's `protocol.DecodeReflect` checks no `required` / `allocbound` and decodes a repeated map entry into the existing one; reads the array form too (#2426) |
| `algo-network` `identity.rs`, `algo-p2p` `wsproto.rs` (`peerMetaHeaders`) | peer handshake | no (identity challenge / headers; go-encoded canonical; no consensus effect) | none |
| `algo-rest-api` `handlers.rs` (txn submit), `simulate_strict.rs`, `format.rs` | local REST clients | no | none (go's REST `protocol.Decode` is the model; strict-unknown-field guard already present) |
| `algo-ledger` `eval_delta.rs` inner-txn rebuild, `state_delta.rs`, `catchpoint/types.rs` | our own re-encoded values / go catchpoint files | no / file | none |
| `algo-codec` `decode_logicsig` / `decode_multisig` / `decode_signed_txn_stream`, `decode_state_proof_verification_context` | `goal`/kmd CLI blobs, own DB, catchpoint file | no | none |

The one remaining observation in the other direction: the hand-written
readers skip unknown map keys by default while go's generated decoders
return `ErrNoField`. That is the strict-unknown-field mode (`StrictUnknownFieldsGuard`) already used for
REST submission; for consensus input the acceptance of an extra key cannot
change any hash (the key is dropped on re-encode) and only matters for a
proposal that go would have rejected outright, which cannot gather a quorum
of go votes. Not a regression of this work; recorded for completeness.

## Issue #2397: go `string` fields are arbitrary bytes (non-UTF-8 `str`)

`msgp.ReadStringBytes` / `ReadStringZC` bound the length only and never
validate UTF-8, so go decodes a non-UTF-8 `str` value into any Go `string`
field. `rmp_decode::read_string` rejected it, so a block go decodes failed to
decode here. Affected fields (the only `read_string` callers): `gen` (block
header and transaction), `proto`, `nextproto`, `upgradeprop`, transaction
`type`. (EvalDelta `lg`/`bs` and the other raw `dt` subtrees already keep the
bytes; asset `un`/`an`/`au` were handled by #2042.)

**Fix.** `read_string` returns the bijective lossless `String` form of
`algo_types::raw_text` (the module #2388 introduced for assembler source,
moved from `algo-avm` and re-exported there): valid UTF-8 is unchanged, an
invalid byte becomes a private-use character. The canonical encoder writes the
five fields through `CanonicalMap::add_raw_string`, which turns that form back
into the original bytes, so encode/hash/txid of every block that decoded before
is unchanged and a non-UTF-8 value re-encodes byte-exactly. The `upgradeprop`
length check uses `raw_text::raw_len` (go's `len(string)`).

**Consensus relevance (decided).**

| field | go's later checks | go accepts a non-UTF-8 value? |
|---|---|---|
| `gen` | `Block.PreCheck`/eval: must equal the ledger's genesis id | no |
| `proto` | `config.Consensus[proto]` lookup (`ProcessUpgradeParams`: "previous protocol not supported") | no |
| txn `type` | `Transaction.WellFormed`: unknown type rejected | no |
| `upgradeprop` | `applyUpgradeVote` (`data/bookkeeping/block.go`): only length `<= MaxVersionStringLen` and no pending proposal | **yes, any byte string** |
| `nextproto` | set from an accepted `upgradeprop`, then copied into every following header until the vote ends | **yes** |

So a block with a non-UTF-8 `upgradeprop` is valid in go (a proposal need not
name a known consensus version), and every header until the vote deadline
carries it as `nextproto`: a Rust node that failed to decode it would fork
off. Both fields are now lossless. For `gen`/`proto`/`type` go decodes and
then rejects at validation, Rust now decodes and rejects at the same stage.

**Proof.** `strict_unknown_fields_go_parity` (seeds are now go-encoded
`RandomizeObject` values with their random non-UTF-8 strings, no ASCII
sanitisation) replays every case against go's real decoders (red before the
fix: 126 mismatches, all `read_string: invalid utf-8`);
`non_utf8_string_fields_round_trip_byte_exact` re-encodes those seeds to the
identical bytes; the real-chain corpus tests are unchanged.

**Follow-up found by the 100k differential fuzz on PR #2401 (unsanitised seeds
exposed it).** A state-proof `Reveal` with a repeated `p` key carrying `{}`:
go decodes the empty map INTO the already populated `Participant` (fields the
map does not mention are kept), so the `codec:",required"` verifier is still
set and go accepts; the Rust reader replaced the participant and rejected
"missing required field 'p'". `Reveal.part`, `Participant.pk` and
`MerkleSignatureVerifier` now decode into the existing value (the `required`
check runs on the merged result, nil still zeroes it). Pinned as two
always-present cases (`PINNED` in `strict_decode_fixtures.py`). This narrows,
and does not widen, DIV-004's "replace instead of merge on a duplicated key"
(other struct fields still replaced then; #2421's decoded-value oracle showed
that is observable, and #2424 made every reader merge).

## Issue #2421: a repeated key decodes into the populated field

go's generated decoders have no duplicate-key detection: a repeated map key is
decoded again into the field it already filled. A scalar or `[]byte` /
`msgp.Raw` is overwritten; a nested struct keeps the fields the repeat does not
mention (a `nil` map header resets it, `(*z) = T{}`); a map keeps its entries
and gets the new ones (each value fresh); a slice of `n` elements is re-sliced
when `cap >= n` (each element decoded into the existing one, elements hidden
by a shorter repeat come back with a longer one) and is a fresh `make` of zero
elements otherwise; a `[N]byte` (`ReadExactBytes(b, z.X[:])`) overwrites only
the first `min(len, N)` bytes and keeps the rest (`nil` zeroes it). A go
`string` field also reads a `bin` or a uint8 array (`ReadStringZC`'s go-codec
fallback), which `rmp_decode::read_string` / `read_str_bytes` now do for every
reader.

**Non-consensus readers (fixed).** The catchpoint readers
(`crates/core/algo-ledger/src/catchpoint/msgp_compat.rs`: header, chunk
`bl`/`kv`/`oa`/`orp` with go's slice capacity, `BalanceRecordV6.c`, the
account / resource / online blobs including `TealKeyValue`, the state-proof
verification `spd`), the identity handshake messages
(`crates/node/algo-network/src/identity.rs`) and the libp2p peer meta headers
(`crates/node/algo-p2p/src/wsproto.rs`, now lossless for non-UTF-8 bytes) decode
exactly what go decodes. The importer also gained go's
`prepareNormalizedBalancesV6` checks it lacked
(`importer::decode_balance_record_blobs`): an empty account / resource blob
and a resource that is neither an asset nor an app fail the restore.

**Proof.** The fixture generator's oracles now return go's re-encode of the
decoded value; every accepted case carries its sha256 prefix (`go_val`), and
the ledger / network / p2p sets carry repeated-key cases (a key the map already
has, with a value derived from its first one or another map's value under the
same key). The replaying tests re-encode algod-rust's decoded value the way go
encodes it and compare. Red before the fix: 16 of 801 ledger cases, 1 identity
case, 11 of 24 peer-meta cases; green after, plus 36k fuzz cases
(`--fuzz 20000`, 26432 ledger / 9196 network / 630 p2p). Unit tests pin go's
slice-capacity result (checked against go v5.0.5-stable) and each merge rule.

**Consensus readers and tx-sync.** Done by #2424, below.

## Issue #2424: the consensus readers and tx-sync decode a repeated key like go

Every consensus reader now decodes a repeated key the way #2421 describes:
`Transaction`, `SignedTransaction` (`SignedTxnInBlock` / `SignedTxnWithAD`),
`LogicSig`, `MultisigSig`, the state-proof and heartbeat structs, `PQSig`
(`crates/core/algo-types/src/{transaction,pq}.rs`), `Block` / `BlockHeader`
(one shared field dispatch, `header_key_match!`), `BlockResponse` (a repeated
`block` merges; a repeated `cert` keeps both occurrences' entries in order,
which `decode_bundle` then reads exactly as go decodes the second into the
first), and the agreement codec's votes, bundles and proposal payloads
(`crates/core/algo-agreement/src/codec.rs`; a `[2]T` field takes at most two
elements into the leading ones, a `nil` struct is its zero value). The
building blocks are in `crates/core/algo-types/src/rmp_decode.rs`
(`read_struct_map_len`, `read_struct_into_opt`, `read_pointer_into` for go's
one pointer field `hb`, `read_fixed_into_opt`, `read_slice_into` with go's
slice capacity, `read_u64_map_into`, `read_fixed_array_into`). A slice's
hidden capacity (elements past a shorter repeat, which a longer one brings
back) is kept per buffer for the rest of the top-level decode
(`DecodeSession`).

**`dt` and `spt`.** A transaction's eval delta and a header's state-proof
tracking map were kept as the raw `rmpv::Value` and written back verbatim into
the payset commitment and the block hash. They are now decoded with go's
semantics into a typed mirror and kept as go's canonical re-encode
(`crates/core/algo-types/src/go_eval_delta.rs`), including go's allocation
bounds (`MaxStateDeltaKeys`, `MaxEvalDeltaAccounts`, `MaxLogCalls`,
`MaxInnerTransactionsPerDelta`, `MaxAppBytesValueLen`, `NumStateProofTypes`,
`MaxHashDigestSize`) and the `nil`-versus-empty distinctions go's encoder
keeps (`ld: {5: nil}` re-encodes as `nil`). An inner transaction is re-encoded
with the transaction encoder, which moved from `algo-codec` to
`algo_types::canonical` for that (algo-codec re-exports it unchanged).

**Encoders fixed on the way (go's `MarshalMsg` of the decoded value).** Each
was only observable for a value no honest encoder produces, but each changed
bytes go would have written: `lsig: {}` (a zero `LogicSig`) is omitted like
go's `MsgIsZero`; `LogicSig.l` and `PQSig.pk`/`sig` are `[]byte` (length-only
omitempty; an all-zero non-empty value was dropped); an equivocation-vote
authenticator always writes its `sig` pair (go's struct is not omitempty).

**tx-sync is go-codec, not msgp.** go reads a tx-sync response with
`protocol.DecodeReflect` (reflection). Read with the oracle: it checks no
`codec:",required"` field and no msgp `allocbound`, decodes a repeated key
into the populated field like msgp, and decodes a repeated `map[uint64]Reveal`
entry INTO the existing, unaddressable map value: integers are written, a
`[]byte` is copied over the existing prefix (length unchanged), a nested
slice cannot grow, and any `nil` or `[N]byte` fails the decode
(`reflect.Value.Set using unaddressable value` / `slice of unaddressable
array`); msgp decodes every map entry fresh. `decode_tx_sync_response` runs
the readers in that mode (`algo_types::go_codec_reflect`).

**Proof.** `strict_decode_fixtures.py` now generates repeated-key cases for
every consensus kind and `txsync`, and
`crates/core/algo-agreement/tests/strict_unknown_fields_go_parity.rs` compares
every accepted case's decoded value (re-encoded with the node's go-canonical
encoders) with go's, like the non-consensus tests. Red before the fix: 600 of
4748 consensus cases (applydata 101, blockcert 94, block 54, bundle 46, cert
43, evaldelta 110, header 20, payload 58, stxn 10, stxninblock 35, txn 13,
vote 16) and 8 of 593 network (tx-sync) cases; green after, plus the
`--fuzz 100000` run (159,664 consensus and 19,884 network cases, every
verdict and decoded value equal to go's). The real-chain corpus tests, the
88k-case block differential test and the canonical re-encode of every
committed real block are unchanged.

## Issue #2521: DIV-004 retired

The last readers that took only the map form are gone, so `DIV-004` is
`retired` in `docs/DIVERGENCES.md`.

* The agreement codec's decoders of its own authenticated forms
  (`decode_credential`, `decode_authenticated_vote`,
  `decode_authenticated_bundle`, the `AuthenticatedBundle` type, their
  encoders and the cursor helpers) were deleted: nothing outside tests called
  them, and go decodes `committee.Credential`, `agreement.vote` and
  `agreement.bundle` only from its own persisted state. Their go-fixture and
  proptest round-trip tests went with them.
* algokey's PQ key-file reader (`decode_pq_signing_material`) has a real
  caller (every `algokey pq` command that reads a key file), so it was
  rebuilt on `rmp_decode::struct_keys` and is replayed against go's
  `protocol.Decode` of `pqSigningMaterial`: the `algokey` fixture set of
  `scripts/strict-decode/strict_decode_fixtures.py` (go-generated seeds and
  cases from `tools/strict-decode-oracle/algokey_oracle_test.go.txt`, array
  form, repeated keys and every mutated value) through the
  `the_key_file_decoder_matches_go_on_every_mutated_file` test. A missing
  field now decodes as zero and is rejected later by `validate()`, as in go,
  and an unknown key is `ErrNoField`, where the old reader skipped it.
* One invisible difference: go keeps a `[]byte` nil after a `nil` and empty
  after an empty `bin` (the msgp encoder writes them differently); the
  reader holds a `Vec` and nothing reads the distinction, so the oracle folds
  the two before re-encoding.

## Issue #2609: go v5.1.1 reads a struct from a map only

go v5.1.1 (algorand/msgp 1.1.66, go #6774) generates struct decoders without
the "struct-from-array" branch: an array where a struct is expected is
`ReadMapHeaderBytes`'s `TypeError`. The array form of #2426 is therefore a
rejection now, in every reader but go-codec's.

Entry points (go v5.1.1 `protocol.Decode` = generated msgp, map only;
`DecodeReflect` = go-codec, array form kept):

| go entry point | go decoder | algod-rust reader | fixture kind / set |
| --- | --- | --- | --- |
| gossip `TX` / `PP` / `VB` / `AV`, `BlockResponse`, block service | generated | `algo-types` / `algo-agreement` readers (`struct_keys`, map only) | consensus: `stxn` `txn` `payload` `vote` `bundle` `cert` `blockcert` `block` `header` `applydata` `evaldelta` `stxninblock` |
| tx-sync response (`rpcs/httpTxSync.go`, go #6729) | generated | `algo-network` `tx_sync_client` | network: `txsync` |
| identity challenge / response / verification | generated | `algo-network` `identity` | network: `idchal` `idresp` `idverify` |
| peer-meta headers (`p2pMetainfo.go`) | generated | `algo-p2p` `wsproto` | p2p: `peermeta` (a map of string to string list, no struct) |
| catchpoint `content.msgpack`, `balances.N.msgpack` (and the account / resource blobs inside), `stateProofVerificationContext.msgpack` | generated | `algo-ledger` `catchpoint/msgp_compat.rs` (array branches removed in #2609) | ledger: `cpheader` `cpchunk` `cpspver` |
| algokey PQ key file | generated | `algokey-rust` `pq/key.rs` | algokey: `pqkey` |
| simulate request body (`server/v2/utils.go`) | go-codec | `algo-rest-api` `simulate_strict.rs` under `go_codec_reflect` | `simulate_strict` rows (#2555, #2608) |
| `libgoal` / `goal` reads of a node's answer, agreement crash state | go-codec | goal-rust (client side), own crash-state format | not a wire entry of the node |

The ledger set had no array rows before #2609 (its schema was not dumped) and
its readers still read the array form; the ledger oracle now dumps its schema
(`TestStrictDecodeSchemaLedger`, the msgp.Raw fields `b` / `c` typed as
`BaseAccountData` / `ResourcesData`), and every set got rows for an array
under a struct-valued key, array headers cut short, arrays nested up to 300
deep and the array form cut at a few points. All are rejected by go v5.1.1 and
by the readers. The older rows were not touched (the new ones are appended).
