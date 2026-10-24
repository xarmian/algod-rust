# Byte-field decode parity: go msgp vs `rmp_decode` (issue #2046)

Audit of every byte-typed call site of the raw msgpack readers in
`crates/core/algo-types` against go-algorand `v5.0.4-stable`'s generated
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
| `ReadBytesBytes` (`[]byte`) | same set; `nil` gives an empty slice | any |
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
  `arg`): go's `ReadBytesBytes(nil)` yields an empty slice, which re-encodes
  as `bin` len 0. Rust's `Option<ByteBuf>` list readers previously mapped a
  nil element to `None` (re-encoded as nil: a different TxID / group ID /
  Merkle leaf). Fixed: the element reader returns `Some(empty)`.
  Tests: `go_msgp_bytes_compat_lists_test.rs`.
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
~5520 at `v5.0.4-stable`).

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
the existing struct. Scalar repeats are last-wins (Rust identical). A
repeated nested-struct key (`txn` twice) decodes *into* the already-populated
struct (a merge), and a repeated fixed-size byte key with a shorter value
keeps the earlier tail (`ReadExactBytes` copies `min(len, N)`); Rust replaces
the nested struct / zero-fills. Not implemented: it needs merge-into-existing
decoding in every struct reader, which is the same shape as the array-form
change, and is observable only for inputs no encoder emits. Registered in
`DIV-004` together with the array form (same impact argument: decoded-struct
re-encode drives all hashes; go has no rejection either, so the divergence is
only "which weird duplicate input decodes to which struct").

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
| `algo-network` `tx_sync_client.rs` `Vec<SignedTransaction>` | peer txn-sync response | transaction gossip, not block/consensus input | same serde limitation, DIV-004; failure rejects one peer's response |
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
