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

* go decodes *structs* from a msgpack array as well as a map
  (`SignedTxn.UnmarshalMsgWithState` "struct-from-array" branch) and every
  generated unsigned-integer read (`ReadUint64Bytes`) maps nil to 0; Rust's
  `read_u64` and the struct readers reject both. This is a separate, wider
  non-canonical-encoding class than byte fields (tracked in #2063).
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
