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
* Other decoders with their own readers are outside this issue and unaudited:
  `algo-agreement` `codec.rs`, `algo-consensus-crypto` (`onetimesig`,
  `merklesig`), the serde (`rmp_serde`) paths of `algo-types`, and
  `algo-ledger` catchpoint `msgp_compat.rs` (already accepts bin/str/nil for
  slices; its fixed reader is length-strict).
* The go side was verified by reading `read_bytes.go` and the generated
  decoders; the Go oracle binaries cannot be executed on the audit machine
  (blocked exec), so the differential vectors in
  `crates/core/algo-types/src/rmp_decode.rs` (`go_compat_*`) and
  `crates/core/algo-types/tests/go_msgp_bytes_compat_*.rs` pin the
  source-derived expectations, not runtime go output.
