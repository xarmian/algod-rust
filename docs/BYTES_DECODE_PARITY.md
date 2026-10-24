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
table above (except the interleaved-map corner, still rejected). The strict
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
| pq.rs PQSig `pk`, `sig` | byte slices | ReadBytesBytes (go slice type not re-verified field by field) |
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

## Not changed / left open

* go's "decode a map as an interleaved key/value array" corner of
  `readBytesBytesSlow` / `readExactBytesSlow` is still rejected (no evidence it
  is reachable from any real encoder).
* `ReadExactBytes` normalises a wrong-length value to the array size.
  Fields Rust models as variable `ByteBuf` where go has a fixed array
  (`FalconVerifier.k` = `FalconPublicKey [N]byte`) accept str/nil now but keep
  the encoded length instead of padding/truncating.
* Other decoders with their own readers are outside this issue and unaudited:
  `algo-agreement` `codec.rs`, `algo-consensus-crypto` (`onetimesig`,
  `merklesig`), the serde (`rmp_serde`) paths of `algo-types`, and
  `algo-ledger` catchpoint `msgp_compat.rs` (already accepts bin/str/nil for
  slices; its fixed reader is length-strict).
* The go side was verified by reading `read_bytes.go` and the generated
  decoders; the Go oracle binaries cannot be executed on the audit machine
  (blocked exec), so the differential vectors in
  `crates/core/algo-types/src/rmp_decode.rs` (`go_compat_*`) and
  `crates/core/algo-types/tests/go_msgp_bytes_compat_test.rs` pin the
  source-derived expectations, not runtime go output.
