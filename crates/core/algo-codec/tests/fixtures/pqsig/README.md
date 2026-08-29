# PQSig fixtures (issue #707)

Real go-algorand `v5.0.0-stable` `algokey pq`-produced msgpack fixtures,
replacing the hand-computed byte oracle from issue #660 with byte-exact
conformance against a live encoder run.

- `signed_txn_with_pqsig.canonical.hex` — `protocol.Encode(&SignedTxn{...})`
  output of `algokey pq sign`, signing a plain "pay" transaction whose
  `Sender` differs from the PQ signing address (so the map also carries
  `AuthAddr`/`sgnr`).
- `logicsig_with_pqsig.canonical.hex` — `protocol.Encode(&LogicSig{...})`
  output of `algokey pq sign-program`, delegating a trivial 3-byte
  compiled program (`0x06 0x81 0x01`, i.e. `int 1`).

Both use the same deterministic Falcon-1024 key, derived via
`algokey pq import -m "<mnemonic>"` from the well-known all-zero test
mnemonic (`abandon abandon ... invest`) already used by
`crates/core/algo-consensus-crypto/tests/passphrase_parity.rs` — so the
capture is fully reproducible from a clean `../go-algorand` checkout, and
no `algokey pq generate` randomness is involved.

## Refreshing

See `scripts/capture-pqsig-fixtures.sh` for the exact recipe, including
the Docker-based `algokey` build used on a Windows dev box without a
working cgo toolchain (building go-algorand's vendored libsodium fork
requires `make libsodium`, a C toolchain, and — on a Windows git checkout
of `../go-algorand` — stripping CRLF from the libsodium-fork's
autoconf/configure scripts before building in a Linux container).

```bash
ALGOKEY=/path/to/linux/algokey bash scripts/capture-pqsig-fixtures.sh
git diff crates/core/algo-codec/tests/fixtures/pqsig/  # should be empty
```

Consumed by `crates/core/algo-codec/tests/pqsig_canonical_test.rs`.
