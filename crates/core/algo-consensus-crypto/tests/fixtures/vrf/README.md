# VRF parity fixtures

This directory holds Go-produced VRF test vectors that serve as the ground
truth for Rust-side byte-exact parity testing (see **TASK-52**, consumer).

## File format

`vectors.jsonl` — one JSON object per line (JSONL), each record:

| field    | type           | meaning                                          |
|----------|----------------|--------------------------------------------------|
| `name`   | string         | stable identifier (see *Coverage* below)         |
| `seed`   | 32-byte hex    | VRF seed (input to `VrfKeygenFromSeed`)          |
| `alpha`  | variable hex   | raw VRF message (no `HashID` prefix)             |
| `pk`     | 32-byte hex    | derived `VrfPubkey`                              |
| `sk`     | 64-byte hex    | derived `VrfPrivkey` (ed25519 `seed \|\| pk`)    |
| `proof`  | 80-byte hex    | `crypto_vrf_prove(sk, alpha)`                    |
| `output` | 64-byte hex    | `crypto_vrf_proof_to_hash(proof)` aka `β`        |

The Rust parity harness is expected to, for each record:

1. `VrfPrivkey::from_seed(seed).prove(alpha)` produces `proof` byte-for-byte.
2. `VrfProof::to_hash()` returns `output` byte-for-byte.
3. `VrfPubkey::verify(proof, alpha)` returns `Ok(output)` against the recorded
   `pk`.

## Coverage

The corpus is currently 10,198 vectors = ~198 fixed edge-case entries + 10,000
random entries.

**Fixed edge cases** (11 seeds × 18 alphas):

- Seeds: zero; `lsb=0x01`; all-`0xff`; all-`0x55`; all-`0xaa`; ascending
  `0..31`; descending `31..0`; MSB-only; LSB-only; IETF draft-irtf-cfrg-vrf-03
  TV1 and TV2 (the same seeds anchored in `crates/core/algo-consensus-crypto/
  src/vrf.rs` unit tests).
- Alphas: empty; 1-byte `0x00` / `0xff` / `0x72` (TV2's alpha); 8-, 32-, 64-,
  128-byte zero / `0xff` / counting patterns; 256- / 512- / 1024-byte counting
  and alternating `0x55/0xaa` patterns.

**Random vectors:** 10,000 `(seed, alpha)` pairs drawn from `math/rand` seeded
with the constant `0x5152_5354_5556_5758`. Alpha sizes sampled from a
consensus-weighted distribution (empty .. 1 KB; small inputs dominate).

**Spec anchors:** TV1/TV2 produce the exact `(pk, proof, output)` tuples from
draft-irtf-cfrg-vrf-03 §A.4 — see the `test_prove_tv1` / `test_prove_tv2` unit
tests in Rust's `vrf.rs` for the expected constants. If the fixture's TV1 or
TV2 entries ever fail to match those constants, treat it as a regeneration
error, not a Rust VRF bug.

## Regenerating

See `docs/DEV_WORKFLOW.md` → **VRF Vector Regeneration** for the full
procedure. Short version:

```bash
cd tools/vrf-vector-capture
go run .
```

Output is deterministic (fixed RNG seed + stable iteration order), so two
runs against the same go-algorand pin produce byte-identical `vectors.jsonl`.

## When to regenerate

- go-algorand pin bump that touches `crypto/vrf.go` or `crypto/libsodium-fork`
  (in practice: never, within a minor go-algorand release).
- Adding new fixed edge cases to the capture tool — append, don't renumber,
  so existing `name` identifiers stay stable across regenerations.

Do **not** edit `vectors.jsonl` by hand. The fixture is a build artifact of
the capture tool.
