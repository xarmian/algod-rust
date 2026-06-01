# AVM opcode conformance fixtures

Go-produced ground-truth vectors for **AVM/TEAL opcode** conformance. These
close the gap that hid **BT-294**: the byte-level conformance harness was
block-decode / state-compare oriented and had **zero** opcode coverage, so a
consensus-critical `ed25519verify` divergence shipped undetected.

Each vector is one TEAL program + LogicSig args, evaluated by go-algorand's
authoritative `logic.EvalSignatureFull` (the exact path a node takes to
validate a LogicSig transaction). The Rust replay
(`crates/tools/algo-conformance/tests/avm_opcode_conformance.rs`) runs the same
program + args through the Rust AVM and asserts the result matches go.

## File format

`vectors.jsonl` — one JSON object per line (JSONL), each record:

| field         | type            | meaning                                              |
|---------------|-----------------|------------------------------------------------------|
| `name`        | string          | stable identifier                                    |
| `description` | string          | human note (what the vector exercises)               |
| `proto`       | string          | consensus version string (the `ConsensusV41` value)  |
| `program`     | hex             | assembled program bytes (version byte + code)        |
| `args`        | array of hex    | LogicSig args (`arg 0`, `arg 1`, …)                  |
| `pass`        | bool            | go `EvalSignature` result (program approved?)        |
| `error`       | string          | go error string; **empty iff go returned no error**  |
| `final_stack` | array           | EvalContext stack at exit, bottom→top (only on success) |

`final_stack` entries are `{"t":"u","v":"<decimal>"}` for uint64 or
`{"t":"b","v":"<hex>"}` for bytes.

The replay compares:
- **error category** (errored vs. did-not-error) — go and Rust error *strings*
  differ (go embeds `pc=`/`Details:`), so an exact string match is not
  meaningful; matching the boolean *errored* category is.
- **pass** (only when neither side errored).
- **final stack** (only when neither side errored), value-for-value.

## Coverage

Crypto-verify opcodes (the priority — these are where BT-294 lived):

- `ed25519verify` (0x04): **valid** (BT-294 guard, see below), **wrong_data**
  (reject), **prehashed_sig_rejected** (BT-294 shape, reject),
  **short_sig_errors** (hard error).
- `ed25519verify_bare` (0x84): valid, wrong_data.
- `ecdsa_verify Secp256k1` (0x05/0): valid, tampered_r, wrong_msg.
- `ecdsa_verify Secp256r1` (0x05/1): valid, tampered_r.
- `vrf_verify VrfAlgorand` (0xd0): valid_empty_alpha, valid_alpha_72,
  fails_verify.

Plus cheap non-crypto sanity opcodes: `+`, `/` (div-by-zero error), `sha256`,
`concat`/`len`, `return`.

### The BT-294 guard (`ed25519verify/valid`)

go signs `Msg{ProgramHash: H(Program(program)), Data: data}` whose
`ToBeHashed` is `"ProgData" || programHash || data` with **no** extra prehash
(`crypto/util.go` `HashRep` concatenates only). The **pre-fix** Rust
`ed25519verify` SHA-512/256-prehashed that payload and therefore **rejected**
this exact go-produced signature. A passing replay of this fixture proves the
fix (commit 0552d10) and would have caught the original bug.

`ed25519verify/prehashed_sig_rejected` is the inverse: a signature over
`SHA512_256("ProgData" || H || data)`. go (and fixed Rust) verify the **raw**
payload so this is **rejected**; the pre-fix Rust would have **accepted** it.

## Regenerating

See `docs/DEV_WORKFLOW.md` → **AVM Opcode Vector Regeneration**. Short version:

```bash
cd tools/avm-opcode-capture
go run .
```

Output is deterministic (fixed RNG seed for key material + stable iteration
order), so two runs against the same go-algorand pin produce a byte-identical
`vectors.jsonl`. The capture tool enforces the pin at runtime: it refuses to
generate unless `../../../go-algorand` is on the tag tracked in `CLAUDE.md`
(`v4.5.1-stable`); override only with `--allow-unpinned`.

Do **not** edit `vectors.jsonl` by hand — it is a build artifact of the
capture tool.

## When to regenerate

- go-algorand pin bump that touches `data/transactions/logic/crypto.go`,
  `eval.go`, or `crypto/`.
- Adding new vectors to `tools/avm-opcode-capture/main.go` — append, don't
  renumber, so existing `name` identifiers stay stable.
