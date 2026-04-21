# Agreement wire-format fixtures

Go-produced canonical msgpack encodings of every agreement wire type, to
serve as ground truth for:

- **TASK-55** — codec roundtrip parity (decode-then-encode must yield the
  exact same bytes; any divergence means Rust's hand-coded codec has
  drifted from `go-algorand/agreement/msgp_gen.go`).
- **TASK-56** — msgpack fuzz harness seed corpus.

Captured by `tools/agreement-wire-capture` driving a package-internal
`_test.go` staged into `../go-algorand/agreement/`. See
`docs/DEV_WORKFLOW.md` → **Agreement Wire Vector Regeneration** for the
regeneration flow; this README describes the on-disk layout.

## Directory layout

| subdir          | Go type (package `agreement` v4.5.1-stable)                       |
|-----------------|--------------------------------------------------------------------|
| `rawvote/`      | `rawVote`                                                          |
| `uvote/`        | `unauthenticatedVote`                                              |
| `vote/`         | `vote` (authenticated)                                             |
| `ubundle/`      | `unauthenticatedBundle`                                            |
| `cert/`         | `Certificate` (= `type Certificate unauthenticatedBundle`)         |
| `bundle/`       | `bundle` (authenticated)                                           |
| `uproposal/`    | `unauthenticatedProposal`                                          |
| `proposal/`     | `proposal` (same wire bytes as `uproposal`; adds unserialized `ve`)|
| `tpayload/`     | `transmittedPayload` (= `uproposal` + `PriorVote unauthenticatedVote`) |
| `proposalvalue/`| `proposalValue` (inner schema anchor, 3 fixtures)                  |

Per-fixture files:

- `<name>.msgpack` — raw `protocol.Encode(&v)` bytes. These are the
  ground truth; the Rust codec is expected to round-trip them bit-for-bit.
- `<name>.json` — metadata sidecar: `{name, type, doc, byte_count,
  hex_head, source}`. Purely for human debuggability — no consumer
  parses it for semantics.

Each of the 6 task-required types (`vote`, `uvote`, `bundle`, `cert`,
`uproposal`, `proposal`) has **≥20 fixtures**. The capture test asserts
the count at runtime, so a refactor that silently narrows coverage
will fail regeneration.

## Fixture variation

The synthetic data is deterministic: crypto fields (signatures, VRF
proofs, Credential) are filled with predictable byte patterns keyed by
a seed byte. These are **not** cryptographically valid — canonical
msgpack encoding is a pure function of struct shape and field values,
so the fixtures probe encoder behavior without depending on signature
validity.

Coverage dimensions exercised:

- **Vote / UVote:** steps 0–5 (propose / soft / cert / next / recovery),
  bottom-proposal (nil) on step=next, varied round / period / sender
  (zero, 0xff, distinct), distinct proposal values.
- **Bundle / UBundle / Cert:** 1 / 2 / 5 / 10 / 15 / 20 vote-authenticator
  slices; 0–10 equivocation authenticators; bottom proposals; recovery
  steps; round / period at boundaries; mixed authenticator+equivocation.
- **Proposal / UProposal / TPayload:** zero-value, header-only, with /
  without seed proof, all-`0x00` / all-`0xff` seed-proof patterns,
  round = 0 / 1 / 100 / 1000 / 10M / u32::MAX, varied original period /
  proposer.

The smallest fixtures are 1 byte (zero-valued structs encode to a
single msgpack sentinel); the largest is ~34 KB
(`bundle/full_mix.msgpack`: 20 authenticated votes + 5 equivocation
votes, each carrying a OneTimeSignature + Credential).

## Regeneration

From the repo root:

```bash
cd tools/agreement-wire-capture
go run .
```

Takes ~40 s (dominated by Go test binary compilation in
`../go-algorand/agreement/`; the fixture dump itself runs in ~20 ms).
Output is deterministic across runs — `diff -r` against the committed
corpus must match byte-for-byte.

Do **not** edit these files by hand. They are build artifacts of the
capture tool; any drift breaks the TASK-55 roundtrip parity.
