# algokey Phase A fixtures

Captured from `../go-algorand` pinned to `v4.5.1-stable` via
`scripts/capture-algokey-fixtures.sh`.

- `import/case_NN.stdout` — output of `algokey import -m "<mnemonic>"`
  for each `(seed, mnemonic)` pair below.
- `export/case_NN.keyfile` — raw 32-byte seed.
- `export/case_NN.stdout` — output of `algokey export -f <keyfile>`.

The 10 cases use the seed/mnemonic pairs from
`crates/core/algo-consensus-crypto/tests/passphrase_parity.rs`:

| # | seed (hex)                                                       |
|---|------------------------------------------------------------------|
| 1 | \`0000000000000000000000000000000000000000000000000000000000000000\` |
| 2 | \`ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\` |
| 3 | \`8ed3f6ad685b959ead7022518e1af76cd816f8e8ec7ccdda1ed4018e8f2223f8\` |
| 4 | \`f144a6907dc4284d1f9fe6a7d9b9ff53c02c1d07ba68f24d413d7ff7f757a782\` |
| 5 | \`b9dd960c1753459a78115d3cb845a57d924b6877e805b08bd01086ccdf34433c\` |
| 6 | \`4f4a9410ffcdf895c4adb880659e9b5c0dd1f23a30790684340b3eaacb045398\` |
| 7 | \`092c79e8f80e559e404bcf660c48f3522b67aba9ff1484b0367e1a4ddef7431d\` |
| 8 | \`9533327a239046b9fb62ee9b412bcd93a098721f6b4f72095b2612e4eedea38e\` |
| 9 | \`625fe74cad4600b5e8b76a9283333eb79052ae50d6af7f660feb4831d87af5d2\` |
| 10 | \`8d53a3e3672946bd802cd2037f1d5da8a61081910cb4054a882b905a51550125\` |

## Refreshing

```bash
(cd ../go-algorand && go build -o /tmp/algokey-go ./cmd/algokey)
ALGOKEY=/tmp/algokey-go bash scripts/capture-algokey-fixtures.sh
git diff crates/tools/algokey-rust/tests/fixtures/algokey/  # should be empty
```

## generate

`algokey generate` draws from `crypto/rand` and exposes no
deterministic-seed mode, so we don't capture stdout fixtures for it. The
byte-equal parity for the random path is covered by the zero-vector
unit test in `src/commands/generate.rs` (a fixed seed injected via
`run_with_seed`).
