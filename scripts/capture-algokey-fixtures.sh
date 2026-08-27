#!/usr/bin/env bash
#
# Capture algokey fixtures from go-algorand for byte-equal parity tests.
#
# Usage:
#   ALGOKEY=$(which algokey) bash scripts/capture-algokey-fixtures.sh
#
# Or, with a hand-built binary:
#   cd ../go-algorand && go build -o /tmp/algokey-go ./cmd/algokey
#   ALGOKEY=/tmp/algokey-go bash scripts/capture-algokey-fixtures.sh
#
# Requires go-algorand pinned to v4.7.2-stable (the version this repo
# tracks). The script regenerates every file under
# crates/tools/algokey-rust/tests/fixtures/algokey/ from scratch.
#
# Fixture seeds are a deterministic mix of all-zero, all-ones, and
# SHA-256(NATO phonetic) — matches the corpus used by
# crates/core/algo-consensus-crypto/tests/passphrase_parity.rs.

set -euo pipefail

ALGOKEY="${ALGOKEY:-algokey}"

if ! command -v "$ALGOKEY" >/dev/null 2>&1; then
    echo "error: ALGOKEY=$ALGOKEY not found on PATH" >&2
    echo "Build it with: (cd ../go-algorand && go build -o /tmp/algokey-go ./cmd/algokey)" >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FIX_DIR="$REPO_ROOT/crates/tools/algokey-rust/tests/fixtures/algokey"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$FIX_DIR/import" "$FIX_DIR/export"

# Mnemonics + matching seed-hex captured from passphrase_parity.rs
# (TASK-156). Each pair is `<seed_hex>:<mnemonic>`. Keep this list in
# sync with the parity-test corpus.
read -r -d '' FIXTURES <<'EOF' || true
0000000000000000000000000000000000000000000000000000000000000000:abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invest
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff:zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo abstract adapt
8ed3f6ad685b959ead7022518e1af76cd816f8e8ec7ccdda1ed4018e8f2223f8:impact swap finger repair click guilt lyrics carbon sketch health knee man color dignity guard language fluid kiwi tube theme business silly scissors abstract festival
f144a6907dc4284d1f9fe6a7d9b9ff53c02c1d07ba68f24d413d7ff7f757a782:owner october sign elephant face spy wedding track crunch trash zone ahead flower shrug south hamster salad ahead pact jewel useful sting benefit above throw
b9dd960c1753459a78115d3cb845a57d924b6877e805b08bd01086ccdf34433c:rescue fork main cousin melt charge mesh fringe always black sport chief now sure dry album invite drama anchor silent sauce snake tilt ability blue
4f4a9410ffcdf895c4adb880659e9b5c0dd1f23a30790684340b3eaacb045398:enemy eye marriage that various century hotel reward quote kangaroo evidence still pear royal limb junior liar spirit airport physical nuclear scorpion secret above mimic
092c79e8f80e559e404bcf660c48f3522b67aba9ff1484b0367e1a4ddef7431d:license tool injury usage present chest foam soon mimic cage keen release soft hello wool belt awesome suspect disease spider route worth tube abandon bind
9533327a239046b9fb62ee9b412bcd93a098721f6b4f72095b2612e4eedea38e:increase silver rug acquire minor unusual blind unveil cricket public track ankle course syrup flight exhaust comic history basket donkey tape waste insect above move
625fe74cad4600b5e8b76a9283333eb79052ae50d6af7f660feb4831d87af5d2:unable output please hello above coil satisfy height inch sock pair arena pioneer clog raw quit soup diesel intact behind race gadget nut absorb kitten
8d53a3e3672946bd802cd2037f1d5da8a61081910cb4054a882b905a51550125:immune minute vault nose middle consider goat split there invest company hedgehog candy gate goose reduce doll cancel beyond poverty pencil fetch chimney ability come
EOF

i=0
while IFS=":" read -r seed_hex mnemonic; do
    if [[ -z "$seed_hex" ]]; then
        continue
    fi
    i=$((i + 1))
    name=$(printf "case_%02d" "$i")

    # Import fixture: stdout from `algokey import -m "<mnemonic>"`.
    "$ALGOKEY" import -m "$mnemonic" >"$FIX_DIR/import/$name.stdout"

    # Export fixture: write the seed to a keyfile (matching Go's raw
    # 32-byte format) then capture `algokey export -f keyfile`.
    keyfile="$TMP/key_$name"
    # Decode the hex via xxd into raw bytes for the keyfile.
    printf '%s' "$seed_hex" | xxd -r -p >"$keyfile"
    chmod 0600 "$keyfile"
    "$ALGOKEY" export -f "$keyfile" >"$FIX_DIR/export/$name.stdout"

    # Also commit the keyfile bytes so the parity test can read them
    # without a Go binary at test time.
    cp "$keyfile" "$FIX_DIR/export/$name.keyfile"
done <<<"$FIXTURES"

cat >"$FIX_DIR/README.md" <<EOF
# algokey Phase A fixtures

Captured from \`../go-algorand\` pinned to \`v4.7.2-stable\` via
\`scripts/capture-algokey-fixtures.sh\`.

- \`import/case_NN.stdout\` — output of \`algokey import -m "<mnemonic>"\`
  for each \`(seed, mnemonic)\` pair below.
- \`export/case_NN.keyfile\` — raw 32-byte seed.
- \`export/case_NN.stdout\` — output of \`algokey export -f <keyfile>\`.

The 10 cases use the seed/mnemonic pairs from
\`crates/core/algo-consensus-crypto/tests/passphrase_parity.rs\`:

| # | seed (hex)                                                       |
|---|------------------------------------------------------------------|
EOF

i=0
while IFS=":" read -r seed_hex mnemonic; do
    if [[ -z "$seed_hex" ]]; then
        continue
    fi
    i=$((i + 1))
    printf '| %d | \`%s\` |\n' "$i" "$seed_hex" >>"$FIX_DIR/README.md"
done <<<"$FIXTURES"

cat >>"$FIX_DIR/README.md" <<'EOF'

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
EOF

echo "Captured $i fixture cases under $FIX_DIR"

# ---------------------------------------------------------------------------
# Phase C captures: partkey DB + `part info` stdout
# ---------------------------------------------------------------------------

PART_FIX_DIR="$REPO_ROOT/crates/tools/algokey-rust/tests/fixtures/partkey"
mkdir -p "$PART_FIX_DIR/part_info_outputs"

# Deterministic checksummed test address used as `--parent`.
# Phase C parity tests assert against the same string.
TEST_PARENT="7777777777777777777777777777777777777777777777777774MSJUVU"

capture_partkey() {
    local name="$1"
    local first="$2"
    local last="$3"
    local dilution="$4"
    local db_path="$PART_FIX_DIR/$name.db"
    local stdout_path="$PART_FIX_DIR/part_info_outputs/$name.stdout"

    rm -f "$db_path" "$db_path-shm" "$db_path-wal"
    echo "Generating partkey fixture: $name (first=$first last=$last dilution=$dilution)"
    "$ALGOKEY" part generate \
        --keyfile "$db_path" \
        --first "$first" --last "$last" \
        --dilution "$dilution" \
        --parent "$TEST_PARENT" \
        >/dev/null

    "$ALGOKEY" part info --keyfile "$db_path" >"$stdout_path"
    # Strip WAL/SHM sidecars so only the canonical DB ships in-tree.
    rm -f "$db_path-shm" "$db_path-wal"
}

# Small fixture used by tests/part_info_parity.rs.
capture_partkey "small_with_sp" 1 512 100

echo "Captured Phase C partkey fixtures under $PART_FIX_DIR"
