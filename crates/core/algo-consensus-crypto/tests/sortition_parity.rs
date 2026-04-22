//! Algorand sortition parity harness (Rust vs Go / Boost 1.65.1 C++ CDF).
//!
//! Consumes the JSONL corpus captured by `tools/sortition-vector-capture`
//! and asserts that Rust's `algo_consensus_crypto::sortition::select`
//! returns the **same weight** as `github.com/algorand/sortition` for every
//! `(money, total_money, expected_size, digest)` tuple. Rust walks the
//! binomial CDF via a numerically stable log-PMF recurrence seeded from
//! `log1p(-p)`, with a Boost-equivalent tail-bound saturation check for
//! the `ratio == 1.0` boundary (TASK-59); Go delegates to Boost's
//! regularized incomplete beta function. A divergence at precision-
//! boundary money values would mean committee-selection disagreement
//! and fork risk.
//!
//! Fixture: `tests/fixtures/sortition/vectors.jsonl` (captured against
//! `github.com/algorand/sortition v1.0.0`; 5,189 tuples in the committed
//! corpus, biased toward precision-boundary money values in [2^59, 2^61]).
//!
//! Every fixture must match Go exactly. No allowlist.
//!
//! References:
//!   - go-algorand `data/committee/credential.go:106` — production call site
//!   - sortition@v1.0.0 `sortition.go:44` — Go `Select`
//!   - sortition@v1.0.0 `sortition.cpp:10` — Boost CDF walk
//!   - Rust `src/sortition.rs:92` — `select` under test

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

use algo_consensus_crypto::sortition;
use serde::Deserialize;

/// One JSONL record. Use the `_hex` u64 variants to avoid JSON-number
/// precision loss above 2^53 — `money` and `total_money` commonly sit in
/// the 2^60 range where decoding a JSON number as f64 would truncate.
#[derive(Debug, Deserialize)]
struct Record {
    name: String,
    money_hex: String,
    total_money_hex: String,
    expected_size: f64,
    digest: String,
    weight: u64,
}

fn fixture_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures/sortition/vectors.jsonl");
    p
}

/// Parse a `0xHEXHEXHEX…` u64 rendered with zero-padded width 16.
fn parse_hex_u64(field: &str, s: &str) -> u64 {
    let stripped = s
        .strip_prefix("0x")
        .unwrap_or_else(|| panic!("fixture: {field} missing 0x prefix (value={s:?})"));
    u64::from_str_radix(stripped, 16)
        .unwrap_or_else(|e| panic!("fixture: {field} not a valid hex u64: {e} (value={s:?})"))
}

fn parse_digest(field: &str, s: &str) -> [u8; 32] {
    let v = hex::decode(s)
        .unwrap_or_else(|e| panic!("fixture: {field} is not valid hex: {e} (value={s:?})"));
    v.as_slice()
        .try_into()
        .unwrap_or_else(|_| panic!("fixture: {field} is {} bytes, expected 32", v.len()))
}

#[test]
fn sortition_parity_vs_go_algorand() {
    let path = fixture_path();
    let file = File::open(&path).unwrap_or_else(|e| {
        panic!(
            "cannot open sortition fixture {path:?}: {e}.\n\
             Run `cd tools/sortition-vector-capture && go run .` to regenerate \
             (see docs/DEV_WORKFLOW.md → Sortition Vector Regeneration)."
        )
    });

    let mut total = 0usize;
    let mut precision_stress = 0usize;
    let mut digest_max = 0usize;
    let mut divergences: Vec<String> = Vec::new();
    for (line_no, line) in BufReader::new(file).lines().enumerate() {
        let line = line.expect("read fixture line");
        if line.is_empty() {
            continue;
        }
        let rec: Record = serde_json::from_str(&line).unwrap_or_else(|e| {
            panic!("fixture parse error at line {line_no}: {e}\n  raw: {line}")
        });

        let money = parse_hex_u64("money_hex", &rec.money_hex);
        let total_money = parse_hex_u64("total_money_hex", &rec.total_money_hex);
        let digest = parse_digest("digest", &rec.digest);

        let got = sortition::select(money, total_money, rec.expected_size, digest);

        total += 1;
        if rec.name.starts_with("precision/") {
            precision_stress += 1;
        }
        // Track digest_max (ratio = 1.0) fixtures explicitly. Before TASK-59
        // these were allowlisted as known Boost-ibeta saturation
        // divergences; now they must match Go byte-for-byte. Asserting a
        // minimum coverage here means that if the capture tool ever drops
        // the `digest_max` digest pattern we notice.
        if rec.name.ends_with("/digest_max") {
            digest_max += 1;
        }

        if got != rec.weight {
            divergences.push(format!(
                "fixture {name:?}: money={money} (0x{money:016x}) \
                 total={total_money} (0x{total_money:016x}) \
                 expected_size={expected} \
                 digest={digest_hex} \
                 go_weight={go} rust_weight={rust}",
                name = rec.name,
                expected = rec.expected_size,
                digest_hex = rec.digest,
                go = rec.weight,
                rust = got,
            ));
        }
    }

    if !divergences.is_empty() {
        let shown = divergences.iter().take(20).cloned().collect::<Vec<_>>();
        panic!(
            "sortition parity: {n_div} / {total} divergences \
             Rust ↔ Go (first {shown_n} shown):\n{shown}\n\
             TASK-59 closed the ratio==1.0 allowlist — any divergence \
             here is a new regression; investigate before landing.",
            n_div = divergences.len(),
            shown_n = shown.len(),
            shown = shown.join("\n"),
        );
    }

    // Size floors (match the capture tool's defaults). All three must hold,
    // so a truncated fixture, a misconfigured precision-stress subset, or a
    // dropped `digest_max` pattern gets surfaced loudly rather than
    // silently eroding coverage.
    assert!(
        total >= 5_000,
        "sortition parity fixture is unexpectedly small ({total} records). \
         Regenerate via `cd tools/sortition-vector-capture && go run .`."
    );
    assert!(
        precision_stress >= 200,
        "precision-stress subset too small ({precision_stress} records, need ≥200). \
         The capture tool's `--precision` flag may have been lowered."
    );
    assert!(
        digest_max >= 13,
        "digest_max (ratio = 1.0) fixture coverage too small ({digest_max} records, need ≥13). \
         TASK-59 explicitly validates this boundary — don't drop it from the corpus."
    );

    eprintln!(
        "sortition_parity_vs_go_algorand: {total} / {total} vectors matched \
         Go exactly (of which {precision_stress} in the 2^59..2^61 precision \
         band and {digest_max} ratio==1.0 saturation-boundary fixtures)."
    );
}
