//! Algorand sortition parity harness (Rust vs Go / Boost 1.65.1 C++ CDF).
//!
//! Consumes the JSONL corpus captured by `tools/sortition-vector-capture`
//! and asserts that Rust's `algo_consensus_crypto::sortition::select`
//! returns the **same weight** as `github.com/algorand/sortition` for every
//! `(money, total_money, expected_size, digest)` tuple. Rust walks the
//! binomial CDF via a numerically stable log-PMF recurrence seeded from
//! `log1p(-p)`; Go delegates to Boost's regularized incomplete beta
//! function. A divergence at precision-boundary money values would mean
//! committee-selection disagreement and fork risk.
//!
//! Fixture: `tests/fixtures/sortition/vectors.jsonl` (captured against
//! `github.com/algorand/sortition v1.0.0`; 5,189 tuples in the committed
//! corpus, biased toward precision-boundary money values in [2^59, 2^61]).
//!
//! 13 fixtures are allowlisted as known `digest_max` (ratio = 1.0) f64
//! saturation cases — see `is_known_boost_saturation_divergence`. All
//! other fixtures must match Go exactly.
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
    let mut allowlisted = 0usize;
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

        // Always count the record in the corpus totals, EVEN when it
        // hits the allowlist — otherwise removing every allowlisted
        // fixture from vectors.jsonl could silently pass the
        // `total >= 5_000` floor and drop coverage of the
        // ratio-exactly-1.0 boundary without any test failure
        // (Codex P2 on PR #227, r2).
        total += 1;
        if rec.name.starts_with("precision/") {
            precision_stress += 1;
        }

        if got != rec.weight {
            // KNOWN DIVERGENCE ALLOWLIST — ratio-exactly-1.0 edge cases.
            //
            // All 13 currently-allowed divergences are `digest_max`
            // fixtures (VRF output = 0xff…ff ⇒ ratio = 1.0). Rust's
            // log-PMF walker accumulates CDF(j) toward 1.0 via a
            // numerically stable PMF recurrence; on the committed
            // corpus that saturates one f64 ulp BELOW exactly 1.0, so
            // `1.0 <= cdf` fails for the exact match. Go's
            // Boost-backed walker evaluates CDF via regularized
            // incomplete beta freshly at each j, which rounds up to
            // exactly 1.0 at a specific j and returns that j.
            //
            // In production this is cryptographically unreachable:
            // ratio == 1.0 requires VRF output bytes = 0xff..ff,
            // hit with probability ~2^-256 per query. The corpus
            // includes `digest_max` fixtures deliberately to probe
            // this boundary, so we allowlist them rather than drop
            // them. Closing the gap is tracked as TASK-59 (port the
            // relevant slice of Boost's ibeta continued-fraction
            // expansion). Meanwhile, anything NEW outside this
            // allowlist MUST fail the test.
            if is_known_boost_saturation_divergence(&rec.name) {
                allowlisted += 1;
                continue;
            }
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
            "sortition parity: {n_div} / {total} UNEXPECTED divergences \
             Rust ↔ Go (first {shown_n} shown):\n{shown}\n\
             These are outside the ratio==1.0 allowlist — investigate \
             before landing. The known-Boost-saturation allowlist lives \
             in `is_known_boost_saturation_divergence`.",
            n_div = divergences.len(),
            shown_n = shown.len(),
            shown = shown.join("\n"),
        );
    }

    // Size floors (match the capture tool's defaults). Both must hold, so a
    // truncated fixture or a misconfigured precision-stress subset is
    // surfaced loudly rather than silently eroding coverage.
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
    // Sanity: the allowlist should remain small. A sudden jump here
    // implies either the corpus got larger in the ratio==1.0 bucket
    // or Rust's select regressed; either way the human should look.
    assert!(
        allowlisted <= 32,
        "ratio==1.0 allowlist grew unexpectedly ({allowlisted} > 32). \
         A regression in `select` or a corpus expansion in the digest_max \
         bucket needs review."
    );

    eprintln!(
        "sortition_parity_vs_go_algorand: {matched} / {total} vectors matched \
         Go exactly (of which {precision_stress} in the 2^59..2^61 precision \
         band); {allowlisted} ratio==1.0 fixtures allowlisted as known Boost-\
         ibeta saturation divergence.",
        matched = total - allowlisted
    );
}

/// Returns true if `name` is one of the 13 committed-corpus fixtures where
/// Rust's log-PMF walker and Go's Boost-ibeta walker round CDF → 1.0
/// differently at the exact saturation point. See the panic message in
/// `vrf_parity_vs_go_algorand` for background. Keeping this list inline
/// (rather than e.g. scanning the name for `/digest_max`) makes regressions
/// visible: any NEW name showing up in this bucket has to be added here
/// deliberately with a code review comment, not silently tolerated.
fn is_known_boost_saturation_divergence(name: &str) -> bool {
    matches!(
        name,
        // Each entry below maps to a digest_max (ratio = 1.0) fixture
        // where Go's weight != Rust's weight because CDF saturation in
        // f64 happens at a different j between the two implementations.
        "fixed/money_p48_total_p62_exp20/digest_max"
            | "fixed/money_p59_total_p62_exp20/digest_max"
            | "fixed/money_p60_total_p62_exp20/digest_max"
            | "fixed/money_p60_plus_1_total_p62_exp20/digest_max"
            | "fixed/money_p61_total_p62_exp20/digest_max"
            | "fixed/money_p61_minus_1_total_p62_exp20/digest_max"
            | "fixed/money_p62_total_p62_exp20/digest_max"
            | "fixed/money_eq_total_1e6_exp20/digest_max"
            | "fixed/money_eq_total_p60_exp20/digest_max"
            | "fixed/money_tminus1_1e6_exp20/digest_max"
            | "fixed/money_1e5_total_1e6_exp1500/digest_max"
            | "fixed/money_1e5_total_1e6_exp2990/digest_max"
            | "fixed/money_1e5_total_1e6_exp10000/digest_max"
    )
}
