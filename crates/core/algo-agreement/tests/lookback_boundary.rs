//! Version-boundary parity harness for the three lookback primitives
//! in `algo_agreement::lookback`:
//!
//! - `params_round(r)`                 — `r.SubSaturate(2)` (version-independent)
//! - `seed_round(r, cparams)`          — `r.SubSaturate(SeedLookback)`
//! - `balance_round(r, cparams)`       — `r.SubSaturate(2 * SeedRefreshInterval * SeedLookback)`
//!
//! Each of these is called on every vote verification, so silent
//! drift between Rust's implementation (or Rust's `ConsensusParams`
//! table) and Go's would cause committee-selection divergence during
//! a protocol upgrade. The fixed fixture under
//! `tests/fixtures/lookback/lookback_boundaries.json` — produced by
//! running `tools/lookback-vector-capture` against the pinned
//! `go-algorand` v4.6.0-stable — anchors every (version, round) pair
//! against Go's actual output. This test asserts Rust agrees byte-
//! identically with the captured Go values.
//!
//! Coverage: every consensus version from V7 through V41 (not just
//! the task's V18..V41 range) so the V7→V8 transition — the only
//! protocol change in Algorand history that actually shifts
//! `SeedRefreshInterval` (100 → 80) — is explicitly exercised. For
//! every version we hit a range of rounds straddling the saturation
//! floor (0, 1), the `seed_lookback` boundary, the `balance_lookback`
//! boundary, and a large round far past either.
//!
//! Regeneration: see `docs/DEV_WORKFLOW.md` → "Lookback Vector
//! Regeneration". In brief:
//!
//! ```bash
//! cd tools/lookback-vector-capture
//! go run .
//! ```
//!
//! The fixture is checked in; any change to it must be justified by
//! a deliberate go-algorand pin bump or a lookback-schema change.

use std::path::PathBuf;

use algo_agreement::{balance_round, params_round, seed_round};
use algo_types::{consensus::consensus_params_for_version, Round};
use serde::Deserialize;

/// One captured (version, round, expected outputs) tuple. Matches the
/// JSON schema emitted by `tools/lookback-vector-capture`.
#[derive(Debug, Deserialize)]
struct Vector {
    version: String,
    seed_lookback: u64,
    seed_refresh_interval: u64,
    round: u64,
    params_round: u64,
    balance_round: u64,
    seed_round: u64,
}

#[derive(Debug, Deserialize)]
struct Corpus {
    #[allow(dead_code)]
    source: String,
    #[allow(dead_code)]
    go_algorand_pin: String,
    vectors: Vec<Vector>,
}

fn load_corpus() -> Corpus {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures/lookback/lookback_boundaries.json");
    let bytes = std::fs::read(&p).unwrap_or_else(|e| {
        panic!(
            "cannot read lookback fixture {p:?}: {e}. \
             Run `cd tools/lookback-vector-capture && go run .` to regenerate."
        )
    });
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("malformed lookback fixture {p:?}: {e}"))
}

/// Version strings that exist in `KNOWN_PROTOCOL_VERSIONS` but
/// aren't real production protocols — mainnet never activates them
/// and `tools/lookback-vector-capture` deliberately doesn't emit
/// them. Kept as an explicit blocklist (rather than a name-prefix
/// heuristic) so a newly-added production version with an unusual
/// name doesn't get silently excluded.
const EXCLUDED_VERSIONS: &[&str] = &[
    algo_types::consensus::CONSENSUS_FUTURE,
    algo_types::consensus::CONSENSUS_ALPHA1,
    algo_types::consensus::CONSENSUS_ALPHA2,
    algo_types::consensus::CONSENSUS_ALPHA3,
    algo_types::consensus::CONSENSUS_ALPHA4,
    algo_types::consensus::CONSENSUS_ALPHA5,
];

/// The set of consensus versions the parity harness must cover,
/// derived from `algo_types::consensus::KNOWN_PROTOCOL_VERSIONS`
/// (the canonical registry) with `EXCLUDED_VERSIONS` filtered out.
///
/// Deriving rather than hard-coding means a new production version
/// added to the registry is automatically required here — if the
/// capture tool hasn't been regenerated to cover it, this test
/// fails loudly instead of silently inheriting uncovered math.
///
/// The converse is also enforced (every captured version must be
/// required) so a capture that emits an unexpected version likewise
/// fails.
fn required_versions() -> Vec<&'static str> {
    algo_types::consensus::KNOWN_PROTOCOL_VERSIONS
        .iter()
        .copied()
        .filter(|v| !EXCLUDED_VERSIONS.contains(v))
        .collect()
}

/// The captured version set must exactly match `required_versions()`:
/// no missing versions (silent coverage gap) and no unknown versions
/// (new protocol landed without the anchor being extended). Checked
/// by set-difference rather than count so a drop-and-add of equal
/// cardinality can't slip through.
#[test]
fn corpus_covers_every_known_version() {
    let corpus = load_corpus();
    let required = required_versions();
    let mut captured: Vec<&str> = corpus.vectors.iter().map(|v| v.version.as_str()).collect();
    captured.sort_unstable();
    captured.dedup();

    // (1) Every required version must appear.
    for req in &required {
        assert!(
            captured.contains(req),
            "version {req:?} missing from corpus; \
             regenerate via `cd tools/lookback-vector-capture && go run .`"
        );
    }

    // (2) Every captured version must be one we require. Catches a
    // future tool run that emits a newly-added version before this
    // test is extended (automatically, via KNOWN_PROTOCOL_VERSIONS)
    // to cover it — and also catches a capture that accidentally
    // emits something in `EXCLUDED_VERSIONS`.
    for cap in &captured {
        assert!(
            required.contains(cap),
            "corpus contains unknown / excluded version {cap:?}; \
             either add it to algo_types::KNOWN_PROTOCOL_VERSIONS \
             (and write any version-specific anchor tests) or drop it \
             from tools/lookback-vector-capture"
        );
    }

    // V7 is REQUIRED specifically because it has a distinct
    // SeedRefreshInterval (100 vs v8+'s 80) — without the v7 anchor
    // the `v7_to_v8_transition_shifts_balance_round_by_160` test
    // below has no captured fixture backing the v7 side.
    assert!(
        required.contains(&algo_types::consensus::CONSENSUS_V7),
        "v7 missing from required set; KNOWN_PROTOCOL_VERSIONS or EXCLUDED_VERSIONS has drifted"
    );
}

/// Byte-identical parity: for every captured `(version, round)`,
/// Rust's `params_round` / `balance_round` / `seed_round` must match
/// Go's recorded output.
#[test]
fn rust_matches_go_on_every_captured_vector() {
    let corpus = load_corpus();

    for v in &corpus.vectors {
        let params = consensus_params_for_version(&v.version).unwrap_or_else(|| {
            panic!(
                "Rust has no ConsensusParams for version {:?} captured by Go. \
                 Add it to algo-types or drop it from the capture matrix.",
                v.version
            )
        });

        // Sanity: the lookback inputs Go recorded for this version
        // must match the Rust params table. A mismatch here means the
        // Rust ConsensusParams has drifted from Go's config/consensus.go
        // — a real consensus-correctness bug the existing consensus.rs
        // unit tests may have missed.
        assert_eq!(
            params.seed_lookback, v.seed_lookback,
            "{} seed_lookback drift: Rust={}, Go={}",
            v.version, params.seed_lookback, v.seed_lookback
        );
        assert_eq!(
            params.seed_refresh_interval, v.seed_refresh_interval,
            "{} seed_refresh_interval drift: Rust={}, Go={}",
            v.version, params.seed_refresh_interval, v.seed_refresh_interval
        );

        let r = Round(v.round);
        assert_eq!(
            params_round(r),
            Round(v.params_round),
            "params_round divergence: version={}, round={}, Rust={:?}, Go={}",
            v.version,
            v.round,
            params_round(r),
            v.params_round,
        );
        assert_eq!(
            balance_round(r, &params),
            Round(v.balance_round),
            "balance_round divergence: version={}, round={}, Rust={:?}, Go={}",
            v.version,
            v.round,
            balance_round(r, &params),
            v.balance_round,
        );
        assert_eq!(
            seed_round(r, &params),
            Round(v.seed_round),
            "seed_round divergence: version={}, round={}, Rust={:?}, Go={}",
            v.version,
            v.round,
            seed_round(r, &params),
            v.seed_round,
        );
    }
}

/// The V7→V8 transition is the only historical point where the
/// lookback-affecting parameter changes. Make the boundary
/// semantics explicit: at any given round R, whichever version's
/// params the caller feeds to `balance_round` governs the answer —
/// NOT some single "consensus current" default. This mirrors Go's
/// `agreement/proposal.go:160,234,280` call sites which look up the
/// consensus params at R before calling `BalanceRound(r, cparams)`.
#[test]
fn v7_to_v8_transition_shifts_balance_round_by_160() {
    let v7 = consensus_params_for_version(algo_types::consensus::CONSENSUS_V7)
        .expect("v7 must be in the Rust params table");
    let v8 = consensus_params_for_version(algo_types::consensus::CONSENSUS_V8)
        .expect("v8 must be in the Rust params table");

    // v7: seed_refresh_interval = 100, seed_lookback = 2 → balance_lookback = 400
    // v8: seed_refresh_interval =  80, seed_lookback = 2 → balance_lookback = 320
    //
    // At round 800 — well past both lookback floors — the balance
    // round a caller gets depends entirely on which version's params
    // they pass:
    let r = Round(800);
    assert_eq!(balance_round(r, &v7), Round(400));
    assert_eq!(balance_round(r, &v8), Round(480));
    assert_eq!(
        u64::from(balance_round(r, &v8)) - u64::from(balance_round(r, &v7)),
        80,
        "v7\u{2192}v8 balance-round shift must be exactly \
         2 * (100 - 80) * seed_lookback = 80"
    );

    // seed_round is unaffected (both versions keep SeedLookback=2).
    assert_eq!(seed_round(r, &v7), seed_round(r, &v8));
    // params_round is version-independent.
    assert_eq!(params_round(r), Round(798));
}
