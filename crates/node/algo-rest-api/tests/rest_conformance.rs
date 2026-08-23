//! REST conformance harness (TASK-255).
//!
//! A partner to `algo-conformance` (which covers block *codec* conformance):
//! this harness drives the Rust REST response builders and diffs their output,
//! field-for-field, against go-algorand v4.6.0-stable reference responses,
//! emitting a per-endpoint / per-field report and failing on any drift.
//!
//! It is fixture-driven and extensible: each [`Case`] pairs an endpoint name
//! with the Rust-produced JSON and the captured Go reference JSON. The
//! representative seed set covers the block endpoint (reusing the
//! `fixtures/block_json` references) and `GET /v2/transactions/params`. The
//! account / asset / application endpoints are conformance-tested in
//! `account_roundtrip_test.rs`; further endpoints can be added here as their
//! references are captured.
//!
//! The known-501 group-delta endpoints are intentionally excluded until they
//! are implemented (TASK-256 / TASK-257).

use algo_rest_api::block_json::encode_block_json;

/// A single field-level difference between the Rust and Go responses.
#[derive(Debug, Clone)]
struct Mismatch {
    path: String,
    expected: String,
    actual: String,
}

/// Result of comparing one endpoint response.
struct CaseResult {
    endpoint: String,
    mismatches: Vec<Mismatch>,
}

impl CaseResult {
    fn passed(&self) -> bool {
        self.mismatches.is_empty()
    }
}

/// Recursively diff two JSON values, collecting field-path-level mismatches
/// (order-independent for objects). This is the harness's reusable comparison
/// primitive — it reports *where* responses drift, not just that they differ.
fn diff_json(
    path: &str,
    expected: &serde_json::Value,
    actual: &serde_json::Value,
    out: &mut Vec<Mismatch>,
) {
    use serde_json::Value as V;
    match (expected, actual) {
        (V::Object(e), V::Object(a)) => {
            let mut keys: Vec<&String> = e.keys().chain(a.keys()).collect();
            keys.sort();
            keys.dedup();
            for k in keys {
                let child = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                match (e.get(k), a.get(k)) {
                    (Some(ev), Some(av)) => diff_json(&child, ev, av, out),
                    (Some(ev), None) => out.push(Mismatch {
                        path: child,
                        expected: ev.to_string(),
                        actual: "<missing>".into(),
                    }),
                    (None, Some(av)) => out.push(Mismatch {
                        path: child,
                        expected: "<missing>".into(),
                        actual: av.to_string(),
                    }),
                    (None, None) => unreachable!(),
                }
            }
        }
        (V::Array(e), V::Array(a)) => {
            if e.len() != a.len() {
                out.push(Mismatch {
                    path: format!("{path}.len"),
                    expected: e.len().to_string(),
                    actual: a.len().to_string(),
                });
            }
            for (i, (ev, av)) in e.iter().zip(a.iter()).enumerate() {
                diff_json(&format!("{path}[{i}]"), ev, av, out);
            }
        }
        (e, a) if e != a => out.push(Mismatch {
            path: path.to_string(),
            expected: e.to_string(),
            actual: a.to_string(),
        }),
        _ => {}
    }
}

struct Case {
    endpoint: String,
    actual: serde_json::Value,
    expected: serde_json::Value,
}

fn run_case(c: Case) -> CaseResult {
    let mut mismatches = Vec::new();
    diff_json("", &c.expected, &c.actual, &mut mismatches);
    CaseResult {
        endpoint: c.endpoint,
        mismatches,
    }
}

const BLOCK_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/block_json");

/// Block endpoint cases: re-encode each stored `{block,cert}` msgpack as
/// canonical JSON and diff against the Go `JSONStrictHandle` reference.
fn block_cases() -> Vec<Case> {
    [
        "block1",
        "block_1",
        "block_2",
        "block_3",
        "block_5",
        "block_9",
        "synthetic_appl",
    ]
    .into_iter()
    .map(|name| {
        let msgpack = std::fs::read(format!("{BLOCK_DIR}/{name}.msgpack")).unwrap();
        let golden = std::fs::read_to_string(format!("{BLOCK_DIR}/{name}.json")).unwrap();
        let actual_bytes = encode_block_json(&msgpack).expect("encode block json");
        Case {
            endpoint: format!("GET /v2/blocks/{{round}} [{name}]"),
            actual: serde_json::from_slice(&actual_bytes).unwrap(),
            expected: serde_json::from_str(&golden).unwrap(),
        }
    })
    .collect()
}

/// `GET /v2/transactions/params` (`model.TransactionParametersResponse`). The
/// model is a direct field mapping; the reference documents Go's field names
/// and the base64 encoding of `genesis-hash`.
fn transaction_params_case() -> Case {
    use algo_rest_api::handlers::TransactionParametersResponse;
    use base64::Engine;

    let gh = vec![0xABu8; 32];
    let resp = TransactionParametersResponse {
        consensus_version: "future".into(),
        fee: 0,
        genesis_hash: gh.clone(),
        genesis_id: "testnet-v1.0".into(),
        last_round: 12345,
        min_fee: 1000,
    };
    let expected = serde_json::json!({
        "consensus-version": "future",
        "fee": 0,
        "genesis-hash": base64::engine::general_purpose::STANDARD.encode(&gh),
        "genesis-id": "testnet-v1.0",
        "last-round": 12345,
        "min-fee": 1000,
    });
    Case {
        endpoint: "GET /v2/transactions/params".into(),
        actual: serde_json::to_value(&resp).unwrap(),
        expected,
    }
}

const ACCOUNT_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/account_roundtrip"
);

/// `GET /v2/accounts/{addr}` (`model.Account`, JSON). Reuses the offline-minimal
/// reference from the account roundtrip fixtures; the resource-bearing variants
/// (assets / apps / participation) are exercised in `account_roundtrip_test.rs`.
fn account_case() -> Case {
    use algo_rest_api::models::account_data_to_response;
    use algo_rest_api::node::AccountLookup;
    use algo_types::consensus::{consensus_params_for_version, CONSENSUS_V41};
    use algo_types::{AccountData, AccountStatus, Address};

    let mut a = [0u8; 32];
    a[0] = 0x11;
    a[31] = 0x11 ^ 0xff;
    let addr = Address(a);
    let lookup = AccountLookup {
        account_data: AccountData {
            micro_algos: 1_000_000,
            status: AccountStatus::Offline,
            ..Default::default()
        },
        last_round: 100,
        amount_without_pending_rewards: 1_000_000,
        assets: Default::default(),
        created_assets: Default::default(),
        app_local_states: Default::default(),
        created_apps: Default::default(),
    };
    let consensus = consensus_params_for_version(CONSENSUS_V41).unwrap();
    let resp = account_data_to_response(&lookup, &addr, "none", &consensus);
    let golden =
        std::fs::read_to_string(format!("{ACCOUNT_DIR}/offline_minimal.account.json")).unwrap();
    Case {
        endpoint: "GET /v2/accounts/{address} [offline_minimal]".into(),
        actual: serde_json::to_value(&resp).unwrap(),
        expected: serde_json::from_str(&golden).unwrap(),
    }
}

#[test]
fn rest_conformance_suite() {
    let mut cases = block_cases();
    cases.push(account_case());
    cases.push(transaction_params_case());

    let results: Vec<CaseResult> = cases.into_iter().map(run_case).collect();

    // Emit a per-endpoint report (partner to algo-conformance's reporting).
    let passed = results.iter().filter(|r| r.passed()).count();
    println!("\n=== REST conformance report ===");
    for r in &results {
        if r.passed() {
            println!("  PASS  {}", r.endpoint);
        } else {
            println!(
                "  FAIL  {} ({} field mismatch(es))",
                r.endpoint,
                r.mismatches.len()
            );
            for m in &r.mismatches {
                println!(
                    "        {}: expected {} got {}",
                    m.path, m.expected, m.actual
                );
            }
        }
    }
    println!("{passed}/{} endpoints conformant\n", results.len());

    let failures: Vec<&CaseResult> = results.iter().filter(|r| !r.passed()).collect();
    assert!(
        failures.is_empty(),
        "{} REST endpoint(s) drifted from go-algorand; see report above",
        failures.len()
    );
}
