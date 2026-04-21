//! Integration test: `algo-validate` consumers can use
//! `algo_avm::check_program_version_allowed` to gate program acceptance on the
//! active consensus `logic_sig_version` ceiling.
//!
//! Corresponds to go-algorand's pre-eval check in
//! `data/transactions/logic/eval.go` against `proto.LogicSigVersion`
//! (`config/consensus.go:233` / V41 = 12 / vFuture = 13).

use algo_avm::check_program_version_allowed;
use algo_types::consensus::{
    consensus_params_for_version, ConsensusParams, CONSENSUS_V40, CONSENSUS_V41,
};

fn ceiling(params: &ConsensusParams) -> u64 {
    params.logic_sig_version
}

fn v40() -> ConsensusParams {
    consensus_params_for_version(CONSENSUS_V40).expect("V40 params must be constructible")
}

fn v41() -> ConsensusParams {
    consensus_params_for_version(CONSENSUS_V41).expect("V41 params must be constructible")
}

#[test]
fn v41_consensus_accepts_v12_programs() {
    let v41 = v41();
    assert_eq!(ceiling(&v41), 12);
    // A program declaring v12 is at the ceiling; accepted.
    assert!(check_program_version_allowed(12, ceiling(&v41)).is_ok());
}

#[test]
fn v41_consensus_rejects_v13_programs() {
    let v41 = v41();
    assert_eq!(ceiling(&v41), 12);
    // A program declaring v13 exceeds the V41 ceiling; must be rejected.
    let err = check_program_version_allowed(13, ceiling(&v41)).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("exceeds consensus LogicSigVersion ceiling"),
        "unexpected error: {msg}"
    );
}

#[test]
fn v40_consensus_rejects_v12_programs() {
    // V40 LogicSigVersion = 11; a v12 program must be rejected under V40
    // even though the Rust AVM itself supports v12.
    let v40 = v40();
    assert_eq!(ceiling(&v40), 11);
    assert!(check_program_version_allowed(12, ceiling(&v40)).is_err());
}

#[test]
fn v40_consensus_accepts_v11_programs() {
    let v40 = v40();
    assert_eq!(ceiling(&v40), 11);
    assert!(check_program_version_allowed(11, ceiling(&v40)).is_ok());
}
