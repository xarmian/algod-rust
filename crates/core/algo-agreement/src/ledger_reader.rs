// Copyright (C) 2019-2026 Algorand Foundation Ltd.
// Modifications Copyright (C) 2026 Algod DAO
// This file is part of algod-rust, a modified work based on go-algorand
// (https://github.com/algorand/go-algorand).
//
// algod-rust is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// algod-rust is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with algod-rust.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// LedgerReader trait and BalanceRecord, matching go-algorand/agreement/abstractions.go
// and go-algorand/data/committee/committee.go.
//
// The LedgerReader provides read access to ledger state needed by the
// agreement protocol for vote and bundle verification.

use algo_types::{Address, ConsensusParams, Digest, Round};

use crate::seed::Seed;
use crate::step::Period;

/// Online account data needed for agreement verification.
///
/// Mirrors Go's `basics.OnlineAccountData` (embedded in `committee.BalanceRecord`).
/// Contains the voting-related fields needed for committee membership checks.
#[derive(Debug, Clone)]
pub struct OnlineAccountData {
    /// The account's online stake (microAlgos), used for sortition weight.
    /// Go: `MicroAlgosWithRewards`.
    pub micro_algos: u64,
    /// The OTS master public key (ed25519 verifier for one-time signatures).
    /// Go: `VoteID` (`crypto.OneTimeSignatureVerifier`, 32 bytes).
    pub vote_id: [u8; 32],
    /// The VRF selection public key (32 bytes).
    /// Go: `SelectionID` (`crypto.VRFVerifier`, 32 bytes).
    pub selection_id: [u8; 32],
    /// First round this key is valid for voting.
    /// Go: `VoteFirstValid`.
    pub vote_first_valid: Round,
    /// Last round this key is valid for voting (0 = no upper bound).
    /// Go: `VoteLastValid`.
    pub vote_last_valid: Round,
    /// Key dilution parameter (0 = use consensus default).
    /// Go: `VoteKeyDilution`.
    pub vote_key_dilution: u64,
    /// Whether the account is eligible for block incentive payouts.
    /// Go: `IncentiveEligible`.
    pub incentive_eligible: bool,
    /// Last round the account proposed a block.
    /// Go: `LastProposed`.
    pub last_proposed: Round,
    /// Last round the account sent a heartbeat.
    /// Go: `LastHeartbeat`.
    pub last_heartbeat: Round,
    /// The state proof ID (Merkle signature commitment, 64 bytes).
    /// Go: `StateProofID` (`merklesignature.Commitment`, 64 bytes).
    pub state_proof_id: [u8; 64],
}

/// A balance record pairing an address with its online account data.
///
/// Mirrors Go's `committee.BalanceRecord`:
/// ```go
/// type BalanceRecord struct {
///     basics.OnlineAccountData
///     Addr basics.Address
/// }
/// ```
#[derive(Debug, Clone)]
pub struct BalanceRecord {
    /// The account's online data (voting keys, stake, etc.).
    pub online_account_data: OnlineAccountData,
    /// The account's address.
    pub addr: Address,
}

impl BalanceRecord {
    /// Returns the voting stake (microAlgos).
    pub fn voting_stake(&self) -> u64 {
        self.online_account_data.micro_algos
    }
}

/// Errors returned by `LedgerReader` methods.
#[derive(Debug, Clone, PartialEq)]
pub enum LedgerError {
    /// The requested round has not yet been confirmed.
    RoundNotAvailable(Round),
    /// The requested round was dropped from the ledger.
    DroppedRound {
        round: Round,
        source: Option<String>,
    },
    /// Generic error with message.
    Other(String),
}

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RoundNotAvailable(r) => write!(f, "round {r} not available"),
            Self::DroppedRound { round, source } => {
                write!(f, "round {round} dropped from ledger")?;
                if let Some(src) = source {
                    write!(f, ": {src}")?;
                }
                Ok(())
            }
            Self::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for LedgerError {}

/// Read access to ledger state needed by the agreement protocol.
///
/// Mirrors Go's `agreement.LedgerReader` interface. The agreement protocol
/// uses this to look up seeds, account data, circulation, digests, and
/// consensus parameters — all needed for vote verification and committee
/// membership checks.
pub trait LedgerReader {
    /// Returns the VRF seed agreed upon in the given round.
    ///
    /// Used to construct the Selector for committee sortition.
    fn seed(&self, round: Round) -> Result<Seed, LedgerError>;

    /// Returns the online account data for the given address at the given round.
    ///
    /// This is used to look up voting keys and stake for membership checks.
    /// Mirrors Go's `LookupAgreement`.
    fn lookup_agreement(
        &self,
        round: Round,
        addr: &Address,
    ) -> Result<OnlineAccountData, LedgerError>;

    /// Returns the total amount of online money in circulation at `rnd`
    /// that is eligible for voting at `vote_rnd`.
    ///
    /// Mirrors Go's `Circulation(rnd, voteRnd)`.
    fn circulation(&self, rnd: Round, vote_rnd: Round) -> Result<u64, LedgerError>;

    /// Returns the digest of the block agreed on in the given round.
    fn lookup_digest(&self, round: Round) -> Result<Digest, LedgerError>;

    /// Returns the consensus parameters for the given round.
    fn consensus_params(&self, round: Round) -> Result<ConsensusParams, LedgerError>;

    /// Returns the first round for which no Block has been confirmed.
    ///
    /// Mirrors Go's `LedgerReader.NextRound()`.
    fn next_round(&self) -> Round;

    /// Returns the consensus version (protocol version string) for the given round.
    ///
    /// Mirrors Go's `LedgerReader.ConsensusVersion()`.
    fn consensus_version(&self, round: Round) -> Result<String, LedgerError>;

    /// Blocks until the specified round completes and is durably stored.
    ///
    /// Mirrors Go's `LedgerReader.Wait()` which returns a channel that fires
    /// when the round is available. In Rust we use a blocking call instead.
    /// The non-blocking variant is available via `round_notify()`.
    fn wait_for_round(&self, round: Round) -> Result<(), LedgerError>;

    /// Returns a receiver that will receive a notification when the ledger
    /// reaches or passes the given round. The receiver fires at most once.
    ///
    /// Mirrors Go's `ledger.Wait(round)` channel pattern used by the demux
    /// to select on round-change events without blocking.
    fn round_notify(&self, round: Round) -> crossbeam_channel::Receiver<Round>;
}

/// Construct a `Membership` from ledger state, matching Go's `membership()` helper
/// in `agreement/selector.go`.
///
/// This performs the necessary lookback computations to fetch the right balance,
/// seed, and circulation data for verifying a vote in the given round/period/step.
pub fn membership_from_ledger(
    l: &dyn LedgerReader,
    addr: &Address,
    round: Round,
    period: Period,
    step: crate::step::Step,
) -> Result<
    (
        crate::credential::Membership,
        OnlineAccountData,
        ConsensusParams,
    ),
    LedgerError,
> {
    let cparams = l.consensus_params(crate::lookback::params_round(round))?;
    let bal_round = crate::lookback::balance_round(round, &cparams);
    let seed_rnd = crate::lookback::seed_round(round, &cparams);

    let record = l.lookup_agreement(bal_round, addr)?;
    let total = l.circulation(bal_round, round)?;
    let seed = l.seed(seed_rnd)?;

    let membership = crate::credential::Membership {
        address: *addr,
        selection_id: record.selection_id,
        balance: record.micro_algos,
        total_money: total,
        selector: crate::selector::Selector {
            seed,
            round,
            period,
            step,
        },
    };

    Ok((membership, record, cparams))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn balance_record_voting_stake() {
        let br = BalanceRecord {
            online_account_data: OnlineAccountData {
                micro_algos: 5_000_000,
                vote_id: [0u8; 32],
                selection_id: [0u8; 32],
                vote_first_valid: Round(0),
                vote_last_valid: Round(0),
                vote_key_dilution: 0,
                incentive_eligible: false,
                last_proposed: Round(0),
                last_heartbeat: Round(0),
                state_proof_id: [0u8; 64],
            },
            addr: Address([0x42; 32]),
        };
        assert_eq!(br.voting_stake(), 5_000_000);
    }

    #[test]
    fn ledger_error_display() {
        let err = LedgerError::RoundNotAvailable(Round(42));
        assert_eq!(format!("{err}"), "round 42 not available");

        let err = LedgerError::DroppedRound {
            round: Round(10),
            source: None,
        };
        assert_eq!(format!("{err}"), "round 10 dropped from ledger");

        let err = LedgerError::DroppedRound {
            round: Round(10),
            source: Some("catchup lag".to_string()),
        };
        assert_eq!(
            format!("{err}"),
            "round 10 dropped from ledger: catchup lag"
        );

        let err = LedgerError::Other("test error".to_string());
        assert_eq!(format!("{err}"), "test error");
    }

    #[test]
    fn online_account_data_construction() {
        let oad = OnlineAccountData {
            micro_algos: 1_000_000,
            vote_id: [1u8; 32],
            selection_id: [2u8; 32],
            vote_first_valid: Round(100),
            vote_last_valid: Round(200),
            vote_key_dilution: 1000,
            incentive_eligible: true,
            last_proposed: Round(50),
            last_heartbeat: Round(60),
            state_proof_id: [0u8; 64],
        };
        assert_eq!(oad.micro_algos, 1_000_000);
        assert_eq!(oad.vote_id, [1u8; 32]);
        assert_eq!(oad.selection_id, [2u8; 32]);
        assert_eq!(oad.vote_first_valid, Round(100));
        assert_eq!(oad.vote_last_valid, Round(200));
        assert_eq!(oad.vote_key_dilution, 1000);
        assert!(oad.incentive_eligible);
        assert_eq!(oad.last_proposed, Round(50));
        assert_eq!(oad.last_heartbeat, Round(60));
    }
}
