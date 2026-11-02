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

//! Shared fixture for the bundle verification differential test and
//! benchmark (issue #2145): real one-time signatures and VRF credentials
//! that win sortition against an in-memory ledger.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};

use algo_agreement::{
    hash_rep, EquivocationVoteAuthenticator, Hashable, LedgerError, LedgerReader,
    OnlineAccountData, Period, ProposalValue, RawVote, Seed, Selector, UnauthenticatedBundle,
    UnauthenticatedCredential, VoteAuthenticator,
};
use algo_consensus_crypto::vrf::VrfKeypair;
use algo_consensus_crypto::{one_time_id_for_round, OneTimeSignatureSecrets};
use algo_types::consensus::consensus_params_for_version;
use algo_types::{Address, ConsensusParams, Digest, Round, CONSENSUS_V41};

pub const ROUND: u64 = 10_000;
pub const KEY_DILUTION: u64 = 100;
pub const STAKE: u64 = 1_000_000_000;

pub struct TestLedger {
    pub params: ConsensusParams,
    pub accounts: HashMap<Address, OnlineAccountData>,
    pub fail_lookup: HashSet<Address>,
    pub fail_circulation: bool,
    pub fail_seed: bool,
}

impl LedgerReader for TestLedger {
    fn seed(&self, _round: Round) -> Result<Seed, LedgerError> {
        if self.fail_seed {
            return Err(LedgerError::Other("seed unavailable".into()));
        }
        Ok(Seed([0xab; 32]))
    }
    fn lookup_agreement(
        &self,
        _round: Round,
        addr: &Address,
    ) -> Result<OnlineAccountData, LedgerError> {
        if self.fail_lookup.contains(addr) {
            return Err(LedgerError::Other("lookup failed".into()));
        }
        self.accounts
            .get(addr)
            .cloned()
            .ok_or_else(|| LedgerError::Other("no such account".into()))
    }
    fn circulation(&self, _rnd: Round, _vote_rnd: Round) -> Result<u64, LedgerError> {
        if self.fail_circulation {
            return Err(LedgerError::Other("circulation unavailable".into()));
        }
        Ok(STAKE * self.accounts.len() as u64)
    }
    fn lookup_digest(&self, _round: Round) -> Result<Digest, LedgerError> {
        Ok(Digest([0; 32]))
    }
    fn consensus_params(&self, _round: Round) -> Result<ConsensusParams, LedgerError> {
        Ok(self.params.clone())
    }
    fn next_round(&self) -> Round {
        Round(ROUND)
    }
    fn consensus_version(&self, _round: Round) -> Result<String, LedgerError> {
        Ok(CONSENSUS_V41.to_string())
    }
    fn wait_for_round(&self, _round: Round) -> Result<(), LedgerError> {
        Ok(())
    }
    fn round_notify(&self, _round: Round) -> crossbeam_channel::Receiver<Round> {
        crossbeam_channel::bounded(1).1
    }
}

pub struct Voter {
    pub addr: Address,
    pub ots: OneTimeSignatureSecrets,
    pub vrf: VrfKeypair,
}

/// splitmix64: a tiny deterministic generator so the mutation sequence is
/// reproducible without depending on a particular `rand` API.
pub struct Rng(pub u64);
impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

pub fn pool(n: usize) -> Vec<Voter> {
    let id = one_time_id_for_round(ROUND, KEY_DILUTION);
    (0..n)
        .map(|i| Voter {
            addr: Address([i as u8 + 1; 32]),
            ots: OneTimeSignatureSecrets::generate(id.batch, 1),
            vrf: VrfKeypair::from_seed([i as u8 + 100; 32]),
        })
        .collect()
}

pub fn proposal(tag: u8) -> ProposalValue {
    ProposalValue {
        original_period: Period(0),
        original_proposer: Address([0x77; 32]),
        block_digest: Digest([tag; 32]),
        encoding_digest: Digest([tag ^ 0x55; 32]),
    }
}

pub fn ledger(voters: &[Voter]) -> TestLedger {
    let accounts = voters
        .iter()
        .map(|v| {
            (
                v.addr,
                OnlineAccountData {
                    micro_algos: STAKE,
                    vote_id: v.ots.verifier(),
                    selection_id: *v.vrf.pk.as_bytes(),
                    vote_first_valid: Round(0),
                    vote_last_valid: Round(0),
                    vote_key_dilution: KEY_DILUTION,
                    incentive_eligible: false,
                    last_proposed: Round(0),
                    last_heartbeat: Round(0),
                    state_proof_id: [0u8; 64],
                },
            )
        })
        .collect();
    TestLedger {
        params: consensus_params_for_version(CONSENSUS_V41).expect("v41"),
        accounts,
        fail_lookup: HashSet::new(),
        fail_circulation: false,
        fail_seed: false,
    }
}

pub fn cred_for(v: &Voter, step: algo_agreement::Step) -> UnauthenticatedCredential {
    let sel = Selector {
        seed: Seed([0xab; 32]),
        round: Round(ROUND),
        period: Period(0),
        step,
    };
    let (proof, _) = v.vrf.sk.prove(&hash_rep(&sel));
    UnauthenticatedCredential::new(proof.0)
}

pub fn sign(
    v: &Voter,
    step: algo_agreement::Step,
    p: ProposalValue,
) -> algo_consensus_crypto::OneTimeSignature {
    let rv = RawVote {
        sender: v.addr,
        round: Round(ROUND),
        period: Period(0),
        step,
        proposal: p,
    };
    let msg = [RawVote::hash_id(), rv.to_be_hashed().as_slice()].concat();
    v.ots.sign(&msg, ROUND, KEY_DILUTION)
}

pub fn bundle(
    voters: &[Voter],
    step: algo_agreement::Step,
    p: ProposalValue,
) -> UnauthenticatedBundle {
    UnauthenticatedBundle {
        round: Round(ROUND),
        period: Period(0),
        step,
        proposal: p,
        votes: voters
            .iter()
            .map(|v| VoteAuthenticator {
                sender: v.addr,
                cred: cred_for(v, step),
                sig: sign(v, step, p),
            })
            .collect(),
        equivocation_votes: vec![],
    }
}

pub fn equivocation(
    v: &Voter,
    step: algo_agreement::Step,
    a: ProposalValue,
    b: ProposalValue,
) -> EquivocationVoteAuthenticator {
    EquivocationVoteAuthenticator {
        sender: v.addr,
        cred: cred_for(v, step),
        sigs: [sign(v, step, a), sign(v, step, b)],
        proposals: [a, b],
    }
}
