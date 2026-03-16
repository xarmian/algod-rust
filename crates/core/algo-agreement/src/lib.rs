// algo-agreement: Algorand agreement protocol types and helpers.
//
// Mirrors go-algorand/agreement (types, step/period, committee sizing)
// and go-algorand/data/committee (Selector, Seed, BalanceRecord).

mod bundle;
mod certificate;
mod credential;
mod hashable;
mod ledger_reader;
mod lookback;
mod proposal;
mod seed;
mod selector;
mod step;
mod vote;

pub use bundle::{
    Bundle, BundleError, EquivocationVoteAuthenticator, UnauthenticatedBundle, VoteAuthenticator,
};
pub use certificate::{Certificate, CertificateError};
pub use credential::{
    Credential, CredentialError, HashableCredential, Membership, UnauthenticatedCredential,
};
pub use hashable::{hash_obj, hash_rep, Hashable};

/// Size of a VRF proof in bytes.
pub const VRF_PROOF_SIZE: usize = 80;
pub use ledger_reader::{
    membership_from_ledger, BalanceRecord, LedgerError, LedgerReader, OnlineAccountData,
};
pub use lookback::{balance_lookback, balance_round, effective_key_dilution, params_round, seed_round};
pub use proposal::{verify_proposer, ProposalError, UnauthenticatedProposal};
pub use seed::{
    derive_seed_period_nonzero, derive_seed_period_zero, history_mix_round, ProposerSeed, Seed,
    SeedInput, VrfOutput,
};
pub use selector::Selector;
pub use step::{Period, Step, CERT, DOWN, LATE, NEXT, PROPOSE, REDO, SOFT};
pub use vote::{
    ProposalValue, RawVote, UnauthenticatedVote, Vote, VoteError, VoteVerifyParams, BOTTOM,
};
