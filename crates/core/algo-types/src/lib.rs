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

mod account;
mod address;
mod block;
pub mod consensus;
mod digest;
mod header;
pub mod networks;
pub mod pq;
pub(crate) mod rmp_decode;
mod round;
pub mod serde_bytes_array;
mod transaction;
pub mod txtail;

pub use account::{
    AccountData, AccountStatus, AppLocalState, AppParams, AssetHolding, AssetParamsRecord,
    TealValue,
};
pub use address::Address;
pub use block::{Block, BlockResponse};
pub use consensus::{
    consensus_params_for_version, ConsensusParams, CONSENSUS_CURRENT_VERSION, CONSENSUS_FUTURE,
    CONSENSUS_V41, CONSENSUS_V42, KNOWN_PROTOCOL_VERSIONS,
};
pub use digest::Digest;
pub use header::BlockHeader;
pub use networks::{resolve_genesis_hash, Network, ResolveGenesisError, UnknownNetwork};
pub use pq::{
    canonical_pq_address_salt, pq_address, PQAddressSalt, PQDelegatedProgram, PQSig,
    PQ_SCHEME_FALCON1024,
};
pub use rmp_decode::check_msgpack_depth;
pub use round::Round;
pub use transaction::{
    AssetParams, BoxRef, FalconVerifier, HashFactory, HeartbeatProof, HeartbeatTxnFields,
    HoldingRef, LocalsRef, LogicSig, MerkleProof, MerkleSignature, MerkleSignatureVerifier,
    MultisigSig, MultisigSubsig, Participant, ResourceRef, Reveal, SigSlotCommit,
    SignedTransaction, StateProofBody, StateProofMessage, StateSchema, Transaction, TxnType,
};
pub use txtail::{TxTailRound, TxTailRoundLease};
